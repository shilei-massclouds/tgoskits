"""Resumable QEMU orchestration for coverage and mismatch minimization."""

import hashlib
import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, List, Optional, Set, Tuple

from corpus import CorpusStore
from artifact import build_failure_metadata_v2, validate_failure
from common import atomic_save, save_metadata
from generator import GENERATOR_VERSION
from fingerprint import MismatchFingerprint
from guest_result import (
    GuestExecutionResult,
    GuestResultCategory,
    normalize_guest_execution,
)
from minimization import (
    MinimizationSession,
    PredicateDecision,
    ScheduledCandidate,
    coverage_decision,
    mismatch_decision,
)
from minimization_schema import HOST_ORACLE_NAME, STARRY_ELF_NAME
from minimization_store import (
    MinimizationEvidence,
    MinimizationJob,
    MinimizationStore,
)
from reducer import ReductionInput
from scenario import combine_documents, serialize_document


@dataclass(frozen=True)
class MinimizationRuntime:
    record_host: Callable[[Path, Path, Path], Any]
    run_guest_compare: Callable[[Path, Path, Optional[Path]], Any]
    extract_regions: Callable[[List[Path], Path], Set[str]]
    coverage_object: Callable[[Path], Path]


@dataclass(frozen=True)
class MinimizationOutcome:
    failed: bool
    category: str
    completion: Optional[str]
    job_id: str
    original_digests: Tuple[str, ...]
    minimized_digests: Tuple[str, ...]
    candidate_qemu: int
    proof_qemu: int
    duration_seconds: float


@dataclass
class _ReplayObservation:
    temporary: tempfile.TemporaryDirectory
    evidence: MinimizationEvidence
    category: GuestResultCategory
    covered_regions: Set[str]
    fingerprint: Optional[MismatchFingerprint]
    digest: str
    ran_qemu: bool

    def cleanup(self) -> None:
        self.temporary.cleanup()


def resume_minimization_job(
    workspace: Path,
    corpus_store: CorpusStore,
    minimization_store: MinimizationStore,
    job: MinimizationJob,
    runtime: MinimizationRuntime,
) -> MinimizationOutcome:
    job = minimization_store.load_job(job.job_id)
    if job.metadata["state"] in {"stale", "unstable"}:
        category = job.metadata["state"]
        minimization_store.finish_terminal_move(job)
        return _failed_outcome(job, category)
    minimization_store.prune_best_evidence(job)
    if job.metadata["state"] == "completed":
        return _outcome(job)
    stale_path = minimization_store.mark_stale_if_elf_changed(
        job,
        runtime.coverage_object(workspace),
    )
    if stale_path is not None:
        return _failed_outcome(job, "stale")
    session = minimization_store.restore_session(job)
    try:
        job = _validate_original(
            workspace,
            minimization_store,
            job,
            session,
            runtime,
        )
        job, session = _reduce_candidates(
            workspace,
            minimization_store,
            job,
            session,
            runtime,
        )
        job = _run_final_proofs(
            workspace,
            minimization_store,
            job,
            session,
            runtime,
        )
        job = _finalize_job(corpus_store, minimization_store, job, session)
        return _outcome(job)
    except _MinimizationInstability as error:
        active = minimization_store.load_job(job.job_id)
        minimization_store.mark_unstable(active, str(error))
        return _failed_outcome(active, "unstable")


class _MinimizationInstability(RuntimeError):
    pass


def _validate_original(
    workspace: Path,
    store: MinimizationStore,
    job: MinimizationJob,
    session: MinimizationSession,
    runtime: MinimizationRuntime,
) -> MinimizationJob:
    job = store.load_job(job.job_id)
    if job.metadata["state"] != "validating":
        return job
    if job.metadata["validation"] is not None:
        raise _MinimizationInstability(
            "saved original validation did not reproduce the predicate"
        )
    started = time.monotonic()
    observation = _run_replay(
        workspace,
        job,
        session.best_inputs(),
        runtime,
    )
    try:
        decision = _combined_decision(job, session, observation)
        satisfied = decision == PredicateDecision.ACCEPT
        evidence_digest = store.save_evidence(job, "original-validation", observation.evidence)
        job = store.record_validation(
            job,
            result_category=observation.category.value,
            satisfied=satisfied,
            evidence_digest=evidence_digest,
            duration_seconds=time.monotonic() - started,
            qemu_counted=observation.ran_qemu,
        )
        if not satisfied:
            raise _MinimizationInstability(
                "original input did not reproduce the minimization predicate: "
                f"{observation.category.value}"
            )
        return job
    finally:
        observation.cleanup()


def _reduce_candidates(
    workspace: Path,
    store: MinimizationStore,
    job: MinimizationJob,
    session: MinimizationSession,
    runtime: MinimizationRuntime,
) -> Tuple[MinimizationJob, MinimizationSession]:
    job = store.load_job(job.job_id)
    if job.metadata["state"] != "reducing":
        return job, store.restore_session(job)
    if any(
        attempt["decision"] == PredicateDecision.EXCEPTIONAL.value
        for attempt in job.metadata["attempts"]
    ):
        raise _MinimizationInstability(
            "a saved candidate produced an exceptional result"
        )
    session = store.restore_session(job)
    while scheduled := session.next_candidate():
        started = time.monotonic()
        candidate_input = scheduled.candidate.reduction_input
        observation = _run_replay(
            workspace,
            job,
            (candidate_input,),
            runtime,
        )
        try:
            decision = _candidate_decision(job, session, scheduled, observation)
            evidence_digest = observation.digest
            if decision in {PredicateDecision.ACCEPT, PredicateDecision.EXCEPTIONAL}:
                label = (
                    f"best-{scheduled.item_index:04d}-{scheduled.candidate.digest}"
                    if decision == PredicateDecision.ACCEPT
                    else f"abnormal-{session.candidate_qemu + 1:04d}"
                )
                evidence_digest = store.save_evidence(job, label, observation.evidence)
            if decision == PredicateDecision.EXCEPTIONAL and not observation.ran_qemu:
                raise _MinimizationInstability(
                    "candidate failed before QEMU execution: "
                    f"{observation.category.value}"
                )
            session.record_candidate(
                scheduled,
                accepted=decision == PredicateDecision.ACCEPT,
            )
            job = store.record_candidate(
                job,
                session,
                scheduled,
                decision=decision,
                result_category=observation.category.value,
                covered_regions=tuple(sorted(observation.covered_regions)),
                fingerprint=observation.fingerprint,
                evidence_digest=evidence_digest,
                duration_seconds=time.monotonic() - started,
            )
            if decision == PredicateDecision.EXCEPTIONAL:
                raise _MinimizationInstability(
                    "candidate produced an exceptional result: "
                    f"{observation.category.value}"
                )
        finally:
            observation.cleanup()
    job = store.begin_final_proof(job, session)
    return job, session


def _run_final_proofs(
    workspace: Path,
    store: MinimizationStore,
    job: MinimizationJob,
    session: MinimizationSession,
    runtime: MinimizationRuntime,
) -> MinimizationJob:
    job = store.load_job(job.job_id)
    if job.metadata["state"] != "final-proof":
        return job
    if any(
        proof["decision"] == PredicateDecision.EXCEPTIONAL.value
        for proof in job.metadata["proofs"]
    ):
        raise _MinimizationInstability(
            "a saved final proof produced an exceptional result"
        )
    session = store.restore_session(job)
    while len(job.metadata["proofs"]) < 2:
        proof_index = len(job.metadata["proofs"]) + 1
        started = time.monotonic()
        observation = _run_replay(
            workspace,
            job,
            session.best_inputs(),
            runtime,
        )
        try:
            decision = _combined_decision(job, session, observation)
            satisfied = decision == PredicateDecision.ACCEPT
            evidence_digest = store.save_evidence(
                job,
                f"final-proof-{proof_index:04d}",
                observation.evidence,
            )
            job = store.record_proof(
                job,
                result_category=observation.category.value,
                decision=decision,
                satisfied=satisfied,
                evidence_digest=evidence_digest,
                duration_seconds=time.monotonic() - started,
                qemu_counted=observation.ran_qemu,
            )
            if decision == PredicateDecision.EXCEPTIONAL:
                raise _MinimizationInstability(
                    "final proof produced an exceptional result: "
                    f"{observation.category.value}"
                )
        finally:
            observation.cleanup()
    if not all(proof["satisfied"] for proof in job.metadata["proofs"]):
        raise _MinimizationInstability(
            "two final proofs did not reproduce the minimization predicate"
        )
    return job


def _finalize_job(
    corpus_store: CorpusStore,
    store: MinimizationStore,
    job: MinimizationJob,
    session: MinimizationSession,
) -> MinimizationJob:
    job = store.load_job(job.job_id)
    if job.metadata["state"] == "completed":
        return job
    session = store.restore_session(job)
    if job.metadata["kind"] == "coverage":
        for item, reducer in zip(session.items, session.reducers):
            best_digest = hashlib.sha256(
                serialize_document(reducer.best.document).encode("utf-8")
            ).hexdigest()
            if best_digest == item.original_digest:
                continue
            corpus_store.admit_minimized_entry(
                reducer.best.document,
                item.provenance,
                set(item.responsibility_regions),
                job.job_id,
                {item.original_digest},
            )
            corpus_store.supersede_entry(
                item.original_digest,
                best_digest,
                job.job_id,
            )
    else:
        _save_minimized_mismatch(corpus_store, job)
    changed = any(
        item["best_digest"] != item["original_digest"]
        for item in job.metadata["items"]
    )
    if job.metadata["candidate_qemu"] >= job.metadata["max_candidate_qemu"]:
        completion = "budget-limited"
    elif changed:
        completion = "minimized"
    else:
        completion = "already-minimal"
    return store.complete(job, completion)


def _save_minimized_mismatch(corpus_store: CorpusStore, job: MinimizationJob) -> Path:
    best = job.metadata["items"][0]
    source = Path(job.metadata["source"]["path"])
    source_metadata = validate_failure(source)
    destination = (
        corpus_store.failures_dir
        / f"{job.metadata['source']['id']}_minimized_{best['best_digest'][:12]}"
    )
    if destination.exists():
        validate_failure(destination)
        return destination
    final_evidence = job.path / "evidence" / "final-proof-0002"
    fingerprint = MismatchFingerprint.from_metadata(
        job.metadata["expected_fingerprint"]
    )

    def write(temporary: Path) -> None:
        shutil.copy2(final_evidence / "pipe.ops", temporary / "pipe.ops")
        shutil.copy2(final_evidence / "pipe.ops", temporary / "input.bin")
        shutil.copy2(final_evidence / "linux.trace", temporary / "linux.trace")
        shutil.copy2(final_evidence / "guest.log", temporary / "guest.log")
        shutil.copy2(job.path / HOST_ORACLE_NAME, temporary / HOST_ORACLE_NAME)
        shutil.copy2(job.path / STARRY_ELF_NAME, temporary / STARRY_ELF_NAME)
        profraws = temporary / "profraws"
        profraws.mkdir()
        for item in sorted((final_evidence / "profraws").iterdir(), key=lambda path: path.name):
            shutil.copy2(item, profraws / item.name)
        metadata = build_failure_metadata_v2(
            temporary,
            generator_version=source_metadata.get(
                "generator_version",
                GENERATOR_VERSION,
            ),
            fuzz_seed=source_metadata.get("fuzz_seed"),
            batch_index=max(0, source_metadata.get("batch_index", 0)),
            command=f"minimization job {job.job_id}",
            result_category=GuestResultCategory.SEMANTIC_MISMATCH,
            mismatch_fingerprint=fingerprint,
            failure_category="minimized-semantic-mismatch",
        )
        save_metadata(temporary, metadata)

    atomic_save(destination, write)
    return destination


def _run_replay(
    workspace: Path,
    job: MinimizationJob,
    reduction_inputs: Tuple[ReductionInput, ...],
    runtime: MinimizationRuntime,
) -> _ReplayObservation:
    temporary_handle = tempfile.TemporaryDirectory()
    temporary = Path(temporary_handle.name)
    documents = [reduction_input.document for reduction_input in reduction_inputs]
    ops_path = temporary / "pipe.ops"
    ops_path.write_text(
        serialize_document(combine_documents(documents)),
        encoding="utf-8",
    )
    trace_path = temporary / "linux.trace"
    shutil.copy2(job.path / HOST_ORACLE_NAME, temporary / HOST_ORACLE_NAME)
    host_record = runtime.record_host(
        job.path / HOST_ORACLE_NAME,
        ops_path,
        trace_path,
    )
    ran_qemu = False
    covered_regions: Set[str] = set()
    fingerprint = None
    if not trace_path.is_file():
        trace_path.write_bytes(b"")
    if not host_record.passed:
        execution = GuestExecutionResult(
            GuestResultCategory.ORACLE_FAILURE,
            host_record.log,
            (),
            None,
        )
    else:
        execution = normalize_guest_execution(
            runtime.run_guest_compare(
                workspace,
                temporary,
                job.path / STARRY_ELF_NAME,
            )
        )
        ran_qemu = True
    category = execution.category
    profraws = list(execution.profraw_paths)
    guest_log = execution.log
    if category == GuestResultCategory.PASSED and job.metadata["kind"] == "coverage":
        if not profraws:
            category = GuestResultCategory.INFRASTRUCTURE_FAILURE
            guest_log += "\nQEMU passed without a fresh coverage profile.\n"
        else:
            try:
                covered_regions = runtime.extract_regions(
                    profraws,
                    job.path / STARRY_ELF_NAME,
                )
            except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
                category = GuestResultCategory.INFRASTRUCTURE_FAILURE
                guest_log += f"\nCoverage analysis failed: {error}\n"
    if category == GuestResultCategory.SEMANTIC_MISMATCH and len(reduction_inputs) == 1:
        try:
            fingerprint = MismatchFingerprint.for_reduction_input(
                execution.difference,
                reduction_inputs[0],
            )
        except ValueError:
            fingerprint = None
            category = GuestResultCategory.ORACLE_FAILURE
    evidence = MinimizationEvidence(
        ops_path,
        trace_path,
        guest_log,
        tuple(profraws),
        category.value,
        tuple(sorted(covered_regions)),
        fingerprint,
    )
    digest = _observation_digest(evidence)
    return _ReplayObservation(
        temporary_handle,
        evidence,
        category,
        covered_regions,
        fingerprint,
        digest,
        ran_qemu,
    )


def _candidate_decision(
    job: MinimizationJob,
    session: MinimizationSession,
    scheduled: ScheduledCandidate,
    observation: _ReplayObservation,
) -> PredicateDecision:
    if job.metadata["kind"] == "coverage":
        return coverage_decision(
            observation.category,
            observation.covered_regions,
            set(session.items[scheduled.item_index].responsibility_regions),
        )
    expected = MismatchFingerprint.from_metadata(job.metadata["expected_fingerprint"])
    return mismatch_decision(observation.category, observation.fingerprint, expected)


def _combined_decision(
    job: MinimizationJob,
    session: MinimizationSession,
    observation: _ReplayObservation,
) -> PredicateDecision:
    if job.metadata["kind"] == "coverage":
        required = set().union(
            *(set(item.responsibility_regions) for item in session.items)
        )
        return coverage_decision(
            observation.category,
            observation.covered_regions,
            required,
        )
    expected = MismatchFingerprint.from_metadata(job.metadata["expected_fingerprint"])
    return mismatch_decision(observation.category, observation.fingerprint, expected)


def _observation_digest(evidence: MinimizationEvidence) -> str:
    payload = {
        "result_category": evidence.result_category,
        "guest_log_sha256": hashlib.sha256(evidence.guest_log.encode("utf-8")).hexdigest(),
        "covered_regions": list(evidence.covered_regions),
        "fingerprint": (
            evidence.fingerprint.as_metadata()
            if evidence.fingerprint is not None
            else None
        ),
        "profraws": [
            hashlib.sha256(path.read_bytes()).hexdigest()
            for path in evidence.profraw_paths
            if path.is_file()
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _outcome(job: MinimizationJob) -> MinimizationOutcome:
    return MinimizationOutcome(
        False,
        "completed",
        job.metadata["completion"],
        job.job_id,
        tuple(item["original_digest"] for item in job.metadata["items"]),
        tuple(item["best_digest"] for item in job.metadata["items"]),
        job.metadata["candidate_qemu"],
        job.metadata["proof_qemu"],
        job.metadata["duration_seconds"],
    )


def _failed_outcome(job: MinimizationJob, category: str) -> MinimizationOutcome:
    return MinimizationOutcome(
        True,
        category,
        None,
        job.job_id,
        tuple(item["original_digest"] for item in job.metadata["items"]),
        tuple(item["best_digest"] for item in job.metadata["items"]),
        job.metadata["candidate_qemu"],
        job.metadata["proof_qemu"],
        job.metadata["duration_seconds"],
    )


__all__ = [
    "MinimizationOutcome",
    "MinimizationRuntime",
    "resume_minimization_job",
]
