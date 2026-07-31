"""Exact-attribution replay orchestration for productive pipe batches."""

import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from attribution import (
    AttributionInput,
    AttributionInstability,
    AttributionJob,
    AttributionStore,
    ReplayEvidence,
)
from corpus import CanonicalCorpus, CorpusStorageError, CorpusStore
from guest_result import GuestExecutionResult, normalize_guest_execution
from scenario import combine_documents, serialize_document


@dataclass(frozen=True)
class AttributionReplayRuntime:
    record_host: Callable[[Path, Path, Path], Any]
    run_guest_compare: Callable[
        [Path, Path, Optional[Path]],
        Any,
    ]
    extract_regions: Callable[[List[Path], Path], Set[str]]
    coverage_object: Callable[[Path], Path]


@dataclass(frozen=True)
class AttributionOutcome:
    failed: bool
    category: str
    new_regions: Tuple[str, ...]
    admitted_digests: Tuple[str, ...]
    starry_elf_sha256: str
    job_id: str
    entry_regions: Tuple[Tuple[str, Tuple[str, ...]], ...]
    representative_digests: Tuple[str, ...]
    qemu_replays: int
    duration_seconds: float


@dataclass(frozen=True)
class AttributionReplayResult:
    passed: bool
    reason: Optional[str]


def resume_attribution_job(
    workspace: Path,
    store: CorpusStore,
    attribution_store: AttributionStore,
    corpus: CanonicalCorpus,
    job: AttributionJob,
    runtime: AttributionReplayRuntime,
) -> AttributionOutcome:
    try:
        job = attribution_store.load_job(job.job_id)
        if job.metadata["state"] != "completed":
            job = _restart_job_if_elf_changed(
                workspace,
                store,
                attribution_store,
                job,
                runtime,
            )
        job = _replay_unfinished_entries(
            workspace,
            attribution_store,
            job,
            runtime,
        )
        job = _replay_representatives(
            workspace,
            attribution_store,
            job,
            runtime,
        )
        _finalize_attribution_job(store, corpus, attribution_store, job)
        completed = attribution_store.load_job(job.job_id)
        result = _job_outcome(completed)
        print(
            "  Exact attribution completed: "
            f"entries={len(completed.metadata['entries'])} "
            f"representatives={len(result.representative_digests)} "
            f"extra-qemu={result.qemu_replays}",
            flush=True,
        )
        return result
    except AttributionInstability as error:
        failed_job = attribution_store.load_job(job.job_id)
        result = _job_outcome(
            failed_job,
            failed=True,
            category="attribution-instability",
        )
        failure_path = attribution_store.fail_job(job.job_id, str(error))
        print(
            "  ATTRIBUTION INSTABILITY saved to "
            f"{failure_path.relative_to(workspace)}: {error}",
            flush=True,
        )
        return result


def _restart_job_if_elf_changed(
    workspace: Path,
    store: CorpusStore,
    attribution_store: AttributionStore,
    job: AttributionJob,
    runtime: AttributionReplayRuntime,
) -> AttributionJob:
    current_elf = runtime.coverage_object(workspace)
    if current_elf.is_file() and store.elf_digest(current_elf) == job.metadata[
        "starry_elf_sha256"
    ]:
        return job

    print(
        f"  Attribution job {job.job_id} sees a different Starry ELF; "
        "replaying the complete batch on the active build.",
        flush=True,
    )
    entries = attribution_store.input_entries(job)
    fallback_elf = _saved_job_elf(job)
    restarted_job: List[AttributionJob] = []

    def persist_restart(evidence: ReplayEvidence, duration: float) -> None:
        actual_digest = store.elf_digest(evidence.starry_elf_path)
        if evidence.result_category != "passed":
            attribution_store.persist_restart_evidence(job, evidence)
            if _result_ran_qemu(evidence.result_category):
                attribution_store.record_qemu_replay_attempt(
                    job.job_id,
                    duration_seconds=duration,
                )
            return
        if actual_digest == job.metadata["starry_elf_sha256"]:
            restarted_job.append(
                attribution_store.record_qemu_replay_attempt(
                    job.job_id,
                    duration_seconds=duration,
                )
            )
            return
        attribution_store.persist_restart_evidence(job, evidence)
        baseline = store.load_coverage_regions(evidence.starry_elf_path)
        target = set(evidence.covered_regions) - baseline
        restarted_job.append(
            attribution_store.restart_for_elf(
                job.job_id,
                baseline_regions=baseline,
                target_regions=target,
                evidence=evidence,
                duration_seconds=duration,
            )
        )

    replay = _run_attribution_replay(
        workspace,
        attribution_store.host_oracle_path(job),
        entries,
        fallback_elf,
        None,
        persist_restart,
        runtime,
    )
    if not replay.passed:
        raise AttributionInstability(replay.reason or "ELF restart replay failed")
    if not restarted_job:
        raise AttributionInstability("ELF restart did not produce persistent state")
    return restarted_job[0]


def _replay_unfinished_entries(
    workspace: Path,
    attribution_store: AttributionStore,
    job: AttributionJob,
    runtime: AttributionReplayRuntime,
) -> AttributionJob:
    if job.metadata["state"] != "entry-replays":
        return job
    input_by_digest = {
        entry.digest: entry for entry in attribution_store.input_entries(job)
    }
    completed = set(job.metadata["completed_entry_digests"])
    for digest in sorted(set(input_by_digest) - completed):
        job = attribution_store.load_job(job.job_id)
        saved = attribution_store.saved_entry_evidence(job, digest)
        if saved is not None:
            if saved.result_category != "passed":
                raise AttributionInstability(
                    f"entry replay {digest} previously failed: "
                    f"{saved.result_category}"
                )
            job = attribution_store.record_entry_replay(
                job.job_id,
                digest,
                saved,
                duration_seconds=0.0,
            )
            continue

        def persist_entry(evidence: ReplayEvidence, duration: float) -> None:
            attribution_store.persist_entry_evidence(job, digest, evidence)
            if evidence.result_category == "passed":
                attribution_store.record_entry_replay(
                    job.job_id,
                    digest,
                    evidence,
                    duration_seconds=duration,
                )
            elif _result_ran_qemu(evidence.result_category):
                attribution_store.record_qemu_replay_attempt(
                    job.job_id,
                    duration_seconds=duration,
                )

        replay = _run_attribution_replay(
            workspace,
            attribution_store.host_oracle_path(job),
            (input_by_digest[digest],),
            _saved_job_elf(job),
            _saved_job_elf(job),
            persist_entry,
            runtime,
        )
        if not replay.passed:
            raise AttributionInstability(
                replay.reason or f"entry replay {digest} failed"
            )
    return attribution_store.load_job(job.job_id)


def _replay_representatives(
    workspace: Path,
    attribution_store: AttributionStore,
    job: AttributionJob,
    runtime: AttributionReplayRuntime,
) -> AttributionJob:
    job = attribution_store.load_job(job.job_id)
    if job.metadata["state"] != "representative-replay":
        return job
    input_by_digest = {
        entry.digest: entry for entry in attribution_store.input_entries(job)
    }
    representatives = tuple(job.metadata["representative_digests"])
    saved = attribution_store.saved_representative_evidence(job)
    if saved is not None:
        if saved.result_category != "passed":
            raise AttributionInstability(
                "representative replay previously failed: "
                f"{saved.result_category}"
            )
        return attribution_store.record_representative_replay(
            job.job_id,
            saved,
            duration_seconds=0.0,
        )

    def persist_representative(evidence: ReplayEvidence, duration: float) -> None:
        attribution_store.persist_representative_evidence(job, evidence)
        if evidence.result_category == "passed":
            attribution_store.record_representative_replay(
                job.job_id,
                evidence,
                duration_seconds=duration,
            )
        elif _result_ran_qemu(evidence.result_category):
            attribution_store.record_qemu_replay_attempt(
                job.job_id,
                duration_seconds=duration,
            )

    replay = _run_attribution_replay(
        workspace,
        attribution_store.host_oracle_path(job),
        tuple(input_by_digest[digest] for digest in representatives),
        _saved_job_elf(job),
        _saved_job_elf(job),
        persist_representative,
        runtime,
    )
    if not replay.passed:
        raise AttributionInstability(replay.reason or "representative replay failed")
    return attribution_store.load_job(job.job_id)


def _run_attribution_replay(
    workspace: Path,
    host_oracle: Path,
    entries: Tuple[AttributionInput, ...],
    fallback_starry_elf: Path,
    pinned_starry_elf: Optional[Path],
    persist_evidence: Callable[[ReplayEvidence, float], None],
    runtime: AttributionReplayRuntime,
) -> AttributionReplayResult:
    started = time.monotonic()
    documents = [entry.document for entry in entries]
    ops_text = serialize_document(combine_documents(documents))
    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        ops_path = temporary / "pipe.ops"
        ops_path.write_text(ops_text, encoding="utf-8")
        trace_path = temporary / "linux.trace"
        host_record = runtime.record_host(host_oracle, ops_path, trace_path)
        trace_missing = not trace_path.is_file()
        if trace_missing:
            trace_path.write_bytes(b"")
        artifact_oracle = temporary / "pipe-linux-oracle"
        shutil.copy2(host_oracle, artifact_oracle)
        profraws: List[Path] = []
        covered_regions: Set[str] = set()

        if not host_record.passed or trace_missing:
            category = (
                "host-parser-rejection"
                if not trace_missing and host_record.parser_rejection
                else "host-record-failure"
            )
            guest_log = host_record.log
            if trace_missing and host_record.passed:
                guest_log += "\nHost record reported success without a trace.\n"
        else:
            guest_result = normalize_guest_execution(
                runtime.run_guest_compare(
                    workspace,
                    temporary,
                    pinned_starry_elf,
                )
            )
            guest_log = guest_result.log
            profraws = list(guest_result.profraw_paths)
            category = guest_result.category.value

        active_starry_elf = runtime.coverage_object(workspace)
        if not active_starry_elf.is_file():
            active_starry_elf = fallback_starry_elf
        if category == "passed":
            if not profraws:
                category = "missing-profraw"
            else:
                try:
                    covered_regions = runtime.extract_regions(
                        profraws,
                        active_starry_elf,
                    )
                except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
                    category = "coverage-failure"
                    guest_log += f"\nCoverage analysis failed: {error}\n"

        evidence = ReplayEvidence(
            ops_path=ops_path,
            trace_path=trace_path,
            guest_log=guest_log,
            profraw_paths=tuple(profraws),
            starry_elf_path=active_starry_elf,
            host_oracle_path=artifact_oracle,
            covered_regions=frozenset(covered_regions),
            result_category=category,
        )
        persist_evidence(evidence, time.monotonic() - started)
    reason = None if category == "passed" else f"attribution replay failed: {category}"
    return AttributionReplayResult(category == "passed", reason)


def _result_ran_qemu(category: str) -> bool:
    return category not in {"host-parser-rejection", "host-record-failure"}


def _finalize_attribution_job(
    store: CorpusStore,
    corpus: CanonicalCorpus,
    attribution_store: AttributionStore,
    job: AttributionJob,
) -> None:
    job = attribution_store.load_job(job.job_id)
    if job.metadata["state"] != "completed":
        raise CorpusStorageError(f"attribution job {job.job_id} is not complete")
    input_by_digest = {
        entry.digest: entry for entry in attribution_store.input_entries(job)
    }
    mapping = {
        digest: set(regions)
        for digest, regions in job.metadata["entry_regions"].items()
    }
    representatives = set(job.metadata["representative_digests"])
    for digest in sorted(mapping):
        regions = mapping[digest]
        if not regions:
            continue
        entry = input_by_digest[digest]
        if digest in representatives:
            added_in_memory = corpus.add(entry.document)
            added_on_disk = store.admit_attributed_entry(
                entry.document,
                entry.provenance,
                regions,
                job.job_id,
            )
            if added_in_memory or added_on_disk:
                print(f"  New exact corpus representative: {digest[:12]}...", flush=True)
        else:
            store.update_existing_attribution(
                entry.document,
                regions,
                job.job_id,
            )

    saved_elf = _saved_job_elf(job)
    committed_regions = set(job.metadata["baseline_regions"]) | set(
        job.metadata["target_regions"]
    )
    store.save_coverage_regions(saved_elf, committed_regions)


def _saved_job_elf(job: AttributionJob) -> Path:
    return (
        job.path
        / "elfs"
        / job.metadata["starry_elf_sha256"]
        / "starryos"
    )


def _job_outcome(
    job: AttributionJob,
    *,
    failed: bool = False,
    category: str = "passed",
) -> AttributionOutcome:
    entry_regions = tuple(
        (digest, tuple(regions))
        for digest, regions in sorted(job.metadata["entry_regions"].items())
    )
    return AttributionOutcome(
        failed,
        category,
        tuple(job.metadata["target_regions"]),
        tuple(job.metadata["representative_digests"]),
        job.metadata["starry_elf_sha256"],
        job.job_id,
        entry_regions,
        tuple(job.metadata["representative_digests"]),
        job.metadata["qemu_replays"],
        job.metadata["duration_seconds"],
    )


__all__ = [
    "AttributionOutcome",
    "AttributionReplayRuntime",
    "resume_attribution_job",
]
