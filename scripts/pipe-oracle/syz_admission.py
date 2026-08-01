"""Admission orchestration for stable restricted syzkaller scenarios."""

import hashlib
import os
import shutil
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, Optional, Sequence, Set, Tuple

from artifact import build_failure_metadata_v3, validate_failure
from attribution import AttributionInput, AttributionStore, ReplayEvidence
from batch_execution import BatchInput, HostRecordResult, execute_batch
from common import atomic_save, save_metadata
from corpus import CanonicalCorpus, CorpusStore, ExternalSource
from coverage import TARGET_SET_ID
from guest_result import GuestResultCategory
from host_runtime import find_or_build_host_oracle, record_host
from import_store import ImportBatchEvidence, ImportJob, ImportStore
from minimization_store import MinimizationStore
from fingerprint import MismatchFingerprint
from reducer import ReductionInput
from runner import coverage_object, run_guest_compare
from scenario import parse_document
from syz_converter import IMPORTER_VERSION


@dataclass(frozen=True)
class AdmissionOutcome:
    job_id: str
    failed: bool
    category: str
    host_stable: int
    host_unstable: int
    qemu_runs: int
    new_regions: Tuple[str, ...]
    admitted_digests: Tuple[str, ...]
    failure_path: Optional[str] = None


@dataclass(frozen=True)
class AttributionAdmissionOutcome:
    failed: bool
    category: str
    new_regions: Tuple[str, ...]
    admitted_digests: Tuple[str, ...]
    representative_digests: Tuple[str, ...]
    attribution_replays: int


@dataclass(frozen=True)
class AdmissionRuntime:
    find_host_oracle: Callable[[Path], Optional[Path]]
    record_host: Callable[[Path, Path, Path], HostRecordResult]
    run_guest_compare: Callable[[Path, Path, Optional[Path]], object]
    coverage_object: Callable[[Path], Path]
    extract_regions: Callable[[Sequence[Path], Path], Set[str]]
    load_active_corpus: Callable[[CorpusStore], CanonicalCorpus]
    resume_attribution: Callable[
        [Path, CorpusStore, AttributionStore, CanonicalCorpus, object],
        AttributionAdmissionOutcome,
    ]
    run_minimization: Callable[[Path, CorpusStore, Path, int], Tuple[object, object]]
    resume_global_jobs: Callable[[Path, CorpusStore, str, int], bool]


def default_runtime() -> AdmissionRuntime:
    import fuzz

    def load_active(store: CorpusStore) -> CanonicalCorpus:
        corpus, _built_in, _disk = fuzz._load_active_corpus(store)
        return corpus

    def resume_global(
        workspace: Path,
        store: CorpusStore,
        command: str,
        max_qemu: int,
    ) -> bool:
        attribution_store = AttributionStore(workspace, store.generator_version)
        if fuzz._resume_saved_jobs(
            workspace,
            store,
            attribution_store,
            load_active(store),
            command,
        ):
            return True
        minimization_store = MinimizationStore(workspace, store.generator_version)
        return fuzz._resume_minimization_work(
            workspace,
            store,
            attribution_store,
            minimization_store,
            command,
            max_qemu,
        )

    def resume_attribution(
        workspace: Path,
        store: CorpusStore,
        attribution_store: AttributionStore,
        corpus: CanonicalCorpus,
        job: object,
    ) -> AttributionAdmissionOutcome:
        outcome = fuzz._resume_attribution_job(
            workspace,
            store,
            attribution_store,
            corpus,
            job,
        )
        return AttributionAdmissionOutcome(
            outcome.failed,
            outcome.category,
            tuple(outcome.new_regions),
            tuple(outcome.admitted_digests),
            tuple(outcome.representative_digests),
            outcome.attribution_replays,
        )

    return AdmissionRuntime(
        find_host_oracle=find_or_build_host_oracle,
        record_host=record_host,
        run_guest_compare=run_guest_compare,
        coverage_object=coverage_object,
        extract_regions=lambda profraws, elf: fuzz._extract_regions(
            list(profraws),
            elf,
            TARGET_SET_ID,
        ),
        load_active_corpus=load_active,
        resume_attribution=resume_attribution,
        run_minimization=fuzz._run_source_minimization,
        resume_global_jobs=resume_global,
    )


def run_admission(
    workspace: Path,
    check_report: Dict[str, object],
    *,
    command: str,
    host_repetitions: int,
    batch_size: int,
    max_qemu: int,
    runtime: Optional[AdmissionRuntime] = None,
) -> Dict[str, object]:
    """Resume saved work, then admit one newly classified input set."""
    runtime = runtime or default_runtime()
    workspace = workspace.resolve()
    corpus_store = CorpusStore(workspace)
    import_store = ImportStore(workspace)

    outcomes = []
    resumed_current_input = False
    for saved_job in import_store.load_resumable_jobs():
        resumed_current_input |= _job_matches_report(saved_job, check_report)
        outcome = _resume_import_job(
            workspace,
            corpus_store,
            import_store,
            saved_job,
            command,
            runtime,
        )
        outcomes.append(outcome)
        if outcome.failed:
            return _admission_report(outcomes)

    if runtime.resume_global_jobs(workspace, corpus_store, command, max_qemu):
        raise RuntimeError("saved attribution or minimization work failed")

    if resumed_current_input:
        return _admission_report(outcomes)

    completed_match = next(
        (
            job
            for job in reversed(import_store.load_jobs())
            if job.metadata["state"] == "completed"
            and _job_matches_report(job, check_report)
        ),
        None,
    )
    if completed_match is not None:
        return _admission_report((_outcome_from_job(completed_match),))

    job = import_store.create_job(
        _import_job_id(),
        reports=check_report["inputs"],
        syzkaller_revision=str(check_report["syzkaller_revision"]),
        importer_version=IMPORTER_VERSION,
        host_repetitions=host_repetitions,
        batch_size=batch_size,
        max_qemu=max_qemu,
    )
    outcomes.append(
        _resume_import_job(
            workspace,
            corpus_store,
            import_store,
            job,
            command,
            runtime,
        )
    )
    return _admission_report(outcomes)


def _resume_import_job(
    workspace: Path,
    corpus_store: CorpusStore,
    import_store: ImportStore,
    job: ImportJob,
    command: str,
    runtime: AdmissionRuntime,
) -> AdmissionOutcome:
    job = import_store.load_job(job.job_id)
    if job.metadata["state"] == "completed":
        outcome = _outcome_from_job(job)
        _record_import_run(corpus_store, import_store, job, outcome, command)
        return outcome
    if job.metadata["state"] == "classified":
        job = import_store.begin_host_stability(job.job_id)

    if not job.metadata["canonical_inputs"]:
        job = import_store.configure_batches(job.job_id, ())
        completed = import_store.finish(
            job.job_id,
            result_category="no-accepted-input",
        )
        outcome = _outcome_from_job(completed)
        _record_import_run(corpus_store, import_store, completed, outcome, command)
        return outcome

    host_oracle = runtime.find_host_oracle(workspace)
    if host_oracle is None:
        failed = import_store.finish(
            job.job_id,
            result_category="host-oracle-build-failure",
            failure_reason="cannot build pipe-linux-oracle",
        )
        return _outcome_from_job(failed)
    host_failure = _complete_host_stability(
        import_store,
        job,
        host_oracle,
        runtime.record_host,
    )
    if host_failure is not None:
        return _outcome_from_job(host_failure)
    job = import_store.load_job(job.job_id)
    if not job.metadata["batches"] and job.metadata["state"] == "host-stability":
        stable_digests = [
            item["digest"]
            for item in job.metadata["canonical_inputs"]
            if item["host_status"] == "stable"
        ]
        batches = tuple(
            tuple(stable_digests[index : index + job.metadata["settings"]["batch_size"]])
            for index in range(0, len(stable_digests), job.metadata["settings"]["batch_size"])
        )
        job = import_store.configure_batches(job.job_id, batches)

    admitted = {
        digest
        for batch in job.metadata["batches"]
        for digest in batch["admitted_digests"]
    }
    new_regions = {
        region
        for batch in job.metadata["batches"]
        for region in batch["new_regions"]
    }
    while job.metadata["next_batch_index"] < len(job.metadata["batches"]):
        batch_index = job.metadata["next_batch_index"]
        batch_outcome = _resume_import_batch(
            workspace,
            corpus_store,
            import_store,
            job,
            batch_index,
            command,
            host_oracle,
            runtime,
        )
        admitted.update(batch_outcome.admitted_digests)
        new_regions.update(batch_outcome.new_regions)
        job = import_store.load_job(job.job_id)
        if batch_outcome.failed:
            failed = import_store.finish(
                job.job_id,
                result_category=batch_outcome.category,
                failure_reason=batch_outcome.failure_path or batch_outcome.category,
            )
            return _outcome_from_job(
                failed,
                admitted=admitted,
                new_regions=new_regions,
                failure_path=batch_outcome.failure_path,
            )

    category = (
        "no-accepted-input"
        if not job.metadata["canonical_inputs"]
        else (
            "no-host-stable-input"
            if not job.metadata["batches"]
            else (
                "passed-new-coverage"
                if new_regions
                else "passed-no-new-coverage"
            )
        )
    )
    completed = import_store.finish(job.job_id, result_category=category)
    outcome = _outcome_from_job(
        completed,
        admitted=admitted,
        new_regions=new_regions,
    )
    _record_import_run(corpus_store, import_store, completed, outcome, command)
    return outcome


def _complete_host_stability(
    store: ImportStore,
    job: ImportJob,
    host_oracle: Path,
    record: Callable[[Path, Path, Path], HostRecordResult],
) -> Optional[ImportJob]:
    repetitions = job.metadata["settings"]["host_repetitions"]
    for item in job.metadata["canonical_inputs"]:
        if item["host_status"] != "pending":
            continue
        started = time.monotonic()
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            traces = []
            for repetition in range(repetitions):
                trace = temporary / f"{repetition:04d}.trace"
                result = record(
                    host_oracle,
                    store.canonical_input_path(job, item["digest"]),
                    trace,
                )
                if not result.passed or not trace.is_file():
                    category = (
                        "host-parser-mismatch"
                        if result.parser_rejection
                        else "host-record-failure"
                    )
                    return store.finish(
                        job.job_id,
                        result_category=category,
                        failure_reason=result.log or category,
                        duration_seconds=time.monotonic() - started,
                    )
                traces.append(trace.read_bytes())
            first = traces[0]
            stable = all(trace == first for trace in traces[1:])
            job = store.record_host_result(
                job.job_id,
                item["digest"],
                stable=stable,
                trace_sha256=hashlib.sha256(first).hexdigest(),
                duration_seconds=time.monotonic() - started,
            )
    return None


def _resume_import_batch(
    workspace: Path,
    corpus_store: CorpusStore,
    import_store: ImportStore,
    job: ImportJob,
    batch_index: int,
    command: str,
    host_oracle: Path,
    runtime: AdmissionRuntime,
) -> AdmissionOutcome:
    batch = job.metadata["batches"][batch_index]
    evidence = import_store.load_batch_evidence(job.job_id, batch_index)
    if evidence is None:
        if job.metadata["qemu_runs"] >= job.metadata["settings"]["max_qemu"]:
            return AdmissionOutcome(
                job.job_id,
                True,
                "qemu-budget-exhausted",
                *_host_counts(job),
                job.metadata["qemu_runs"],
                (),
                (),
            )
        inputs = tuple(
            BatchInput(
                digest,
                import_store.canonical_input_path(job, digest).read_bytes(),
            )
            for digest in batch["digests"]
        )
        with execute_batch(
            workspace,
            inputs,
            host_oracle,
            runtime.record_host,
            runtime.run_guest_compare,
        ) as execution:
            if not execution.host_record.passed:
                category = (
                    "host-parser-mismatch"
                    if execution.host_record.parser_rejection
                    else "host-record-failure"
                )
                return AdmissionOutcome(
                    job.job_id,
                    True,
                    category,
                    *_host_counts(job),
                    job.metadata["qemu_runs"],
                    (),
                    (),
                )
            starry_elf = runtime.coverage_object(workspace)
            evidence = import_store.save_batch_evidence(
                job.job_id,
                batch_index,
                execution,
                starry_elf,
            )
    assert evidence is not None
    guest_result = evidence.guest_result
    if not guest_result.passed:
        failure_path, _fingerprint = _save_imported_failure(
            workspace,
            import_store,
            job,
            batch_index,
            evidence,
            command,
        )
        minimization_ids = []
        extra_qemu = 0
        if guest_result.category == GuestResultCategory.SEMANTIC_MISMATCH:
            remaining = _remaining_qemu(job, already_used=1)
            if remaining < 3:
                import_store.record_batch_result(
                    job.job_id,
                    batch_index,
                    result_category="qemu-budget-exhausted",
                    qemu_runs=1,
                    failed=True,
                )
                return AdmissionOutcome(
                    job.job_id,
                    True,
                    "qemu-budget-exhausted",
                    *_host_counts(job),
                    1,
                    (),
                    (),
                    str(failure_path),
                )
            outcome, minimization_job = runtime.run_minimization(
                workspace,
                corpus_store,
                failure_path,
                remaining - 3,
            )
            minimization_ids.append(outcome.job_id)
            extra_qemu = _minimization_qemu(minimization_job)
            if outcome.failed:
                category = f"minimization-{outcome.category}"
                import_store.record_batch_result(
                    job.job_id,
                    batch_index,
                    result_category=category,
                    qemu_runs=1 + extra_qemu,
                    minimization_job_ids=minimization_ids,
                    failed=True,
                )
                return AdmissionOutcome(
                    job.job_id,
                    True,
                    category,
                    *_host_counts(job),
                    1 + extra_qemu,
                    (),
                    (),
                    str(failure_path),
                )
        import_store.record_batch_result(
            job.job_id,
            batch_index,
            result_category=guest_result.category.value,
            qemu_runs=1 + extra_qemu,
            new_regions=(),
            admitted_digests=(),
            minimization_job_ids=minimization_ids,
            failed=True,
        )
        return AdmissionOutcome(
            job.job_id,
            True,
            guest_result.category.value,
            *_host_counts(job),
            1 + extra_qemu,
            (),
            (),
            str(failure_path),
        )

    if not guest_result.profraw_paths:
        return _record_coverage_failure(
            workspace,
            import_store,
            job,
            batch_index,
            evidence,
            command,
            "QEMU passed without producing the expected Starry profraw",
        )
    try:
        baseline = corpus_store.load_coverage_regions(evidence.starry_elf_path)
        replay_regions = runtime.extract_regions(
            guest_result.profraw_paths,
            evidence.starry_elf_path,
        )
        new_regions = replay_regions - baseline
    except (OSError, RuntimeError) as error:
        return _record_coverage_failure(
            workspace,
            import_store,
            job,
            batch_index,
            evidence,
            command,
            str(error),
        )
    if not new_regions:
        corpus_store.save_coverage_regions(evidence.starry_elf_path, baseline)
        import_store.record_batch_result(
            job.job_id,
            batch_index,
            result_category="passed-no-new-coverage",
            qemu_runs=1,
        )
        return AdmissionOutcome(
            job.job_id,
            False,
            "passed-no-new-coverage",
            *_host_counts(job),
            1,
            (),
            (),
        )
    attribution_budget = len(batch["digests"]) + 1
    if _remaining_qemu(job, already_used=1) < attribution_budget:
        import_store.record_batch_result(
            job.job_id,
            batch_index,
            result_category="qemu-budget-exhausted",
            qemu_runs=1,
            new_regions=new_regions,
            failed=True,
        )
        return AdmissionOutcome(
            job.job_id,
            True,
            "qemu-budget-exhausted",
            *_host_counts(job),
            1,
            tuple(sorted(new_regions)),
            (),
        )
    return _attribute_and_minimize_batch(
        workspace,
        corpus_store,
        import_store,
        job,
        batch_index,
        evidence,
        baseline,
        replay_regions,
        new_regions,
        runtime,
    )


def _attribute_and_minimize_batch(
    workspace: Path,
    corpus_store: CorpusStore,
    import_store: ImportStore,
    import_job: ImportJob,
    batch_index: int,
    evidence: ImportBatchEvidence,
    baseline: Set[str],
    replay_regions: Set[str],
    new_regions: Set[str],
    runtime: AdmissionRuntime,
) -> AdmissionOutcome:
    batch = import_job.metadata["batches"][batch_index]
    attribution_store = AttributionStore(workspace, corpus_store.generator_version)
    attribution_job_id = f"{import_job.job_id}-batch-{batch_index + 1:04d}"
    attribution_path = attribution_store.jobs_dir / attribution_job_id
    if attribution_path.exists():
        attribution_job = attribution_store.load_job(attribution_job_id)
    else:
        entries = tuple(
            AttributionInput(
                digest,
                import_store.canonical_input_path(import_job, digest).read_bytes(),
                import_store.provenance(import_job, digest),
            )
            for digest in batch["digests"]
        )
        attribution_job = attribution_store.create_job(
            attribution_job_id,
            fuzz_seed=0,
            batch_index=batch_index,
            entries=entries,
            baseline_regions=baseline,
            target_regions=new_regions,
            initial_evidence=ReplayEvidence(
                ops_path=evidence.ops_path,
                trace_path=evidence.trace_path,
                guest_log=evidence.guest_result.log,
                profraw_paths=evidence.guest_result.profraw_paths,
                starry_elf_path=evidence.starry_elf_path,
                host_oracle_path=evidence.host_oracle_path,
                covered_regions=frozenset(replay_regions),
                result_category="passed",
            ),
            duration_seconds=0.0,
        )
    exact = runtime.resume_attribution(
        workspace,
        corpus_store,
        attribution_store,
        runtime.load_active_corpus(corpus_store),
        attribution_job,
    )
    if exact.failed:
        import_store.record_batch_result(
            import_job.job_id,
            batch_index,
            result_category=exact.category,
            qemu_runs=1 + exact.attribution_replays,
            new_regions=exact.new_regions,
            admitted_digests=exact.admitted_digests,
            attribution_job_id=attribution_job_id,
            failed=True,
        )
        return AdmissionOutcome(
            import_job.job_id,
            True,
            exact.category,
            *_host_counts(import_job),
            1 + exact.attribution_replays,
            tuple(exact.new_regions),
            tuple(exact.admitted_digests),
        )

    admitted_digests = tuple(exact.admitted_digests)
    minimization_ids = []
    minimization_qemu = 0
    if exact.representative_digests:
        remaining = _remaining_qemu(
            import_job,
            already_used=1 + exact.attribution_replays,
        )
        if remaining < 3:
            import_store.record_batch_result(
                import_job.job_id,
                batch_index,
                result_category="qemu-budget-exhausted",
                qemu_runs=1 + exact.attribution_replays,
                new_regions=exact.new_regions,
                admitted_digests=exact.admitted_digests,
                attribution_job_id=attribution_job_id,
                failed=True,
            )
            return AdmissionOutcome(
                import_job.job_id,
                True,
                "qemu-budget-exhausted",
                *_host_counts(import_job),
                1 + exact.attribution_replays,
                tuple(exact.new_regions),
                tuple(exact.admitted_digests),
            )
        outcome, minimization_job = runtime.run_minimization(
            workspace,
            corpus_store,
            attribution_job.path,
            remaining - 3,
        )
        minimization_ids.append(outcome.job_id)
        minimization_qemu = _minimization_qemu(minimization_job)
        if outcome.failed:
            import_store.record_batch_result(
                import_job.job_id,
                batch_index,
                result_category=f"minimization-{outcome.category}",
                qemu_runs=1 + exact.attribution_replays + minimization_qemu,
                new_regions=exact.new_regions,
                admitted_digests=exact.admitted_digests,
                attribution_job_id=attribution_job_id,
                minimization_job_ids=minimization_ids,
                failed=True,
            )
            return AdmissionOutcome(
                import_job.job_id,
                True,
                f"minimization-{outcome.category}",
                *_host_counts(import_job),
                1 + exact.attribution_replays + minimization_qemu,
                tuple(exact.new_regions),
                tuple(exact.admitted_digests),
            )
        admitted_digests = tuple(outcome.minimized_digests)
    import_store.record_batch_result(
        import_job.job_id,
        batch_index,
        result_category="passed-new-coverage",
        qemu_runs=1 + exact.attribution_replays + minimization_qemu,
        new_regions=exact.new_regions,
        admitted_digests=admitted_digests,
        attribution_job_id=attribution_job_id,
        minimization_job_ids=minimization_ids,
    )
    attribution_store.mark_run_recorded(attribution_job_id)
    if minimization_ids:
        minimization_store = MinimizationStore(
            workspace,
            corpus_store.generator_version,
        )
        saved = minimization_store.load_job(minimization_ids[0])
        if saved.metadata["state"] == "completed":
            minimization_store.mark_run_recorded(saved)
    return AdmissionOutcome(
        import_job.job_id,
        False,
        "passed-new-coverage",
        *_host_counts(import_job),
        1 + exact.attribution_replays + minimization_qemu,
        tuple(exact.new_regions),
        admitted_digests,
    )


def _record_coverage_failure(
    workspace: Path,
    import_store: ImportStore,
    job: ImportJob,
    batch_index: int,
    evidence: ImportBatchEvidence,
    command: str,
    reason: str,
) -> AdmissionOutcome:
    failure_path, _fingerprint = _save_imported_failure(
        workspace,
        import_store,
        job,
        batch_index,
        evidence,
        command,
        failure_category="coverage-failure",
        extra_log=f"\nCoverage analysis failed: {reason}\n",
    )
    import_store.record_batch_result(
        job.job_id,
        batch_index,
        result_category="coverage-failure",
        qemu_runs=1,
        failed=True,
    )
    return AdmissionOutcome(
        job.job_id,
        True,
        "coverage-failure",
        *_host_counts(job),
        1,
        (),
        (),
        str(failure_path),
    )


def _save_imported_failure(
    workspace: Path,
    import_store: ImportStore,
    job: ImportJob,
    batch_index: int,
    evidence: ImportBatchEvidence,
    command: str,
    *,
    failure_category: Optional[str] = None,
    extra_log: str = "",
) -> Tuple[Path, Optional[MismatchFingerprint]]:
    guest_result = evidence.guest_result
    fingerprint = (
        MismatchFingerprint.for_reduction_input(
            guest_result.difference,
            ReductionInput.initial(parse_document(evidence.ops_path.read_bytes())),
        )
        if guest_result.category == GuestResultCategory.SEMANTIC_MISMATCH
        and guest_result.difference is not None
        else None
    )
    digest = hashlib.sha256(evidence.ops_path.read_bytes()).hexdigest()
    failure_id = f"{job.job_id}-batch-{batch_index + 1:04d}-{digest[:12]}"
    failure_path = import_store.root / "failures" / failure_id
    if failure_path.exists():
        validate_failure(failure_path)
        return failure_path, fingerprint
    source_digest = _source_digest_for_failure(job, evidence, fingerprint)
    source_path, conversion_path, source_metadata = import_store.source_evidence_paths(
        job,
        source_digest,
    )[0]
    external_source = ExternalSource(
        source_metadata["program_sha256"],
        job.metadata["syzkaller_revision"],
        job.metadata["importer_version"],
        source_metadata["conversion_log_sha256"],
    )
    input_map = {
        digest: import_store.canonical_input_path(job, digest).read_bytes()
        for digest in job.metadata["batches"][batch_index]["digests"]
    }

    def write_failure(temporary: Path) -> None:
        if len(input_map) == 1:
            (temporary / "input.bin").write_bytes(next(iter(input_map.values())))
        else:
            inputs = temporary / "inputs"
            inputs.mkdir()
            for canonical_digest, encoded in sorted(input_map.items()):
                (inputs / f"{canonical_digest}.ops").write_bytes(encoded)
        shutil.copy2(evidence.ops_path, temporary / "pipe.ops")
        shutil.copy2(evidence.trace_path, temporary / "linux.trace")
        shutil.copy2(evidence.host_oracle_path, temporary / "pipe-linux-oracle")
        shutil.copy2(evidence.starry_elf_path, temporary / "starryos")
        shutil.copy2(source_path, temporary / "source.syz")
        shutil.copy2(conversion_path, temporary / "conversion-log.json")
        (temporary / "guest.log").write_text(
            guest_result.log + extra_log,
            encoding="utf-8",
        )
        profraws = temporary / "profraws"
        profraws.mkdir()
        for profraw in guest_result.profraw_paths:
            shutil.copy2(profraw, profraws / profraw.name)
        metadata = build_failure_metadata_v3(
            temporary,
            generator_version=corpus_generator_version(),
            fuzz_seed=None,
            batch_index=batch_index,
            command=command,
            result_category=guest_result.category,
            mismatch_fingerprint=fingerprint,
            external_source=external_source,
            failure_category=failure_category or guest_result.category.value,
        )
        save_metadata(temporary, metadata)

    atomic_save(failure_path, write_failure)
    return failure_path, fingerprint


def _source_digest_for_failure(
    job: ImportJob,
    evidence: ImportBatchEvidence,
    fingerprint: Optional[MismatchFingerprint],
) -> str:
    batch_digests = job.metadata["batches"][int(evidence.path.name)]["digests"]
    if fingerprint is None:
        return batch_digests[0]
    scenario_index = fingerprint.operation_origin.scenario_index
    for digest in batch_digests:
        document = parse_document(
            (job.path / "inputs" / f"{digest}.ops").read_bytes()
        )
        if scenario_index < len(document.scenarios):
            return digest
        scenario_index -= len(document.scenarios)
    raise ValueError("mismatch scenario is outside imported batch inputs")


def _record_import_run(
    corpus_store: CorpusStore,
    import_store: ImportStore,
    job: ImportJob,
    outcome: AdmissionOutcome,
    command: str,
) -> None:
    run_path = corpus_store.runs_dir / job.job_id
    if not run_path.exists():
        corpus_store.save_run(
            job.job_id,
            {
                "command": command,
                "result": outcome.category,
                "import": {
                    "job_id": job.job_id,
                    "total_inputs": len(job.metadata["sources"]),
                    "accepted_inputs": sum(
                        source["status"] == "accepted"
                        for source in job.metadata["sources"]
                    ),
                    "unique_canonical": len(job.metadata["canonical_inputs"]),
                    "host_stable": outcome.host_stable,
                    "host_unstable": outcome.host_unstable,
                    "qemu_runs": outcome.qemu_runs,
                    "new_regions": list(outcome.new_regions),
                    "admitted_digests": list(outcome.admitted_digests),
                    "rejection_categories": dict(
                        sorted(
                            Counter(
                                source["rejection_category"]
                                for source in job.metadata["sources"]
                                if source["status"] == "rejected"
                            ).items()
                        )
                    ),
                },
            },
        )
    import_store.mark_run_recorded(job.job_id)


def _outcome_from_job(
    job: ImportJob,
    *,
    admitted: Iterable[str] = (),
    new_regions: Iterable[str] = (),
    failure_path: Optional[str] = None,
) -> AdmissionOutcome:
    stable, unstable = _host_counts(job)
    admitted = set(admitted)
    new_regions = set(new_regions)
    for batch in job.metadata["batches"]:
        admitted.update(batch["admitted_digests"])
        new_regions.update(batch["new_regions"])
    return AdmissionOutcome(
        job.job_id,
        job.metadata["state"] == "failed",
        job.metadata["result_category"] or job.metadata["state"],
        stable,
        unstable,
        job.metadata["qemu_runs"],
        tuple(sorted(new_regions)),
        tuple(sorted(admitted)),
        failure_path,
    )


def _host_counts(job: ImportJob) -> Tuple[int, int]:
    statuses = Counter(
        item["host_status"] for item in job.metadata["canonical_inputs"]
    )
    return statuses["stable"], statuses["unstable"]


def _minimization_qemu(job: object) -> int:
    metadata = job.metadata
    return (
        metadata["candidate_qemu"]
        + metadata["validation_qemu"]
        + metadata["proof_qemu"]
    )


def _remaining_qemu(job: ImportJob, *, already_used: int) -> int:
    return max(
        0,
        job.metadata["settings"]["max_qemu"]
        - job.metadata["qemu_runs"]
        - already_used,
    )


def _admission_report(outcomes: Sequence[AdmissionOutcome]) -> Dict[str, object]:
    return {
        "schema_version": 1,
        "jobs": [
            {
                "job_id": outcome.job_id,
                "result": outcome.category,
                "failed": outcome.failed,
                "host_stable": outcome.host_stable,
                "host_unstable": outcome.host_unstable,
                "qemu_runs": outcome.qemu_runs,
                "new_regions": list(outcome.new_regions),
                "admitted_digests": list(outcome.admitted_digests),
                "failure_path": outcome.failure_path,
            }
            for outcome in outcomes
        ],
        "summary": {
            "jobs": len(outcomes),
            "failed": sum(outcome.failed for outcome in outcomes),
            "host_stable": sum(outcome.host_stable for outcome in outcomes),
            "host_unstable": sum(outcome.host_unstable for outcome in outcomes),
            "qemu_runs": sum(outcome.qemu_runs for outcome in outcomes),
            "new_regions": sorted(
                {region for outcome in outcomes for region in outcome.new_regions}
            ),
            "admitted_digests": sorted(
                {digest for outcome in outcomes for digest in outcome.admitted_digests}
            ),
        },
    }


def _job_matches_report(job: ImportJob, report: Dict[str, object]) -> bool:
    if (
        job.metadata["syzkaller_revision"] != report["syzkaller_revision"]
        or job.metadata["importer_version"] != report["importer_version"]
    ):
        return False
    reports = sorted(report["inputs"], key=lambda item: str(item["path"]))
    sources = job.metadata["sources"]
    if len(reports) != len(sources):
        return False
    return all(
        source["path"] == str(item["path"])
        and source["status"] == item["status"]
        and source["program_sha256"] == item["program_sha256"]
        and source["conversion_log_sha256"] == item["conversion_log_sha256"]
        and source["canonical_digest"] == item["canonical_digest"]
        for source, item in zip(sources, reports)
    )


def _import_job_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"import-{timestamp}-pid-{os.getpid()}"


def corpus_generator_version() -> str:
    from generator import GENERATOR_VERSION

    return GENERATOR_VERSION


__all__ = [
    "AdmissionOutcome",
    "AdmissionRuntime",
    "AttributionAdmissionOutcome",
    "default_runtime",
    "run_admission",
]
