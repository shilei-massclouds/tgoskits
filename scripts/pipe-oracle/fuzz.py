#!/usr/bin/env python3
"""Coverage-guided pipe campaign over canonical structured corpus entries."""

import argparse
import hashlib
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from artifact import build_failure_metadata_v2
from common import save_metadata
from attribution import (
    AttributionInput,
    AttributionJob,
    AttributionStore,
    ReplayEvidence,
)
from attribution_campaign import (
    AttributionReplayRuntime,
    resume_attribution_job,
)
from corpus import (
    CanonicalCorpus,
    CorpusStorageError,
    CorpusStore,
)
from coverage import TARGET_SET_ID
from generator import (
    GENERATOR_VERSION,
    CampaignRng,
    generate_document,
)
from mutation import (
    CandidateClassification,
    MutationCandidate,
    candidate_from_document,
    mutate_document,
)
from minimization_campaign import (
    MinimizationOutcome,
    MinimizationRuntime,
    resume_minimization_job,
)
from minimization_source import create_or_load_job_from_source
from minimization_store import MinimizationStore
from guest_result import GuestExecutionResult, GuestResultCategory, normalize_guest_execution
from fingerprint import MismatchFingerprint
from reducer import ReductionInput
from runner import coverage_object, run_guest_compare
from scenario import combine_documents, parse_document, serialize_document


DEFAULT_SEED = 42
DEFAULT_BATCHES = 4
DEFAULT_BATCH_SIZE = 32
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass(frozen=True)
class HostRecordResult:
    passed: bool
    parser_rejection: bool
    log: str


@dataclass(frozen=True)
class BatchResult:
    failed: bool
    category: str
    new_regions: Tuple[str, ...] = ()
    admitted_digests: Tuple[str, ...] = ()
    starry_elf_sha256: Optional[str] = None
    attribution_job_id: Optional[str] = None
    entry_regions: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()
    representative_digests: Tuple[str, ...] = ()
    attribution_replays: int = 0
    attribution_duration_seconds: Optional[float] = None
    minimization: Optional[Dict] = None

    def __bool__(self) -> bool:
        return self.failed


class CampaignStats:
    def __init__(self):
        self.classifications = Counter()
        self.mutation_kinds = Counter()
        self.malformed_categories = Counter()
        self.host_parser_rejections = 0

    def record(self, candidate: MutationCandidate) -> None:
        self.classifications[candidate.classification.value] += 1
        self.mutation_kinds[candidate.kind] += 1
        if candidate.error_category:
            self.malformed_categories[candidate.error_category] += 1


def main():
    parser = argparse.ArgumentParser(
        description="Script-driven pipe differential coverage fuzzing"
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--batches", type=int, default=DEFAULT_BATCHES)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--workspace", type=Path, default=WORKSPACE_ROOT)
    parser.add_argument("--max-qemu", type=int, default=64)
    parser.add_argument(
        "--no-minimize",
        action="store_true",
        help="Disable automatic coverage and mismatch minimization",
    )
    args = parser.parse_args()
    if args.max_qemu < 0:
        parser.error("--max-qemu must be nonnegative")

    workspace = args.workspace.resolve()
    store = CorpusStore(workspace)
    try:
        with store.campaign_lock():
            return _run_campaign(args, workspace, store)
    except CorpusStorageError as error:
        print(f"ERROR: {error}", flush=True)
        return 1


def _run_campaign(args, workspace: Path, store: CorpusStore) -> int:
    command = shlex.join(sys.argv)
    attribution_store = AttributionStore(workspace, store.generator_version)
    corpus, _built_in_count, _disk_count = _load_active_corpus(store)
    if _resume_saved_jobs(
        workspace,
        store,
        attribution_store,
        corpus,
        command,
    ):
        return 1

    minimization_store = MinimizationStore(workspace, store.generator_version)
    minimize_enabled = hasattr(args, "no_minimize") and not args.no_minimize
    max_qemu = getattr(args, "max_qemu", 64)
    if minimize_enabled and _resume_minimization_work(
        workspace,
        store,
        attribution_store,
        minimization_store,
        command,
        max_qemu,
    ):
        return 1

    corpus, built_in_count, disk_count = _load_active_corpus(store)
    print(
        "Corpus loaded: "
        f"built-in={built_in_count} disk={disk_count} deduplicated-total={len(corpus)}",
        flush=True,
    )

    rng = CampaignRng(args.seed)
    stats = CampaignStats()
    campaign_id = _campaign_id()

    for batch_index in range(args.batches):
        print(f"=== Batch {batch_index + 1}/{args.batches} ===", flush=True)
        batch_candidates = _select_batch(rng, corpus, args.batch_size, stats)
        run_id = f"{campaign_id}-batch-{batch_index + 1:04d}"
        started = time.monotonic()
        batch_result = _run_batch(
            workspace,
            batch_index,
            batch_candidates,
            None,
            corpus,
            store.failures_dir,
            stats,
            store,
            fuzz_seed=args.seed,
            attribution_job_id=run_id,
            minimize_enabled=minimize_enabled,
            max_minimization_qemu=max_qemu,
        )
        duration = time.monotonic() - started
        run_metadata = _build_run_metadata(
            args.seed,
            command,
            batch_index,
            duration,
            batch_candidates,
            batch_result,
        )
        store.save_run(run_id, run_metadata)
        if batch_result.attribution_job_id is not None and not batch_result.failed:
            attribution_store.mark_run_recorded(batch_result.attribution_job_id)
        if batch_result.minimization is not None:
            minimization_job = minimization_store.load_job(
                batch_result.minimization["job_id"]
            )
            if minimization_job.metadata["state"] == "completed":
                minimization_store.mark_run_recorded(minimization_job)
        if batch_result.failed:
            print(f"Batch {batch_index + 1} failed, stopping.", flush=True)
            return 1
        if batch_result.minimization is not None:
            corpus, _built_in_count, _disk_count = _load_active_corpus(store)
    print(
        "All batches completed: "
        f"executable={stats.classifications['executable']} "
        f"malformed={stats.classifications['malformed']} "
        f"host_parser_rejections={stats.host_parser_rejections}.",
        flush=True,
    )
    return 0


def _load_active_corpus(store: CorpusStore) -> Tuple[CanonicalCorpus, int, int]:
    corpus = CanonicalCorpus.initial()
    built_in_count = len(corpus)
    disk_corpus = store.load_corpus()
    for entry in disk_corpus.ordered_entries():
        corpus.add(entry.document)
    return corpus, built_in_count, len(disk_corpus)


def _campaign_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{timestamp}-pid-{os.getpid()}"


def _build_run_metadata(
    seed: int,
    command: str,
    batch_index: int,
    duration: float,
    candidates: List[MutationCandidate],
    result: BatchResult,
) -> Dict:
    executable = [
        candidate
        for candidate in candidates
        if candidate.classification == CandidateClassification.EXECUTABLE
        and candidate.document is not None
    ]
    sources = Counter(candidate.provenance.source for candidate in candidates)
    relationships = []
    for candidate in candidates:
        provenance = candidate.provenance
        relationships.append(
            {
                "digest": candidate.digest,
                "classification": candidate.classification.value,
                "source": provenance.source,
                "parent_digest": provenance.parent_digest,
                "donor_digest": provenance.donor_digest,
                "mutation_type": provenance.mutation_type,
                "error_category": candidate.error_category,
            }
        )
    return {
        "fuzz_seed": seed,
        "command": command,
        "batch_index": batch_index,
        "batch_duration_seconds": round(duration, 6),
        "candidate_counts": {
            "candidates": len(candidates),
            "executable": len(executable),
            "malformed": len(candidates) - len(executable),
            "unique_inputs": len({candidate.digest for candidate in executable}),
        },
        "candidate_sources": dict(sorted(sources.items())),
        "candidate_relationships": relationships,
        "new_regions": list(result.new_regions),
        "admitted_digests": list(result.admitted_digests),
        "starry_elf_sha256": result.starry_elf_sha256,
        "attribution": {
            "mode": "exact",
            "job_id": result.attribution_job_id,
            "qemu_replays": result.attribution_replays,
            "entry_regions": [
                {"digest": digest, "regions": list(regions)}
                for digest, regions in result.entry_regions
            ],
            "representative_digests": list(result.representative_digests),
        },
        "minimization": result.minimization,
        "result": result.category,
    }


def _resume_saved_jobs(
    workspace: Path,
    store: CorpusStore,
    attribution_store: AttributionStore,
    corpus: CanonicalCorpus,
    command: str,
) -> bool:
    jobs = attribution_store.load_resumable_jobs()
    if jobs:
        print(
            f"Resuming {len(jobs)} persisted attribution job(s) before new batches.",
            flush=True,
        )
    for saved_job in jobs:
        result = _resume_attribution_job(
            workspace,
            store,
            attribution_store,
            corpus,
            saved_job,
        )
        run_path = store.runs_dir / saved_job.job_id
        if not run_path.exists():
            store.save_run(
                saved_job.job_id,
                _build_resumed_run_metadata(saved_job, result, command),
            )
        if result.failed:
            return True
        attribution_store.mark_run_recorded(saved_job.job_id)
    return False


def _build_resumed_run_metadata(
    job: AttributionJob,
    result: BatchResult,
    command: str,
) -> Dict:
    entries = job.metadata["entries"]
    sources = Counter(entry["origin"]["source"] for entry in entries)
    relationships = [
        {
            "digest": entry["digest"],
            "classification": CandidateClassification.EXECUTABLE.value,
            "source": entry["origin"]["source"],
            "parent_digest": entry["origin"]["parent_digest"],
            "donor_digest": entry["origin"]["donor_digest"],
            "mutation_type": entry["origin"]["mutation_type"],
            "error_category": None,
        }
        for entry in entries
    ]
    return {
        "fuzz_seed": job.metadata["fuzz_seed"],
        "command": command,
        "batch_index": job.metadata["batch_index"],
        "batch_duration_seconds": (
            result.attribution_duration_seconds
            if result.attribution_duration_seconds is not None
            else job.metadata["duration_seconds"]
        ),
        "candidate_counts": {
            "candidates": len(entries),
            "executable": len(entries),
            "malformed": 0,
            "unique_inputs": len(entries),
        },
        "candidate_sources": dict(sorted(sources.items())),
        "candidate_relationships": relationships,
        "new_regions": list(result.new_regions),
        "admitted_digests": list(result.admitted_digests),
        "starry_elf_sha256": result.starry_elf_sha256,
        "attribution": {
            "mode": "exact",
            "job_id": result.attribution_job_id,
            "qemu_replays": result.attribution_replays,
            "entry_regions": [
                {"digest": digest, "regions": list(regions)}
                for digest, regions in result.entry_regions
            ],
            "representative_digests": list(result.representative_digests),
        },
        "minimization": result.minimization,
        "resumed": True,
        "result": result.category,
    }


def _resume_minimization_work(
    workspace: Path,
    store: CorpusStore,
    attribution_store: AttributionStore,
    minimization_store: MinimizationStore,
    command: str,
    max_qemu: int,
) -> bool:
    attribution_store.prepare()
    for path in sorted(attribution_store.jobs_dir.iterdir(), key=lambda item: item.name):
        if path.name.startswith(".") or not path.is_dir():
            continue
        attribution_job = attribution_store.load_job(path.name)
        if (
            attribution_job.metadata["state"] == "completed"
            and attribution_job.metadata["representative_digests"]
        ):
            create_or_load_job_from_source(
                workspace,
                attribution_job.path,
                store,
                minimization_store,
                max_qemu=max_qemu,
                active_starry_elf=coverage_object(workspace),
            )

    jobs = minimization_store.load_resumable_jobs()
    if jobs:
        print(
            f"Resuming {len(jobs)} persisted minimization job(s) before corpus reload.",
            flush=True,
        )
    runtime = _minimization_runtime()
    for job in jobs:
        outcome = resume_minimization_job(
            workspace,
            store,
            minimization_store,
            job,
            runtime,
        )
        if outcome.failed:
            return True
        completed = minimization_store.load_job(job.job_id)
        run_path = store.runs_dir / job.job_id
        if not run_path.exists():
            store.save_run(
                job.job_id,
                {
                    "command": command,
                    "result": "passed",
                    "minimization": _minimization_summary(outcome, completed),
                    "resumed": True,
                },
            )
        minimization_store.mark_run_recorded(completed)
        if completed.metadata["kind"] == "mismatch":
            return True
    return False


def _minimization_runtime() -> MinimizationRuntime:
    return MinimizationRuntime(
        record_host=_record_host,
        run_guest_compare=_run_guest_compare,
        extract_regions=_extract_regions,
        coverage_object=coverage_object,
    )


def _minimization_summary(
    outcome: MinimizationOutcome,
    job,
) -> Dict:
    return {
        "job_id": outcome.job_id,
        "kind": job.metadata["kind"],
        "original_digests": list(outcome.original_digests),
        "minimized_digests": list(outcome.minimized_digests),
        "attempts": len(job.metadata["attempts"]),
        "candidate_qemu": outcome.candidate_qemu,
        "validation_qemu": job.metadata["validation_qemu"],
        "proof_qemu": outcome.proof_qemu,
        "completion": outcome.completion,
        "size_changes": [
            {
                "original": item["original_size"],
                "minimized": item["best_size"],
            }
            for item in job.metadata["items"]
        ],
    }


def _resume_attribution_job(
    workspace: Path,
    store: CorpusStore,
    attribution_store: AttributionStore,
    corpus: CanonicalCorpus,
    job: AttributionJob,
) -> BatchResult:
    runtime = AttributionReplayRuntime(
        record_host=_record_host,
        run_guest_compare=_run_guest_compare,
        extract_regions=_extract_regions,
        coverage_object=coverage_object,
    )
    outcome = resume_attribution_job(
        workspace,
        store,
        attribution_store,
        corpus,
        job,
        runtime,
    )
    return BatchResult(
        outcome.failed,
        outcome.category,
        outcome.new_regions,
        outcome.admitted_digests,
        outcome.starry_elf_sha256,
        outcome.job_id,
        outcome.entry_regions,
        outcome.representative_digests,
        outcome.qemu_replays,
        outcome.duration_seconds,
    )


def _select_batch(
    rng,
    corpus: CanonicalCorpus,
    batch_size: int,
    stats: Optional[CampaignStats] = None,
) -> List[MutationCandidate]:
    parents = corpus.ordered_entries()
    batch = []
    for _ in range(batch_size):
        if not parents or rng.range(0, 10) < 3:
            candidate = candidate_from_document(generate_document(rng), "generate")
        else:
            parent_index = rng.range(0, len(parents))
            parent = parents[parent_index]
            donor = _select_donor(rng, parents, parent_index)
            candidate = mutate_document(
                rng,
                parent.document,
                donor.document if donor is not None else None,
            )
        batch.append(candidate)
        if stats is not None:
            stats.record(candidate)
    return batch


def _select_donor(rng, parents, parent_index):
    if len(parents) < 2:
        return None
    donor_index = rng.range(0, len(parents) - 1)
    if donor_index >= parent_index:
        donor_index += 1
    return parents[donor_index]


def _run_batch(
    workspace: Path,
    batch_index: int,
    candidates: List[MutationCandidate],
    covered_regions: Optional[Set[str]],
    corpus: CanonicalCorpus,
    failures_dir: Path,
    stats: Optional[CampaignStats] = None,
    store: Optional[CorpusStore] = None,
    *,
    fuzz_seed: int = DEFAULT_SEED,
    attribution_job_id: Optional[str] = None,
    minimize_enabled: bool = False,
    max_minimization_qemu: int = 64,
) -> BatchResult:
    batch_started = time.monotonic()
    executable = [
        candidate
        for candidate in candidates
        if candidate.classification == CandidateClassification.EXECUTABLE
        and candidate.document is not None
    ]
    malformed_count = len(candidates) - len(executable)
    if not executable:
        print(
            f"  Filtered {malformed_count} malformed candidates; no host/QEMU run.",
            flush=True,
        )
        return BatchResult(False, "no-executable-input")

    candidate_map = {
        candidate.digest: candidate
        for candidate in sorted(executable, key=lambda item: item.digest)
    }
    input_map = {
        digest: candidate_map[digest].encoded
        for digest in sorted(candidate_map)
    }
    documents = [
        parse_document(input_map[digest])
        for digest in sorted(input_map)
    ]
    batch_document = combine_documents(documents)
    ops_text = serialize_document(batch_document)
    ops_digest = hashlib.sha256(ops_text.encode("utf-8")).hexdigest()
    scenario_count = sum(len(document.scenarios) for document in documents)

    print(
        f"  Prepared {scenario_count} scenario groups from {len(input_map)} "
        f"canonical entries; filtered {malformed_count} malformed candidates",
        flush=True,
    )

    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        ops_path = temporary / "pipe.ops"
        ops_path.write_text(ops_text)
        elf_path = _find_or_build_host_oracle(workspace)
        if elf_path is None:
            print("ERROR: cannot build pipe-linux-oracle ELF", flush=True)
            return BatchResult(True, "host-oracle-build-failure")

        trace_path = temporary / "linux.trace"
        host_record = _record_host(elf_path, ops_path, trace_path)
        if not host_record.passed:
            if host_record.parser_rejection:
                if stats is not None:
                    stats.host_parser_rejections += 1
                print(
                    "  Host parser rejected the structured batch; recorded as malformed "
                    "and skipped before QEMU.",
                    flush=True,
                )
                return BatchResult(False, "host-parser-rejection")
            print(f"ERROR: host record failed\n{host_record.log}", flush=True)
            return BatchResult(True, "host-record-failure")

        artifact_elf = temporary / "pipe-linux-oracle"
        shutil.copy2(elf_path, artifact_elf)
        guest_result = normalize_guest_execution(
            _run_guest_compare(workspace, temporary)
        )
        guest_log = guest_result.log
        profraws = list(guest_result.profraw_paths)

        if not guest_result.passed:
            category = guest_result.category.value
            mismatch_fingerprint = (
                MismatchFingerprint.for_reduction_input(
                    guest_result.difference,
                    ReductionInput.initial(batch_document),
                )
                if guest_result.category == GuestResultCategory.SEMANTIC_MISMATCH
                and guest_result.difference is not None
                else None
            )
            failure_label = (
                "mismatch"
                if guest_result.category == GuestResultCategory.SEMANTIC_MISMATCH
                else "guest"
            )
            failure_id = f"batch{batch_index}_{failure_label}_{ops_digest[:12]}"
            failure_path = failures_dir / failure_id
            _save_batch_failure(
                failure_path,
                input_map,
                ops_text,
                artifact_elf,
                trace_path,
                guest_log,
                profraws,
                batch_index,
                fuzz_seed,
                guest_result.category,
                category,
                coverage_object(workspace),
                mismatch_fingerprint,
            )
            print(
                "  "
                + (
                    "MISMATCH"
                    if guest_result.category
                    == GuestResultCategory.SEMANTIC_MISMATCH
                    else category.upper()
                )
                + f" saved to {failure_path.relative_to(workspace)}",
                flush=True,
            )
            minimization_summary = None
            if store is not None and minimize_enabled and (
                guest_result.category == GuestResultCategory.SEMANTIC_MISMATCH
            ):
                outcome, minimization_job = _run_source_minimization(
                    workspace,
                    store,
                    failure_path,
                    max_minimization_qemu,
                )
                if not outcome.failed:
                    minimization_summary = _minimization_summary(
                        outcome,
                        minimization_job,
                    )
            return BatchResult(
                True,
                category,
                minimization=minimization_summary,
            )

        try:
            if not profraws:
                raise RuntimeError(
                    "QEMU passed without producing the expected Starry profraw"
                )
            starry_elf = coverage_object(workspace)
            if store is None:
                active_covered_regions = (
                    covered_regions if covered_regions is not None else set()
                )
                new_regions = _extract_new_regions(
                    profraws,
                    starry_elf,
                    active_covered_regions,
                )
                admitted_digests = tuple(sorted(candidate_map)) if new_regions else ()
                starry_elf_digest = None
                exact_result = None
            else:
                baseline_regions = store.load_coverage_regions(starry_elf)
                replay_regions = _extract_regions(profraws, starry_elf)
                new_regions = replay_regions - baseline_regions
                starry_elf_digest = store.elf_digest(starry_elf)
                if new_regions:
                    job_id = attribution_job_id or (
                        f"manual-{_campaign_id()}-batch-{batch_index + 1:04d}"
                    )
                    attribution_store = AttributionStore(
                        workspace,
                        store.generator_version,
                    )
                    entries = tuple(
                        AttributionInput(
                            digest,
                            candidate_map[digest].encoded,
                            candidate_map[digest].provenance,
                        )
                        for digest in sorted(candidate_map)
                    )
                    initial_evidence = ReplayEvidence(
                        ops_path=ops_path,
                        trace_path=trace_path,
                        guest_log=guest_log,
                        profraw_paths=tuple(profraws),
                        starry_elf_path=starry_elf,
                        host_oracle_path=artifact_elf,
                        covered_regions=frozenset(replay_regions),
                        result_category="passed",
                    )
                    job = attribution_store.create_job(
                        job_id,
                        fuzz_seed=fuzz_seed,
                        batch_index=batch_index,
                        entries=entries,
                        baseline_regions=baseline_regions,
                        target_regions=new_regions,
                        initial_evidence=initial_evidence,
                        duration_seconds=time.monotonic() - batch_started,
                    )
                    exact_result = _resume_attribution_job(
                        workspace,
                        store,
                        attribution_store,
                        corpus,
                        job,
                    )
                    if exact_result.failed:
                        return exact_result
                    admitted_digests = exact_result.admitted_digests
                    starry_elf_digest = exact_result.starry_elf_sha256
                else:
                    store.save_coverage_regions(starry_elf, baseline_regions)
                    admitted_digests = ()
                    exact_result = None
        except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
            guest_log += f"\nCoverage analysis failed: {error}\n"
            failure_id = f"batch{batch_index}_coverage_{ops_digest[:12]}"
            failure_path = failures_dir / failure_id
            _save_batch_failure(
                failure_path,
                input_map,
                ops_text,
                artifact_elf,
                trace_path,
                guest_log,
                profraws,
                batch_index,
                fuzz_seed,
                guest_result.category,
                "coverage-failure",
                coverage_object(workspace),
                None,
            )
            print(
                f"  COVERAGE FAILURE saved to {failure_path.relative_to(workspace)}",
                flush=True,
            )
            return BatchResult(True, "coverage-failure")

        print(
            f"  Coverage saved: {len(profraws)} profraw(s), "
            f"{len(new_regions)} new target regions",
            flush=True,
        )

    if exact_result is not None:
        if store is not None and minimize_enabled:
            attribution_path = (
                workspace
                / "coverage/pipe-oracle-fuzz/attribution-jobs"
                / exact_result.attribution_job_id
            )
            outcome, minimization_job = _run_source_minimization(
                workspace,
                store,
                attribution_path,
                max_minimization_qemu,
            )
            if outcome.failed:
                return replace(
                    exact_result,
                    failed=True,
                    category=f"minimization-{outcome.category}",
                )
            return replace(
                exact_result,
                minimization=_minimization_summary(outcome, minimization_job),
            )
        return exact_result
    return BatchResult(
        False,
        "passed",
        tuple(sorted(new_regions)),
        admitted_digests,
        starry_elf_digest,
    )


def _run_source_minimization(
    workspace: Path,
    corpus_store: CorpusStore,
    source: Path,
    max_qemu: int,
) -> Tuple[MinimizationOutcome, object]:
    minimization_store = MinimizationStore(
        workspace,
        corpus_store.generator_version,
    )
    job = create_or_load_job_from_source(
        workspace,
        source,
        corpus_store,
        minimization_store,
        max_qemu=max_qemu,
        active_starry_elf=coverage_object(workspace),
    )
    outcome = resume_minimization_job(
        workspace,
        corpus_store,
        minimization_store,
        job,
        _minimization_runtime(),
    )
    if outcome.failed:
        return outcome, job
    return outcome, minimization_store.load_job(job.job_id)


def _find_or_build_host_oracle(workspace: Path) -> Optional[Path]:
    source_dir = workspace / "test-suit/starryos/qemu/pipe-linux-oracle/c"
    build_dir = workspace / "target/pipe-oracle-host"
    elf_path = build_dir / "pipe-linux-oracle"

    build_environment = os.environ.copy()
    build_environment.pop("STARRY_PIPE_ORACLE_ARTIFACT_DIR", None)
    try:
        subprocess.run(
            ["cmake", "-S", str(source_dir), "-B", str(build_dir)],
            cwd=str(workspace),
            env=build_environment,
            check=True,
        )
        subprocess.run(
            ["cmake", "--build", str(build_dir), "--target", "pipe-linux-oracle"],
            cwd=str(workspace),
            env=build_environment,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return elf_path if elf_path.is_file() else None


def _record_host(elf: Path, ops: Path, trace: Path) -> HostRecordResult:
    try:
        result = subprocess.run(
            [str(elf), "--record", str(ops), str(trace)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return HostRecordResult(False, False, str(error))
    log = result.stdout + "\n" + result.stderr
    return HostRecordResult(
        result.returncode == 0,
        result.returncode != 0 and _is_host_parser_rejection(result.stderr),
        log,
    )


def _is_host_parser_rejection(stderr: str) -> bool:
    parser_messages = (
        "corpus line is too long",
        "invalid corpus version",
        "invalid scenario",
        "invalid operation",
        "operation appears before first scenario",
        "operation corpus is incomplete",
    )
    return any(message in stderr for message in parser_messages)


def _run_guest_compare(
    workspace: Path,
    artifact_dir: Path,
    pinned_starry_elf: Optional[Path] = None,
) -> GuestExecutionResult:
    return run_guest_compare(workspace, artifact_dir, pinned_starry_elf)


def _extract_new_regions(
    profraws: List[Path],
    elf: Path,
    covered_regions: Set[str],
    target_set_id: str = TARGET_SET_ID,
) -> Set[str]:
    if not profraws:
        return set()
    from coverage import merge_profraws, pipe_region_set

    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        profdata = temporary / "merged.profdata"
        merge_profraws(profraws, profdata)
        regions = pipe_region_set(profdata, elf, target_set_id)
        new_regions = regions - covered_regions
        covered_regions.update(new_regions)
        return new_regions


def _extract_regions(
    profraws: List[Path],
    elf: Path,
    target_set_id: str = TARGET_SET_ID,
) -> Set[str]:
    if not profraws:
        return set()
    from coverage import merge_profraws, pipe_region_set

    with tempfile.TemporaryDirectory() as temporary_directory:
        profdata = Path(temporary_directory) / "merged.profdata"
        merge_profraws(profraws, profdata)
        return pipe_region_set(profdata, elf, target_set_id)


def _save_batch_failure(
    destination: Path,
    input_map: Dict[str, bytes],
    ops_text: str,
    elf: Path,
    trace: Path,
    guest_log: str,
    profraws: List[Path],
    batch_index: int,
    fuzz_seed: int,
    guest_category: GuestResultCategory,
    failure_category: str,
    starry_elf: Path,
    mismatch_fingerprint: Optional[MismatchFingerprint],
):
    from common import atomic_save

    atomic_save(
        destination,
        lambda temporary: _write_failure_parts(
            temporary,
            input_map,
            ops_text,
            elf,
            trace,
            guest_log,
            profraws,
            batch_index,
            fuzz_seed,
            guest_category,
            failure_category,
            starry_elf,
            mismatch_fingerprint,
        ),
    )


def _write_failure_parts(
    temporary: Path,
    input_map: Dict[str, bytes],
    ops_text: str,
    elf_path: Path,
    trace_path: Path,
    guest_log: str,
    profraws: List[Path],
    batch_index: int,
    fuzz_seed: int,
    guest_category: GuestResultCategory,
    failure_category: str,
    starry_elf: Path,
    mismatch_fingerprint: Optional[MismatchFingerprint],
):
    if len(input_map) == 1:
        key = next(iter(sorted(input_map)))
        (temporary / "input.bin").write_bytes(input_map[key])
    else:
        input_directory = temporary / "inputs"
        input_directory.mkdir()
        for digest in sorted(input_map):
            (input_directory / f"{digest}.ops").write_bytes(input_map[digest])
    (temporary / "pipe.ops").write_text(ops_text)
    shutil.copy2(elf_path, temporary / "pipe-linux-oracle")
    if starry_elf.is_file():
        shutil.copy2(starry_elf, temporary / "starryos")
    shutil.copy2(trace_path, temporary / "linux.trace")
    (temporary / "guest.log").write_text(guest_log)
    profraw_directory = temporary / "profraws"
    profraw_directory.mkdir()
    for profraw in profraws:
        if profraw.exists():
            shutil.copy2(profraw, profraw_directory / profraw.name)
    metadata = build_failure_metadata_v2(
        temporary,
        generator_version=GENERATOR_VERSION,
        fuzz_seed=fuzz_seed,
        batch_index=batch_index,
        command=" ".join(sys.argv),
        result_category=guest_category,
        mismatch_fingerprint=mismatch_fingerprint,
        failure_category=failure_category,
    )
    save_metadata(temporary, metadata)


_Rng = CampaignRng


if __name__ == "__main__":
    sys.exit(main())
