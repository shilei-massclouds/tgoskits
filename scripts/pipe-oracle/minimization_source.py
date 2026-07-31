"""Strict source import for failure and completed-attribution minimization jobs."""

import hashlib
from pathlib import Path
from typing import Optional, Set

from artifact import validate_failure
from attribution import AttributionStore
from corpus import CorpusStore
from corpus_errors import CorpusStorageError
from fingerprint import MismatchFingerprint
from guest_result import GuestResultCategory, classify_guest_execution
from minimization import (
    MinimizationItem,
    assign_coverage_responsibilities,
)
from minimization_store import MinimizationJob, MinimizationStore
from reducer import ReductionInput
from scenario import parse_document, serialize_document


def create_or_load_job_from_source(
    workspace: Path,
    source: Path,
    corpus_store: CorpusStore,
    minimization_store: MinimizationStore,
    *,
    max_qemu: int,
    active_starry_elf: Optional[Path] = None,
) -> MinimizationJob:
    source = source.resolve()
    kind = "coverage" if _looks_like_attribution_source(source) else "mismatch"
    existing = _find_source_job(minimization_store, source, kind)
    if existing is not None:
        return existing
    if _looks_like_attribution_source(source):
        return _create_coverage_job(
            workspace,
            source,
            corpus_store,
            minimization_store,
            max_qemu,
        )
    return _create_mismatch_job(
        source,
        minimization_store,
        max_qemu,
        active_starry_elf,
    )


def _create_mismatch_job(
    source: Path,
    store: MinimizationStore,
    max_qemu: int,
    active_starry_elf: Optional[Path],
) -> MinimizationJob:
    metadata = validate_failure(source)
    document = parse_document((source / "pipe.ops").read_bytes())
    canonical = serialize_document(document).encode("utf-8")
    reduction_input = ReductionInput.initial(document)
    if metadata["schema_version"] == 2:
        if metadata["guest_result_category"] != GuestResultCategory.SEMANTIC_MISMATCH.value:
            raise ValueError("failure source is not a semantic mismatch")
        fingerprint = MismatchFingerprint.from_metadata(
            metadata["mismatch_fingerprint"]
        )
        starry_elf = source / "starryos"
    else:
        execution = classify_guest_execution(
            (source / "guest.log").read_text(encoding="utf-8"),
            1,
        )
        if execution.category != GuestResultCategory.SEMANTIC_MISMATCH:
            raise ValueError(
                "legacy failure does not contain one strict semantic mismatch"
            )
        fingerprint = MismatchFingerprint.for_reduction_input(
            execution.difference,
            reduction_input,
        )
        if active_starry_elf is None or not active_starry_elf.is_file():
            raise ValueError("legacy mismatch import requires the active Starry ELF")
        starry_elf = active_starry_elf
    digest = hashlib.sha256(canonical).hexdigest()
    item = MinimizationItem(
        digest,
        reduction_input,
        critical_origin=fingerprint.operation_origin,
    )
    return store.create_job(
        _source_job_id("mismatch", source),
        kind="mismatch",
        source={"kind": "failure", "path": str(source), "id": source.name},
        items=(item,),
        starry_elf=starry_elf,
        host_oracle=source / "pipe-linux-oracle",
        max_qemu=max_qemu,
        expected_fingerprint=fingerprint,
    )


def _create_coverage_job(
    workspace: Path,
    source: Path,
    corpus_store: CorpusStore,
    store: MinimizationStore,
    max_qemu: int,
) -> MinimizationJob:
    attribution_store = AttributionStore(workspace, corpus_store.generator_version)
    expected_source = attribution_store.jobs_dir / source.name
    if source != expected_source.resolve():
        raise ValueError("attribution source must be a workspace attribution job")
    job = attribution_store.load_job(source.name)
    if job.metadata["state"] != "completed":
        raise ValueError("coverage minimization requires completed attribution")
    representatives = tuple(job.metadata["representative_digests"])
    if not representatives:
        raise ValueError("completed attribution has no coverage representatives")
    entry_regions = {
        digest: set(regions)
        for digest, regions in job.metadata["entry_regions"].items()
    }
    historical = {
        digest: _historical_regions(corpus_store, digest)
        for digest in representatives
    }
    responsibilities = assign_coverage_responsibilities(
        representatives,
        entry_regions,
        historical,
        set(job.metadata["target_regions"]),
    )
    inputs = {entry.digest: entry for entry in attribution_store.input_entries(job)}
    items = tuple(
        MinimizationItem(
            digest,
            ReductionInput.initial(inputs[digest].document),
            frozenset(responsibilities[digest]),
            provenance=inputs[digest].provenance,
        )
        for digest in sorted(representatives)
    )
    starry_elf = (
        job.path
        / "elfs"
        / job.metadata["starry_elf_sha256"]
        / "starryos"
    )
    return store.create_job(
        _source_job_id("coverage", source),
        kind="coverage",
        source={"kind": "attribution", "path": str(source), "id": job.job_id},
        items=items,
        starry_elf=starry_elf,
        host_oracle=attribution_store.host_oracle_path(job),
        max_qemu=max_qemu,
        expected_fingerprint=None,
    )


def _historical_regions(store: CorpusStore, digest: str) -> Set[str]:
    entry_dir = store.corpus_dir / digest
    if not entry_dir.exists():
        return set()
    metadata = store.entry_metadata(digest)
    coverage = metadata["coverage"]
    if coverage["attribution"] == "exact":
        return set(coverage["attributed_regions"])
    return set(coverage["first_batch_new_regions"])


def _find_source_job(
    store: MinimizationStore,
    source: Path,
    kind: str,
) -> Optional[MinimizationJob]:
    store.prepare()
    job_id = _source_job_id(kind, source)
    active_path = store.jobs_dir / job_id
    if active_path.exists() or active_path.is_symlink():
        job = store.load_job(job_id)
        if Path(job.metadata["source"]["path"]).resolve() != source:
            raise CorpusStorageError(f"minimization job source mismatch: {active_path}")
        return job
    failed = store.load_failed_job(job_id)
    if failed is not None:
        raise CorpusStorageError(
            "source already has a terminal minimization job: "
            f"{failed.metadata['state']} at {failed.path}"
        )
    return None


def _looks_like_attribution_source(source: Path) -> bool:
    return source.parent.name == "attribution-jobs"


def _source_job_id(kind: str, source: Path) -> str:
    digest = hashlib.sha256(str(source).encode("utf-8")).hexdigest()[:16]
    return f"minimize-{kind}-{digest}"


__all__ = ["create_or_load_job_from_source"]
