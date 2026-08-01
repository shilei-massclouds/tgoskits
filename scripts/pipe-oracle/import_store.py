"""Atomic storage and progress updates for resumable syzkaller imports."""

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from common import CORPUS_DIR
from batch_execution import BatchExecution
from corpus import CorpusProvenance, ExternalSource
from corpus_errors import CorpusStorageError, CorpusValidationError
from import_schema import (
    BATCH_EVIDENCE_NAME,
    CONVERSIONS_NAME,
    IMPORT_JOBS_NAME,
    IMPORT_JOB_SCHEMA_VERSION,
    INPUTS_NAME,
    JOB_ID_PATTERN,
    METADATA_NAME,
    SOURCES_NAME,
    TEMP_PATTERN,
    read_json,
    sha256_bytes,
    validate_job_files,
    validate_job_metadata,
)
from guest_result import (
    GuestExecutionResult,
    GuestResultCategory,
    classify_guest_execution,
)
from syz_import import conversion_log_bytes


@dataclass(frozen=True)
class ImportJob:
    job_id: str
    path: Path
    metadata: Dict[str, Any]


@dataclass(frozen=True)
class ImportBatchEvidence:
    path: Path
    ops_path: Path
    trace_path: Path
    host_oracle_path: Path
    starry_elf_path: Path
    guest_result: GuestExecutionResult


class ImportStore:
    """Own original programs, conversion evidence, and admission progress."""

    def __init__(self, workspace: Path):
        self.workspace = workspace.resolve()
        self.root = self.workspace / CORPUS_DIR
        self.jobs_dir = self.root / IMPORT_JOBS_NAME

    def prepare(self) -> None:
        self.jobs_dir.mkdir(parents=True, exist_ok=True)

    def create_job(
        self,
        job_id: str,
        *,
        reports: Sequence[Dict[str, object]],
        syzkaller_revision: str,
        importer_version: str,
        host_repetitions: int,
        batch_size: int,
        max_qemu: int,
    ) -> ImportJob:
        self.prepare()
        _validate_job_id(job_id)
        if self.jobs_dir.joinpath(job_id).exists():
            raise CorpusStorageError(f"import job already exists: {job_id}")
        _validate_settings(host_repetitions, batch_size, max_qemu)
        ordered_reports = tuple(sorted(reports, key=lambda report: str(report["path"])))
        if len({str(report["path"]) for report in ordered_reports}) != len(ordered_reports):
            raise ValueError("import reports must have unique paths")

        source_metadata, raw_sources, conversion_logs = _prepare_sources(
            ordered_reports,
            syzkaller_revision,
        )
        canonical_inputs, canonical_ops = _prepare_canonical_inputs(
            ordered_reports,
            source_metadata,
        )
        now = _now()
        metadata = {
            "schema_version": IMPORT_JOB_SCHEMA_VERSION,
            "job_id": job_id,
            "state": "classified",
            "run_recorded": False,
            "syzkaller_revision": syzkaller_revision,
            "importer_version": importer_version,
            "created_at": now,
            "updated_at": now,
            "duration_seconds": 0.0,
            "settings": {
                "host_repetitions": host_repetitions,
                "batch_size": batch_size,
                "max_qemu": max_qemu,
            },
            "sources": source_metadata,
            "canonical_inputs": canonical_inputs,
            "batches": [],
            "next_batch_index": 0,
            "qemu_runs": 0,
            "attribution_job_ids": [],
            "minimization_job_ids": [],
            "result_category": None,
            "failure_reason": None,
        }

        destination = self.jobs_dir / job_id
        validate_job_metadata(metadata, destination)
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{job_id}.tmp-", dir=self.jobs_dir)
        )
        try:
            sources_dir = temporary / SOURCES_NAME
            conversions_dir = temporary / CONVERSIONS_NAME
            inputs_dir = temporary / INPUTS_NAME
            batch_evidence_dir = temporary / BATCH_EVIDENCE_NAME
            sources_dir.mkdir()
            conversions_dir.mkdir()
            inputs_dir.mkdir()
            batch_evidence_dir.mkdir()
            for evidence_id, encoded in raw_sources.items():
                _write_bytes(sources_dir / f"{evidence_id}.syz", encoded)
            for evidence_id, encoded in conversion_logs.items():
                _write_bytes(conversions_dir / f"{evidence_id}.json", encoded)
            for digest, encoded in canonical_ops.items():
                _write_bytes(inputs_dir / f"{digest}.ops", encoded)
            _write_json(temporary / METADATA_NAME, metadata)
            for directory in (
                sources_dir,
                conversions_dir,
                inputs_dir,
                batch_evidence_dir,
                temporary,
            ):
                _sync_directory(directory)
            os.replace(temporary, destination)
            _sync_directory(self.jobs_dir)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return self.load_job(job_id)

    def load_job(self, job_id: str) -> ImportJob:
        self.prepare()
        _validate_job_id(job_id)
        path = self.jobs_dir / job_id
        if path.is_symlink() or not path.is_dir():
            raise CorpusValidationError(path, "expected an import job directory")
        metadata = read_json(path / METADATA_NAME)
        validate_job_metadata(metadata, path)
        validate_job_files(path, metadata)
        return ImportJob(job_id, path, metadata)

    def load_resumable_jobs(self) -> List[ImportJob]:
        return [
            job
            for job in self.load_jobs()
            if job.metadata["state"] not in {"completed", "failed"}
            or (
                job.metadata["state"] == "completed"
                and not job.metadata["run_recorded"]
            )
        ]

    def load_jobs(self) -> List[ImportJob]:
        """Load every finalized import job in deterministic order."""
        self.prepare()
        jobs = []
        for path in sorted(self.jobs_dir.iterdir(), key=lambda item: item.name):
            if TEMP_PATTERN.fullmatch(path.name):
                continue
            jobs.append(self.load_job(path.name))
        return jobs

    def begin_host_stability(self, job_id: str) -> ImportJob:
        job = self.load_job(job_id)
        if job.metadata["state"] == "host-stability":
            return job
        if job.metadata["state"] != "classified":
            raise CorpusStorageError("import job cannot begin host stability")
        metadata = _copy_metadata(job.metadata)
        metadata["state"] = "host-stability"
        return self._save_metadata(job, metadata)

    def record_host_result(
        self,
        job_id: str,
        digest: str,
        *,
        stable: bool,
        trace_sha256: str,
        duration_seconds: float,
    ) -> ImportJob:
        job = self.load_job(job_id)
        if job.metadata["state"] != "host-stability":
            raise CorpusStorageError("import job is not checking host stability")
        metadata = _copy_metadata(job.metadata)
        target = next(
            (item for item in metadata["canonical_inputs"] if item["digest"] == digest),
            None,
        )
        if target is None:
            raise CorpusStorageError(f"import job has no canonical input {digest}")
        expected_status = "stable" if stable else "unstable"
        if target["host_status"] != "pending":
            if (
                target["host_status"] == expected_status
                and target["host_trace_sha256"] == trace_sha256
            ):
                return job
            raise CorpusStorageError("import host result conflicts with saved progress")
        if not _is_digest(trace_sha256):
            raise ValueError("host trace digest is invalid")
        _add_duration(metadata, duration_seconds)
        target["host_status"] = expected_status
        target["host_trace_sha256"] = trace_sha256
        return self._save_metadata(job, metadata)

    def configure_batches(
        self,
        job_id: str,
        batches: Sequence[Sequence[str]],
    ) -> ImportJob:
        job = self.load_job(job_id)
        if job.metadata["state"] not in {"host-stability", "qemu-batches"}:
            raise CorpusStorageError("import job cannot configure QEMU batches")
        if job.metadata["batches"]:
            expected = tuple(tuple(batch["digests"]) for batch in job.metadata["batches"])
            actual = tuple(tuple(sorted(batch)) for batch in batches)
            if actual != expected:
                raise CorpusStorageError("import QEMU batches conflict with saved progress")
            return job
        stable = {
            item["digest"]
            for item in job.metadata["canonical_inputs"]
            if item["host_status"] == "stable"
        }
        if any(item["host_status"] == "pending" for item in job.metadata["canonical_inputs"]):
            raise CorpusStorageError("host stability is incomplete")
        ordered_batches = tuple(tuple(sorted(batch)) for batch in batches)
        flattened = [digest for batch in ordered_batches for digest in batch]
        if (
            any(not batch for batch in ordered_batches)
            or len(flattened) != len(set(flattened))
            or set(flattened) != stable
            or any(
                len(batch) > job.metadata["settings"]["batch_size"]
                for batch in ordered_batches
            )
        ):
            raise ValueError("QEMU batches must partition stable canonical inputs")
        metadata = _copy_metadata(job.metadata)
        metadata["batches"] = [
            {
                "index": index,
                "digests": list(batch),
                "state": "pending",
                "result_category": None,
                "qemu_runs": 0,
                "new_regions": [],
                "admitted_digests": [],
                "attribution_job_id": None,
                "minimization_job_ids": [],
            }
            for index, batch in enumerate(ordered_batches)
        ]
        metadata["state"] = "qemu-batches"
        return self._save_metadata(job, metadata)

    def record_batch_result(
        self,
        job_id: str,
        batch_index: int,
        *,
        result_category: str,
        qemu_runs: int,
        new_regions: Iterable[str] = (),
        admitted_digests: Iterable[str] = (),
        attribution_job_id: Optional[str] = None,
        minimization_job_ids: Iterable[str] = (),
        duration_seconds: float = 0.0,
        failed: bool = False,
    ) -> ImportJob:
        job = self.load_job(job_id)
        if job.metadata["state"] != "qemu-batches":
            raise CorpusStorageError("import job is not processing QEMU batches")
        if batch_index != job.metadata["next_batch_index"]:
            if 0 <= batch_index < len(job.metadata["batches"]):
                saved = job.metadata["batches"][batch_index]
                if saved["state"] != "pending":
                    return job
            raise CorpusStorageError("import batch is not the next pending batch")
        if not isinstance(result_category, str) or not result_category:
            raise ValueError("batch result category must be non-empty")
        if not isinstance(qemu_runs, int) or isinstance(qemu_runs, bool) or qemu_runs < 0:
            raise ValueError("batch QEMU count must be nonnegative")
        metadata = _copy_metadata(job.metadata)
        batch = metadata["batches"][batch_index]
        batch["state"] = "failed" if failed else "completed"
        batch["result_category"] = result_category
        batch["qemu_runs"] = qemu_runs
        batch["new_regions"] = sorted(set(new_regions))
        batch["admitted_digests"] = sorted(set(admitted_digests))
        batch["attribution_job_id"] = attribution_job_id
        batch["minimization_job_ids"] = sorted(set(minimization_job_ids))
        metadata["next_batch_index"] += 1
        metadata["qemu_runs"] += qemu_runs
        if attribution_job_id is not None:
            metadata["attribution_job_ids"] = sorted(
                set(metadata["attribution_job_ids"]) | {attribution_job_id}
            )
        metadata["minimization_job_ids"] = sorted(
            set(metadata["minimization_job_ids"]) | set(batch["minimization_job_ids"])
        )
        _add_duration(metadata, duration_seconds)
        return self._save_metadata(job, metadata)

    def save_batch_evidence(
        self,
        job_id: str,
        batch_index: int,
        execution: BatchExecution,
        starry_elf: Path,
    ) -> ImportBatchEvidence:
        """Persist one completed QEMU execution before advancing job metadata."""
        job = self.load_job(job_id)
        if not 0 <= batch_index < len(job.metadata["batches"]):
            raise CorpusStorageError("import batch index is outside the job")
        batch = job.metadata["batches"][batch_index]
        if tuple(batch["digests"]) != tuple(
            item.digest for item in execution.prepared.inputs
        ):
            raise CorpusStorageError("batch execution inputs mismatch saved progress")
        if execution.guest_result is None:
            raise CorpusStorageError("cannot save batch evidence without a guest result")
        if starry_elf.is_symlink() or not starry_elf.is_file():
            raise FileNotFoundError(f"active Starry ELF is missing: {starry_elf}")
        evidence_root = job.path / BATCH_EVIDENCE_NAME
        destination = evidence_root / f"{batch_index:06d}"
        if destination.exists():
            saved = self.load_batch_evidence(job_id, batch_index)
            assert saved is not None
            return saved
        temporary = Path(
            tempfile.mkdtemp(
                prefix=f".{batch_index:06d}.tmp-",
                dir=evidence_root,
            )
        )
        try:
            _copy_file(execution.ops_path, temporary / "pipe.ops")
            _copy_file(execution.trace_path, temporary / "linux.trace")
            _copy_file(execution.host_oracle_path, temporary / "pipe-linux-oracle")
            _copy_file(starry_elf, temporary / "starryos")
            _write_bytes(
                temporary / "guest.log",
                execution.guest_result.log.encode("utf-8"),
            )
            profraws_dir = temporary / "profraws"
            profraws_dir.mkdir()
            profraw_metadata = []
            for index, source in enumerate(execution.guest_result.profraw_paths):
                name = f"{index:04d}-{source.name}"
                copied = profraws_dir / name
                _copy_file(source, copied)
                profraw_metadata.append(
                    {
                        "name": name,
                        "sha256": _sha256_file(copied),
                        "size": copied.stat().st_size,
                    }
                )
            result = {
                "schema_version": 1,
                "batch_index": batch_index,
                "result_category": execution.guest_result.category.value,
                "returncode": execution.guest_result.returncode,
                "ops_sha256": _sha256_file(temporary / "pipe.ops"),
                "trace_sha256": _sha256_file(temporary / "linux.trace"),
                "guest_log_sha256": _sha256_file(temporary / "guest.log"),
                "host_oracle_sha256": _sha256_file(
                    temporary / "pipe-linux-oracle"
                ),
                "starry_elf_sha256": _sha256_file(temporary / "starryos"),
                "profraws": profraw_metadata,
            }
            _write_json(temporary / "result.json", result)
            _sync_directory(profraws_dir)
            _sync_directory(temporary)
            os.replace(temporary, destination)
            _sync_directory(evidence_root)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        self.load_job(job_id)
        saved = self.load_batch_evidence(job_id, batch_index)
        assert saved is not None
        return saved

    def load_batch_evidence(
        self,
        job_id: str,
        batch_index: int,
    ) -> Optional[ImportBatchEvidence]:
        job = self.load_job(job_id)
        if not 0 <= batch_index < len(job.metadata["batches"]):
            raise CorpusStorageError("import batch index is outside the job")
        path = job.path / BATCH_EVIDENCE_NAME / f"{batch_index:06d}"
        if not path.exists():
            return None
        result = read_json(path / "result.json")
        guest_log = (path / "guest.log").read_text(encoding="utf-8")
        profraw_paths = tuple(
            path / "profraws" / item["name"] for item in result["profraws"]
        )
        category = GuestResultCategory(result["result_category"])
        guest_result = classify_guest_execution(
            guest_log,
            result["returncode"],
            profraw_paths,
            timed_out=category == GuestResultCategory.TIMEOUT,
        )
        if guest_result.category != category:
            raise CorpusValidationError(path, "saved guest result category mismatch")
        return ImportBatchEvidence(
            path,
            path / "pipe.ops",
            path / "linux.trace",
            path / "pipe-linux-oracle",
            path / "starryos",
            guest_result,
        )

    def finish(
        self,
        job_id: str,
        *,
        result_category: str,
        failure_reason: Optional[str] = None,
        duration_seconds: float = 0.0,
    ) -> ImportJob:
        job = self.load_job(job_id)
        if job.metadata["state"] in {"completed", "failed"}:
            return job
        if not isinstance(result_category, str) or not result_category:
            raise ValueError("terminal result category must be non-empty")
        metadata = _copy_metadata(job.metadata)
        metadata["state"] = "failed" if failure_reason is not None else "completed"
        metadata["result_category"] = result_category
        metadata["failure_reason"] = failure_reason
        _add_duration(metadata, duration_seconds)
        return self._save_metadata(job, metadata)

    def mark_run_recorded(self, job_id: str) -> ImportJob:
        job = self.load_job(job_id)
        if job.metadata["state"] != "completed":
            raise CorpusStorageError("only completed imports can record a run")
        if job.metadata["run_recorded"]:
            return job
        metadata = _copy_metadata(job.metadata)
        metadata["run_recorded"] = True
        return self._save_metadata(job, metadata)

    def canonical_input_path(self, job: ImportJob, digest: str) -> Path:
        if digest not in {item["digest"] for item in job.metadata["canonical_inputs"]}:
            raise CorpusStorageError(f"import job has no canonical input {digest}")
        return job.path / INPUTS_NAME / f"{digest}.ops"

    def source_evidence_paths(
        self,
        job: ImportJob,
        digest: str,
    ) -> Tuple[Tuple[Path, Path, Dict[str, Any]], ...]:
        canonical = next(
            (item for item in job.metadata["canonical_inputs"] if item["digest"] == digest),
            None,
        )
        if canonical is None:
            raise CorpusStorageError(f"import job has no canonical input {digest}")
        sources = {item["evidence_id"]: item for item in job.metadata["sources"]}
        return tuple(
            (
                job.path / SOURCES_NAME / f"{evidence_id}.syz",
                job.path / CONVERSIONS_NAME / f"{evidence_id}.json",
                sources[evidence_id],
            )
            for evidence_id in canonical["source_evidence_ids"]
        )

    def provenance(self, job: ImportJob, digest: str) -> CorpusProvenance:
        """Build deduplicated typed provenance for one canonical import input."""
        sources = tuple(
            ExternalSource(
                metadata["program_sha256"],
                job.metadata["syzkaller_revision"],
                job.metadata["importer_version"],
                metadata["conversion_log_sha256"],
            )
            for _source_path, _conversion_path, metadata in self.source_evidence_paths(
                job,
                digest,
            )
        )
        return CorpusProvenance.imported(sources)

    def _save_metadata(
        self,
        job: ImportJob,
        metadata: Dict[str, Any],
    ) -> ImportJob:
        metadata["updated_at"] = _now()
        validate_job_metadata(metadata, job.path)
        _atomic_write_json(job.path / METADATA_NAME, metadata)
        return self.load_job(job.job_id)


def _prepare_sources(
    reports: Sequence[Dict[str, object]],
    syzkaller_revision: str,
) -> Tuple[List[Dict[str, Any]], Dict[str, bytes], Dict[str, bytes]]:
    metadata = []
    raw_sources = {}
    conversion_logs = {}
    for index, report in enumerate(reports):
        evidence_id = f"{index:06d}"
        conversion = conversion_log_bytes(report, syzkaller_revision)
        conversion_digest = sha256_bytes(conversion)
        if conversion_digest != report.get("conversion_log_sha256"):
            raise CorpusStorageError("classification conversion log digest mismatch")
        conversion_logs[evidence_id] = conversion
        program_digest = report.get("program_sha256")
        program_size = report.get("program_size")
        if program_digest is not None:
            source_path = Path(str(report["path"]))
            if source_path.is_symlink() or not source_path.is_file():
                raise CorpusStorageError(f"classified input is no longer regular: {source_path}")
            encoded = source_path.read_bytes()
            if sha256_bytes(encoded) != program_digest or len(encoded) != program_size:
                raise CorpusStorageError(f"classified input changed before persistence: {source_path}")
            raw_sources[evidence_id] = encoded
        metadata.append(
            {
                "evidence_id": evidence_id,
                "path": str(report["path"]),
                "status": report["status"],
                "program_sha256": program_digest,
                "program_size": program_size,
                "conversion_log_sha256": conversion_digest,
                "conversion_log_size": len(conversion),
                "canonical_digest": report["canonical_digest"],
                "rejection_category": report["rejection_category"],
                "rejection_detail": report["rejection_detail"],
            }
        )
    return metadata, raw_sources, conversion_logs


def _prepare_canonical_inputs(
    reports: Sequence[Dict[str, object]],
    sources: Sequence[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, bytes]]:
    source_ids_by_digest: Dict[str, List[str]] = {}
    canonical_ops: Dict[str, bytes] = {}
    for report, source in zip(reports, sources):
        if report["status"] != "accepted":
            continue
        digest = str(report["canonical_digest"])
        encoded = str(report["canonical_pipe_ops"]).encode("utf-8")
        if sha256_bytes(encoded) != digest:
            raise CorpusStorageError("accepted canonical input digest mismatch")
        previous = canonical_ops.setdefault(digest, encoded)
        if previous != encoded:
            raise CorpusStorageError("canonical digest collision in import inputs")
        source_ids_by_digest.setdefault(digest, []).append(source["evidence_id"])
    inputs = [
        {
            "digest": digest,
            "source_evidence_ids": sorted(source_ids_by_digest[digest]),
            "host_status": "pending",
            "host_trace_sha256": None,
        }
        for digest in sorted(canonical_ops)
    ]
    return inputs, canonical_ops


def _validate_job_id(job_id: str) -> None:
    if not isinstance(job_id, str) or not JOB_ID_PATTERN.fullmatch(job_id):
        raise ValueError(f"invalid import job id: {job_id}")


def _validate_settings(host_repetitions: int, batch_size: int, max_qemu: int) -> None:
    for name, value in (
        ("host_repetitions", host_repetitions),
        ("batch_size", batch_size),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"{name} must be positive")
    if not isinstance(max_qemu, int) or isinstance(max_qemu, bool) or max_qemu < 0:
        raise ValueError("max_qemu must be nonnegative")


def _copy_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(json.dumps(metadata))


def _add_duration(metadata: Dict[str, Any], seconds: float) -> None:
    if (
        not isinstance(seconds, (int, float))
        or isinstance(seconds, bool)
        or seconds < 0
    ):
        raise ValueError("duration must be nonnegative")
    metadata["duration_seconds"] = round(metadata["duration_seconds"] + seconds, 6)


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_bytes(path: Path, encoded: bytes) -> None:
    with path.open("wb") as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())


def _copy_file(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise FileNotFoundError(f"evidence source is not a regular file: {source}")
    with source.open("rb") as input_file, destination.open("wb") as output:
        shutil.copyfileobj(input_file, output)
        output.flush()
        os.fsync(output.fileno())
    shutil.copymode(source, destination)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, metadata: Dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as output:
        json.dump(metadata, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def _atomic_write_json(path: Path, metadata: Dict[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(metadata, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = ["ImportBatchEvidence", "ImportJob", "ImportStore"]
