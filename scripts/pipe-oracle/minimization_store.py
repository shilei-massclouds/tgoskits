"""Atomic persistent storage for resumable minimization jobs."""

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from common import CORPUS_DIR
from corpus import CorpusProvenance
from coverage import TARGET_SET_ID
from corpus_errors import CorpusStorageError, CorpusValidationError
from fingerprint import MismatchFingerprint
from minimization import (
    MinimizationItem,
    MinimizationSession,
    PredicateDecision,
    ScheduledCandidate,
)
from minimization_schema import (
    BEST_NAME,
    EVIDENCE_NAME,
    HOST_ORACLE_NAME,
    INPUTS_NAME,
    JOB_ID_PATTERN,
    job_target_set_id,
    METADATA_NAME,
    MINIMIZATION_JOBS_NAME,
    MINIMIZATION_SCHEMA_VERSION,
    STARRY_ELF_NAME,
    TEMP_PATTERN,
    read_json,
    sha256_file,
    validate_job_files,
    validate_job_metadata,
)
from reducer import OperationOrigin, ReductionInput, StructuredReducer
from scenario import parse_document, serialize_document


@dataclass(frozen=True)
class MinimizationJob:
    job_id: str
    path: Path
    metadata: Dict[str, Any]


@dataclass(frozen=True)
class MinimizationEvidence:
    ops_path: Path
    trace_path: Path
    guest_log: str
    profraw_paths: Tuple[Path, ...]
    result_category: str
    covered_regions: Tuple[str, ...] = ()
    fingerprint: Optional[MismatchFingerprint] = None


class MinimizationStore:
    """Own minimization jobs independently of source artifacts and corpus history."""

    def __init__(self, workspace: Path, generator_version: str):
        self.workspace = workspace.resolve()
        self.generator_version = generator_version
        self.root = self.workspace / CORPUS_DIR
        self.jobs_dir = self.root / MINIMIZATION_JOBS_NAME
        self.failures_dir = self.root / "failures"

    def prepare(self) -> None:
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.failures_dir.mkdir(parents=True, exist_ok=True)

    def create_job(
        self,
        job_id: str,
        *,
        kind: str,
        source: Dict[str, str],
        items: Tuple[MinimizationItem, ...],
        starry_elf: Path,
        host_oracle: Path,
        max_qemu: int,
        expected_fingerprint: Optional[MismatchFingerprint],
    ) -> MinimizationJob:
        self.prepare()
        if not isinstance(job_id, str) or not JOB_ID_PATTERN.fullmatch(job_id):
            raise ValueError(f"invalid minimization job id: {job_id}")
        if kind not in {"coverage", "mismatch"}:
            raise ValueError(f"unsupported minimization kind: {kind}")
        if not items:
            raise ValueError("minimization requires items")
        if kind == "mismatch" and len(items) != 1:
            raise ValueError("mismatch minimization requires one item")
        if not isinstance(max_qemu, int) or isinstance(max_qemu, bool) or max_qemu < 0:
            raise ValueError("max_qemu must be nonnegative")
        if not starry_elf.is_file() or not host_oracle.is_file():
            raise FileNotFoundError("minimization requires fixed Starry and host ELFs")
        ordered_items = tuple(sorted(items, key=lambda item: item.original_digest))
        destination = self.jobs_dir / job_id
        if destination.exists():
            raise CorpusStorageError(f"minimization job already exists: {destination}")
        now = _now()
        metadata = {
            "schema_version": MINIMIZATION_SCHEMA_VERSION,
            "generator_version": self.generator_version,
            "target_set_id": TARGET_SET_ID,
            "job_id": job_id,
            "kind": kind,
            "source": dict(source),
            "state": "validating",
            "completion": None,
            "run_recorded": False,
            "created_at": now,
            "updated_at": now,
            "duration_seconds": 0.0,
            "max_candidate_qemu": max_qemu,
            "candidate_qemu": 0,
            "validation_qemu": 0,
            "proof_qemu": 0,
            "starry_elf_sha256": sha256_file(starry_elf),
            "host_oracle_sha256": sha256_file(host_oracle),
            "expected_fingerprint": (
                expected_fingerprint.as_metadata()
                if expected_fingerprint is not None
                else None
            ),
            "items": [
                self._item_metadata(index, item)
                for index, item in enumerate(ordered_items)
            ],
            "schedule_cursor": 0,
            "attempts": [],
            "proofs": [],
            "validation": None,
            "failure_reason": None,
        }
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{job_id}.tmp-", dir=self.jobs_dir)
        )
        try:
            (temporary / INPUTS_NAME).mkdir()
            (temporary / BEST_NAME).mkdir()
            (temporary / EVIDENCE_NAME).mkdir()
            _copy_file(starry_elf, temporary / STARRY_ELF_NAME)
            _copy_file(host_oracle, temporary / HOST_ORACLE_NAME)
            for index, item in enumerate(ordered_items):
                encoded = serialize_document(item.reduction_input.document).encode("utf-8")
                _write_bytes(
                    temporary / INPUTS_NAME / f"{item.original_digest}.ops",
                    encoded,
                )
                self._save_best_checkpoint(temporary, index, item.reduction_input)
            _write_json(temporary / METADATA_NAME, metadata)
            _sync_directory(temporary)
            os.replace(temporary, destination)
            _sync_directory(self.jobs_dir)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return self.load_job(job_id)

    def load_job(self, job_id: str) -> MinimizationJob:
        self.prepare()
        if not isinstance(job_id, str) or not JOB_ID_PATTERN.fullmatch(job_id):
            raise ValueError(f"invalid minimization job id: {job_id}")
        path = self.jobs_dir / job_id
        if path.is_symlink() or not path.is_dir():
            raise CorpusValidationError(path, "expected a minimization job directory")
        metadata = read_json(path / METADATA_NAME)
        validate_job_metadata(metadata, path, self.generator_version)
        validate_job_files(path, metadata)
        return MinimizationJob(job_id, path, metadata)

    def load_failed_job(self, job_id: str) -> Optional[MinimizationJob]:
        self.prepare()
        if not isinstance(job_id, str) or not JOB_ID_PATTERN.fullmatch(job_id):
            raise ValueError(f"invalid minimization job id: {job_id}")
        path = self.failures_dir / f"minimization-{job_id}"
        if not path.exists() and not path.is_symlink():
            return None
        if path.is_symlink() or not path.is_dir():
            raise CorpusValidationError(path, "expected a failed minimization directory")
        metadata = read_json(path / METADATA_NAME)
        validate_job_metadata(
            metadata,
            path,
            self.generator_version,
            expected_job_id=job_id,
        )
        if metadata["state"] not in {"stale", "unstable"}:
            raise CorpusValidationError(path, "failed minimization has an active state")
        validate_job_files(path, metadata)
        return MinimizationJob(job_id, path, metadata)

    def load_resumable_jobs(self) -> List[MinimizationJob]:
        self.prepare()
        jobs = []
        for path in sorted(self.jobs_dir.iterdir(), key=lambda item: item.name):
            if TEMP_PATTERN.fullmatch(path.name):
                continue
            job = self.load_job(path.name)
            if job.metadata["state"] != "completed" or not job.metadata["run_recorded"]:
                jobs.append(job)
        return jobs

    def load_items(self, job: MinimizationJob) -> Tuple[MinimizationItem, ...]:
        items = []
        for item in job.metadata["items"]:
            checkpoint = (
                job.path
                / BEST_NAME
                / f"{item['index']:04d}"
                / item["best_digest"]
            )
            document = parse_document((checkpoint / "pipe.ops").read_bytes())
            origins_metadata = read_json(checkpoint / "origins.json")["origins"]
            reduction_input = ReductionInput(
                document,
                tuple(
                    tuple(OperationOrigin(*origin) for origin in scenario_origins)
                    for scenario_origins in origins_metadata
                ),
            )
            critical = item["critical_origin"]
            items.append(
                MinimizationItem(
                    item["original_digest"],
                    reduction_input,
                    frozenset(item["responsibility_regions"]),
                    OperationOrigin(*critical) if critical is not None else None,
                    CorpusProvenance(
                        item["origin"]["source"],
                        item["origin"]["parent_digest"],
                        item["origin"]["donor_digest"],
                        item["origin"]["mutation_type"],
                    ),
                )
            )
        return tuple(items)

    def restore_session(self, job: MinimizationJob) -> MinimizationSession:
        current = self.load_job(job.job_id)
        items = self.load_items(current)
        session = MinimizationSession(
            current.metadata["kind"],
            items,
            max_qemu=current.metadata["max_candidate_qemu"],
        )
        session.candidate_qemu = current.metadata["candidate_qemu"]
        session.schedule_cursor = current.metadata["schedule_cursor"]
        session.budget_limited = (
            session.candidate_qemu >= session.max_qemu
            and current.metadata["state"] != "completed"
        )
        session.reducers = tuple(
            StructuredReducer.restore(item.reduction_input, metadata["reducer"])
            for item, metadata in zip(items, current.metadata["items"])
        )
        return session

    def record_validation(
        self,
        job: MinimizationJob,
        *,
        result_category: str,
        satisfied: bool,
        evidence_digest: str,
        duration_seconds: float,
        qemu_counted: bool = True,
    ) -> MinimizationJob:
        current = self.load_job(job.job_id)
        metadata = current.metadata
        if metadata["state"] != "validating" or metadata["validation"] is not None:
            raise CorpusStorageError("minimization job is not accepting validation")
        metadata["validation"] = {
            "result_category": result_category,
            "satisfied": satisfied,
            "evidence_digest": evidence_digest,
        }
        metadata["validation_qemu"] = 1 if qemu_counted else 0
        if satisfied:
            metadata["state"] = "reducing"
        _add_duration(metadata, duration_seconds)
        return self.save_metadata(current, metadata)

    def record_candidate(
        self,
        job: MinimizationJob,
        session: MinimizationSession,
        scheduled: ScheduledCandidate,
        *,
        decision: PredicateDecision,
        result_category: str,
        covered_regions: Tuple[str, ...],
        fingerprint: Optional[MismatchFingerprint],
        evidence_digest: Optional[str],
        duration_seconds: float,
    ) -> MinimizationJob:
        current = self.load_job(job.job_id)
        metadata = current.metadata
        if metadata["state"] != "reducing":
            raise CorpusStorageError("minimization job is not reducing")
        if session.candidate_qemu != metadata["candidate_qemu"] + 1:
            raise CorpusStorageError("candidate QEMU count did not advance exactly once")
        reducer = session.reducers[scheduled.item_index]
        if decision == PredicateDecision.ACCEPT:
            self.save_best_checkpoint(current, scheduled.item_index, reducer.best)
        self._sync_session_metadata(metadata, session)
        metadata["attempts"].append(
            {
                "sequence": len(metadata["attempts"]) + 1,
                "item_index": scheduled.item_index,
                "candidate_digest": scheduled.candidate.digest,
                "transform": scheduled.candidate.transform,
                "result_category": result_category,
                "decision": decision.value,
                "region_summary": sorted(set(covered_regions)),
                "fingerprint": (
                    fingerprint.as_metadata() if fingerprint is not None else None
                ),
                "evidence_digest": evidence_digest,
            }
        )
        _add_duration(metadata, duration_seconds)
        saved = self.save_metadata(current, metadata)
        if decision == PredicateDecision.ACCEPT:
            self.prune_best_evidence(saved)
        return saved

    def begin_final_proof(
        self,
        job: MinimizationJob,
        session: MinimizationSession,
    ) -> MinimizationJob:
        current = self.load_job(job.job_id)
        metadata = current.metadata
        if metadata["state"] == "final-proof":
            return current
        if metadata["state"] != "reducing":
            raise CorpusStorageError("minimization job cannot start final proof")
        self._sync_session_metadata(metadata, session)
        metadata["state"] = "final-proof"
        return self.save_metadata(current, metadata)

    def record_proof(
        self,
        job: MinimizationJob,
        *,
        result_category: str,
        decision: PredicateDecision,
        satisfied: bool,
        evidence_digest: str,
        duration_seconds: float,
        qemu_counted: bool = True,
    ) -> MinimizationJob:
        current = self.load_job(job.job_id)
        metadata = current.metadata
        if metadata["state"] != "final-proof" or len(metadata["proofs"]) >= 2:
            raise CorpusStorageError("minimization job is not accepting proof evidence")
        index = len(metadata["proofs"]) + 1
        metadata["proofs"].append(
            {
                "index": index,
                "result_category": result_category,
                "decision": decision.value,
                "satisfied": satisfied,
                "evidence_digest": evidence_digest,
            }
        )
        metadata["proof_qemu"] += 1 if qemu_counted else 0
        _add_duration(metadata, duration_seconds)
        return self.save_metadata(current, metadata)

    def complete(self, job: MinimizationJob, completion: str) -> MinimizationJob:
        if completion not in {"minimized", "already-minimal", "budget-limited"}:
            raise ValueError("invalid minimization completion mode")
        current = self.load_job(job.job_id)
        metadata = current.metadata
        if metadata["state"] != "final-proof" or len(metadata["proofs"]) != 2:
            raise CorpusStorageError("minimization final proof is incomplete")
        if not all(proof["satisfied"] for proof in metadata["proofs"]):
            raise CorpusStorageError("minimization final proof did not satisfy predicate")
        metadata["state"] = "completed"
        metadata["completion"] = completion
        return self.save_metadata(current, metadata)

    def prune_best_evidence(self, job: MinimizationJob) -> None:
        current_labels = {
            f"best-{item['index']:04d}-{item['best_digest']}"
            for item in job.metadata["items"]
            if item["best_digest"] != item["original_digest"]
        }
        evidence_dir = job.path / EVIDENCE_NAME
        for path in evidence_dir.iterdir():
            if path.name.startswith("best-") and path.name not in current_labels:
                if path.is_symlink() or not path.is_dir():
                    raise CorpusValidationError(path, "invalid best evidence")
                shutil.rmtree(path)
        _sync_directory(evidence_dir)

    def mark_run_recorded(self, job: MinimizationJob) -> MinimizationJob:
        current = self.load_job(job.job_id)
        if current.metadata["state"] != "completed":
            raise CorpusStorageError("unfinished minimization has no final run")
        metadata = current.metadata
        metadata["run_recorded"] = True
        return self.save_metadata(current, metadata)

    def save_evidence(
        self,
        job: MinimizationJob,
        label: str,
        evidence: MinimizationEvidence,
    ) -> str:
        if not isinstance(label, str) or not JOB_ID_PATTERN.fullmatch(label):
            raise ValueError(f"invalid minimization evidence label: {label}")
        destination = job.path / EVIDENCE_NAME / label
        if destination.exists():
            result_path = destination / "result.json"
            return sha256_file(result_path)
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{label}.tmp-", dir=job.path / EVIDENCE_NAME)
        )
        try:
            _copy_file(evidence.ops_path, temporary / "pipe.ops")
            _copy_file(evidence.trace_path, temporary / "linux.trace")
            _write_bytes(temporary / "guest.log", evidence.guest_log.encode("utf-8"))
            profraws_dir = temporary / "profraws"
            profraws_dir.mkdir()
            profraw_metadata = []
            for index, profraw in enumerate(evidence.profraw_paths):
                name = f"{index:04d}-{profraw.name}"
                copied = profraws_dir / name
                _copy_file(profraw, copied)
                profraw_metadata.append(
                    {"name": name, "sha256": sha256_file(copied), "size": copied.stat().st_size}
                )
            result = {
                "schema_version": job.metadata["schema_version"],
                "starry_elf_sha256": job.metadata["starry_elf_sha256"],
                "result_category": evidence.result_category,
                "covered_regions": sorted(set(evidence.covered_regions)),
                "fingerprint": (
                    evidence.fingerprint.as_metadata()
                    if evidence.fingerprint is not None
                    else None
                ),
                "ops_sha256": sha256_file(temporary / "pipe.ops"),
                "trace_sha256": sha256_file(temporary / "linux.trace"),
                "guest_log_sha256": sha256_file(temporary / "guest.log"),
                "profraws": profraw_metadata,
            }
            if job.metadata["schema_version"] == MINIMIZATION_SCHEMA_VERSION:
                result["target_set_id"] = job_target_set_id(job.metadata)
            _write_json(temporary / "result.json", result)
            _sync_directory(profraws_dir)
            _sync_directory(temporary)
            os.replace(temporary, destination)
            _sync_directory(destination.parent)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return sha256_file(destination / "result.json")

    def save_best_checkpoint(
        self,
        job: MinimizationJob,
        item_index: int,
        reduction_input: ReductionInput,
    ) -> Path:
        return self._save_best_checkpoint(job.path, item_index, reduction_input)

    def mark_stale_if_elf_changed(
        self,
        job: MinimizationJob,
        active_starry_elf: Path,
    ) -> Optional[Path]:
        actual = sha256_file(active_starry_elf) if active_starry_elf.is_file() else "missing"
        expected = job.metadata["starry_elf_sha256"]
        if actual == expected:
            return None
        return self._move_to_failure(
            job,
            "stale",
            f"Starry ELF changed: expected {expected}, got {actual}",
        )

    def mark_unstable(self, job: MinimizationJob, reason: str) -> Path:
        return self._move_to_failure(job, "unstable", reason)

    def finish_terminal_move(self, job: MinimizationJob) -> Path:
        current = self.load_job(job.job_id)
        state = current.metadata["state"]
        reason = current.metadata["failure_reason"]
        if state not in {"stale", "unstable"} or not reason:
            raise CorpusStorageError("minimization job is not terminal")
        return self._move_to_failure(current, state, reason)

    def save_metadata(self, job: MinimizationJob, metadata: Dict[str, Any]) -> MinimizationJob:
        metadata["updated_at"] = _now()
        _atomic_write_json(job.path / METADATA_NAME, metadata)
        return self.load_job(job.job_id)

    def _move_to_failure(
        self,
        job: MinimizationJob,
        state: str,
        reason: str,
    ) -> Path:
        if state not in {"stale", "unstable"} or not reason:
            raise ValueError("invalid minimization failure")
        current = self.load_job(job.job_id)
        metadata = current.metadata
        metadata["state"] = state
        metadata["failure_reason"] = reason
        metadata["updated_at"] = _now()
        _atomic_write_json(current.path / METADATA_NAME, metadata)
        destination = self.failures_dir / f"minimization-{job.job_id}"
        if destination.exists():
            raise CorpusStorageError(f"minimization failure exists: {destination}")
        os.replace(current.path, destination)
        _sync_directory(self.jobs_dir)
        _sync_directory(self.failures_dir)
        return destination

    def _item_metadata(self, index: int, item: MinimizationItem) -> Dict[str, Any]:
        encoded = serialize_document(item.reduction_input.document).encode("utf-8")
        reducer = __import__("reducer").StructuredReducer(
            item.reduction_input,
            item.critical_origin,
        )
        return {
            "index": index,
            "original_digest": item.original_digest,
            "best_digest": item.original_digest,
            "original_size": len(encoded),
            "best_size": len(encoded),
            "responsibility_regions": sorted(item.responsibility_regions),
            "critical_origin": (
                [item.critical_origin.scenario_index, item.critical_origin.operation_index]
                if item.critical_origin is not None
                else None
            ),
            "reducer": reducer.snapshot(),
            "origin": item.provenance.as_metadata(),
        }

    def _sync_session_metadata(
        self,
        metadata: Dict[str, Any],
        session: MinimizationSession,
    ) -> None:
        metadata["candidate_qemu"] = session.candidate_qemu
        metadata["schedule_cursor"] = session.schedule_cursor
        for item_metadata, reducer in zip(metadata["items"], session.reducers):
            encoded = serialize_document(reducer.best.document).encode("utf-8")
            item_metadata["best_digest"] = __import__("hashlib").sha256(encoded).hexdigest()
            item_metadata["best_size"] = len(encoded)
            item_metadata["reducer"] = reducer.snapshot()

    def _save_best_checkpoint(
        self,
        job_path: Path,
        index: int,
        reduction_input: ReductionInput,
    ) -> Path:
        encoded = serialize_document(reduction_input.document).encode("utf-8")
        digest = __import__("hashlib").sha256(encoded).hexdigest()
        item_dir = job_path / BEST_NAME / f"{index:04d}"
        item_dir.mkdir(exist_ok=True)
        destination = item_dir / digest
        if destination.exists():
            return destination
        temporary = Path(tempfile.mkdtemp(prefix=f".{digest}.tmp-", dir=item_dir))
        try:
            _write_bytes(temporary / "pipe.ops", encoded)
            _write_json(
                temporary / "origins.json",
                {
                    "origins": [
                        [
                            [origin.scenario_index, origin.operation_index]
                            for origin in scenario_origins
                        ]
                        for scenario_origins in reduction_input.origins
                    ]
                },
            )
            _sync_directory(temporary)
            os.replace(temporary, destination)
            _sync_directory(item_dir)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return destination


def _write_json(path: Path, metadata: Dict[str, Any]) -> None:
    encoded = json.dumps(metadata, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
    _write_bytes(path, encoded)


def _atomic_write_json(path: Path, metadata: Dict[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(metadata, output, indent=2, ensure_ascii=False, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _write_bytes(path: Path, data: bytes) -> None:
    with path.open("wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def _copy_file(source: Path, destination: Path) -> None:
    with source.open("rb") as input_file, destination.open("wb") as output:
        shutil.copyfileobj(input_file, output, length=1024 * 1024)
        os.fchmod(output.fileno(), source.stat().st_mode & 0o777)
        output.flush()
        os.fsync(output.fileno())


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _add_duration(metadata: Dict[str, Any], duration_seconds: float) -> None:
    if (
        not isinstance(duration_seconds, (int, float))
        or isinstance(duration_seconds, bool)
        or duration_seconds < 0
    ):
        raise ValueError("minimization duration must be nonnegative")
    metadata["duration_seconds"] = round(
        metadata["duration_seconds"] + duration_seconds,
        6,
    )


__all__ = ["MinimizationEvidence", "MinimizationJob", "MinimizationStore"]
