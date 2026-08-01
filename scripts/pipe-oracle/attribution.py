"""Persistent exact coverage-attribution jobs and representative selection."""

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from common import CORPUS_DIR
from coverage import TARGET_SET_ID
from corpus import CorpusProvenance, CorpusStorageError, CorpusValidationError
from generator import GENERATOR_VERSION
from scenario import ScenarioDocument, parse_document, serialize_document
from attribution_schema import (
    ATTRIBUTION_JOBS_NAME,
    ATTRIBUTION_SCHEMA_VERSION,
    FD_ATTRIBUTION_SCHEMA_VERSION,
    POLL_ATTRIBUTION_SCHEMA_VERSION,
    VECTOR_ATTRIBUTION_SCHEMA_VERSION,
    ELFS_NAME,
    FAILURES_NAME,
    HOST_ORACLE_NAME,
    INPUTS_NAME,
    JOB_ID_PATTERN,
    JOB_TEMP_PATTERN,
    METADATA_NAME,
    METADATA_TEMP_PATTERN,
    REPLAYS_NAME,
    batch_label,
    entry_label,
    is_digest,
    job_target_set_id,
    read_json,
    representative_label,
    sha256_file,
    validate_job_files,
    validate_job_metadata,
    validate_replay,
)


class AttributionInstability(CorpusStorageError):
    """A productive batch could not be attributed deterministically."""


@dataclass(frozen=True)
class AttributionInput:
    digest: str
    encoded: bytes
    provenance: CorpusProvenance

    @classmethod
    def from_document(
        cls,
        document: ScenarioDocument,
        provenance: CorpusProvenance,
    ) -> "AttributionInput":
        encoded = serialize_document(document).encode("utf-8")
        return cls(hashlib.sha256(encoded).hexdigest(), encoded, provenance)

    @property
    def document(self) -> ScenarioDocument:
        return parse_document(self.encoded)


@dataclass(frozen=True)
class ReplayEvidence:
    ops_path: Path
    trace_path: Path
    guest_log: str
    profraw_paths: Tuple[Path, ...]
    starry_elf_path: Path
    host_oracle_path: Path
    covered_regions: FrozenSet[str]
    result_category: str


@dataclass(frozen=True)
class AttributionJob:
    job_id: str
    path: Path
    metadata: Dict[str, Any]


def select_representatives(
    entry_regions: Dict[str, Set[str]],
    target_regions: Set[str],
) -> Tuple[str, ...]:
    """Choose a deterministic, inclusion-minimal cover of target regions."""
    target = set(target_regions)
    reproduced = set().union(*entry_regions.values()) if entry_regions else set()
    missing = target - reproduced
    if missing:
        raise AttributionInstability(
            "target regions were not reproduced: " + ", ".join(sorted(missing))
        )

    uncovered = set(target)
    selected: List[str] = []
    while uncovered:
        candidates = [
            (-(len(regions & uncovered)), digest)
            for digest, regions in entry_regions.items()
            if regions & uncovered
        ]
        if not candidates:
            raise AttributionInstability(
                "target regions were not reproduced: "
                + ", ".join(sorted(uncovered))
            )
        _negative_gain, digest = min(candidates)
        selected.append(digest)
        uncovered -= entry_regions[digest]

    for digest in reversed(tuple(selected)):
        remaining = [item for item in selected if item != digest]
        remaining_regions = (
            set().union(*(entry_regions[item] for item in remaining))
            if remaining
            else set()
        )
        if target <= remaining_regions:
            selected.remove(digest)
    return tuple(sorted(selected))


class AttributionStore:
    """Owns resumable attribution jobs and their replay evidence."""

    def __init__(
        self,
        workspace: Path,
        generator_version: str = GENERATOR_VERSION,
    ):
        self.workspace = workspace.resolve()
        self.generator_version = generator_version
        self.root = self.workspace / CORPUS_DIR
        self.jobs_dir = self.root / ATTRIBUTION_JOBS_NAME
        self.failures_dir = self.root / FAILURES_NAME

    def prepare(self) -> None:
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.failures_dir.mkdir(parents=True, exist_ok=True)

    def create_job(
        self,
        job_id: str,
        *,
        fuzz_seed: int,
        batch_index: int,
        entries: Tuple[AttributionInput, ...],
        baseline_regions: Set[str],
        target_regions: Set[str],
        initial_evidence: ReplayEvidence,
        duration_seconds: float,
    ) -> AttributionJob:
        self.prepare()
        _validate_job_id(job_id)
        ordered_entries = tuple(sorted(entries, key=lambda item: item.digest))
        _validate_inputs(ordered_entries)
        _validate_region_partition(
            baseline_regions,
            target_regions,
            set(initial_evidence.covered_regions),
        )
        destination = self.jobs_dir / job_id
        if destination.exists():
            raise CorpusStorageError(f"attribution job already exists: {destination}")

        now = _now()
        elf_digest = sha256_file(initial_evidence.starry_elf_path)
        metadata = {
            "schema_version": ATTRIBUTION_SCHEMA_VERSION,
            "generator_version": self.generator_version,
            "target_set_id": TARGET_SET_ID,
            "job_id": job_id,
            "state": "entry-replays",
            "run_recorded": False,
            "fuzz_seed": fuzz_seed,
            "batch_index": batch_index,
            "created_at": now,
            "updated_at": now,
            "duration_seconds": round(duration_seconds, 6),
            "attempt": 1,
            "starry_elf_sha256": elf_digest,
            "baseline_regions": sorted(baseline_regions),
            "target_regions": sorted(target_regions),
            "entries": [
                {
                    "digest": entry.digest,
                    "origin": entry.provenance.as_metadata(),
                }
                for entry in ordered_entries
            ],
            "completed_entry_digests": [],
            "entry_regions": {},
            "representative_digests": [],
            "representative_regions": [],
            "qemu_replays": 0,
            "elf_transitions": [],
            "failure_reason": None,
        }

        temporary = Path(
            tempfile.mkdtemp(prefix=f".{job_id}.tmp-", dir=self.jobs_dir)
        )
        try:
            inputs_dir = temporary / INPUTS_NAME
            inputs_dir.mkdir()
            for entry in ordered_entries:
                _write_bytes(inputs_dir / f"{entry.digest}.ops", entry.encoded)
            _copy_file(initial_evidence.host_oracle_path, temporary / HOST_ORACLE_NAME)
            (temporary / REPLAYS_NAME).mkdir()
            (temporary / ELFS_NAME).mkdir()
            self._save_replay_in_job(
                temporary,
                batch_label(1),
                initial_evidence,
            )
            _write_json(temporary / METADATA_NAME, metadata)
            _sync_directory(temporary)
            os.replace(temporary, destination)
            _sync_directory(self.jobs_dir)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return self.load_job(job_id)

    def load_job(self, job_id: str) -> AttributionJob:
        self.prepare()
        _validate_job_id(job_id)
        path = self.jobs_dir / job_id
        return self._load_job_path(path)

    def load_resumable_jobs(self) -> List[AttributionJob]:
        self.prepare()
        jobs = []
        for path in sorted(self.jobs_dir.iterdir(), key=lambda item: item.name):
            if JOB_TEMP_PATTERN.fullmatch(path.name):
                continue
            job = self._load_job_path(path)
            if job.metadata["state"] != "completed" or not job.metadata["run_recorded"]:
                jobs.append(job)
        return jobs

    def input_entries(self, job: AttributionJob) -> Tuple[AttributionInput, ...]:
        entries = []
        for item in job.metadata["entries"]:
            origin = item["origin"]
            provenance = CorpusProvenance.from_metadata(origin)
            encoded = (job.path / INPUTS_NAME / f"{item['digest']}.ops").read_bytes()
            entries.append(AttributionInput(item["digest"], encoded, provenance))
        return tuple(entries)

    def host_oracle_path(self, job: AttributionJob) -> Path:
        return job.path / HOST_ORACLE_NAME

    def record_entry_replay(
        self,
        job_id: str,
        digest: str,
        evidence: ReplayEvidence,
        *,
        duration_seconds: float,
    ) -> AttributionJob:
        job = self.load_job(job_id)
        metadata = job.metadata
        if metadata["state"] != "entry-replays":
            raise CorpusStorageError(
                f"job {job_id} is not accepting entry replays"
            )
        entry_digests = {item["digest"] for item in metadata["entries"]}
        if digest not in entry_digests:
            raise CorpusStorageError(f"job {job_id} has no input {digest}")
        if digest in metadata["completed_entry_digests"]:
            return job

        label = entry_label(metadata["attempt"], digest)
        self._save_replay_in_job(job.path, label, evidence)
        try:
            self._require_same_elf(metadata, evidence)
        except AttributionInstability:
            metadata["qemu_replays"] += 1
            _add_duration(metadata, duration_seconds)
            self._save_metadata(job.path, metadata)
            raise
        target = set(metadata["target_regions"])
        metadata["entry_regions"][digest] = sorted(
            set(evidence.covered_regions) & target
        )
        metadata["completed_entry_digests"] = sorted(
            set(metadata["completed_entry_digests"]) | {digest}
        )
        metadata["qemu_replays"] += 1
        _add_duration(metadata, duration_seconds)
        if set(metadata["completed_entry_digests"]) == entry_digests:
            mapping = {
                item_digest: set(regions)
                for item_digest, regions in metadata["entry_regions"].items()
            }
            try:
                metadata["representative_digests"] = list(
                    select_representatives(mapping, target)
                )
            except AttributionInstability:
                self._save_metadata(job.path, metadata)
                raise
            metadata["state"] = "representative-replay"
        self._save_metadata(job.path, metadata)
        return self.load_job(job_id)

    def record_representative_replay(
        self,
        job_id: str,
        evidence: ReplayEvidence,
        *,
        duration_seconds: float,
    ) -> AttributionJob:
        job = self.load_job(job_id)
        metadata = job.metadata
        if metadata["state"] != "representative-replay":
            raise CorpusStorageError(
                f"job {job_id} is not accepting a representative replay"
            )
        label = representative_label(
            metadata["attempt"],
            tuple(metadata["representative_digests"]),
        )
        self._save_replay_in_job(job.path, label, evidence)
        try:
            self._require_same_elf(metadata, evidence)
        except AttributionInstability:
            metadata["qemu_replays"] += 1
            _add_duration(metadata, duration_seconds)
            self._save_metadata(job.path, metadata)
            raise
        target = set(metadata["target_regions"])
        reproduced = set(evidence.covered_regions) & target
        missing = target - reproduced
        metadata["qemu_replays"] += 1
        _add_duration(metadata, duration_seconds)
        if missing:
            self._save_metadata(job.path, metadata)
            raise AttributionInstability(
                "representative replay missed target regions: "
                + ", ".join(sorted(missing))
            )
        metadata["representative_regions"] = sorted(reproduced)
        metadata["state"] = "completed"
        self._save_metadata(job.path, metadata)
        return self.load_job(job_id)

    def restart_for_elf(
        self,
        job_id: str,
        *,
        baseline_regions: Set[str],
        target_regions: Set[str],
        evidence: ReplayEvidence,
        duration_seconds: float,
    ) -> AttributionJob:
        job = self.load_job(job_id)
        metadata = job.metadata
        if metadata["state"] == "completed":
            raise CorpusStorageError(f"completed job {job_id} cannot restart")
        new_digest = sha256_file(evidence.starry_elf_path)
        previous_digest = metadata["starry_elf_sha256"]
        if new_digest == previous_digest:
            raise CorpusStorageError("ELF restart requires a different digest")
        _validate_region_partition(
            baseline_regions,
            target_regions,
            set(evidence.covered_regions),
            require_target=False,
        )

        next_attempt = metadata["attempt"] + 1
        self._save_replay_in_job(
            job.path,
            batch_label(next_attempt),
            evidence,
        )
        metadata["attempt"] = next_attempt
        metadata["starry_elf_sha256"] = new_digest
        metadata["baseline_regions"] = sorted(baseline_regions)
        metadata["target_regions"] = sorted(target_regions)
        metadata["completed_entry_digests"] = []
        metadata["entry_regions"] = {}
        metadata["representative_digests"] = []
        metadata["representative_regions"] = []
        metadata["state"] = "entry-replays" if target_regions else "completed"
        metadata["qemu_replays"] += 1
        metadata["elf_transitions"].append(
            {
                "previous_sha256": previous_digest,
                "restarted_sha256": new_digest,
                "observed_at": _now(),
            }
        )
        _add_duration(metadata, duration_seconds)
        self._save_metadata(job.path, metadata)
        return self.load_job(job_id)

    def fail_job(self, job_id: str, reason: str) -> Path:
        job = self.load_job(job_id)
        if not isinstance(reason, str) or not reason:
            raise ValueError("attribution failure reason must be non-empty")
        metadata = job.metadata
        metadata["state"] = "unstable"
        metadata["failure_reason"] = reason
        metadata["updated_at"] = _now()
        self._save_metadata(job.path, metadata)
        destination = self.failures_dir / f"attribution-{job_id}"
        if destination.exists():
            raise CorpusStorageError(
                f"attribution failure already exists: {destination}"
            )
        os.replace(job.path, destination)
        _sync_directory(self.jobs_dir)
        _sync_directory(self.failures_dir)
        return destination

    def mark_run_recorded(self, job_id: str) -> AttributionJob:
        job = self.load_job(job_id)
        if job.metadata["state"] != "completed":
            raise CorpusStorageError(f"unfinished job {job_id} has no final run")
        metadata = job.metadata
        metadata["run_recorded"] = True
        self._save_metadata(job.path, metadata)
        return self.load_job(job_id)

    def record_qemu_replay_attempt(
        self,
        job_id: str,
        *,
        duration_seconds: float,
    ) -> AttributionJob:
        job = self.load_job(job_id)
        metadata = job.metadata
        metadata["qemu_replays"] += 1
        _add_duration(metadata, duration_seconds)
        self._save_metadata(job.path, metadata)
        return self.load_job(job_id)

    def saved_entry_evidence(
        self,
        job: AttributionJob,
        digest: str,
    ) -> Optional[ReplayEvidence]:
        label = entry_label(job.metadata["attempt"], digest)
        return self._load_replay_evidence(job, label)

    def persist_entry_evidence(
        self,
        job: AttributionJob,
        digest: str,
        evidence: ReplayEvidence,
    ) -> Path:
        return self._save_replay_in_job(
            job.path,
            entry_label(job.metadata["attempt"], digest),
            evidence,
        )

    def saved_representative_evidence(
        self,
        job: AttributionJob,
    ) -> Optional[ReplayEvidence]:
        label = representative_label(
            job.metadata["attempt"],
            tuple(job.metadata["representative_digests"]),
        )
        return self._load_replay_evidence(job, label)

    def persist_representative_evidence(
        self,
        job: AttributionJob,
        evidence: ReplayEvidence,
    ) -> Path:
        label = representative_label(
            job.metadata["attempt"],
            tuple(job.metadata["representative_digests"]),
        )
        return self._save_replay_in_job(job.path, label, evidence)

    def persist_restart_evidence(
        self,
        job: AttributionJob,
        evidence: ReplayEvidence,
    ) -> Path:
        return self._save_replay_in_job(
            job.path,
            batch_label(job.metadata["attempt"] + 1),
            evidence,
        )

    def _load_job_path(self, path: Path) -> AttributionJob:
        if path.is_symlink() or not path.is_dir():
            raise CorpusValidationError(path, "expected an attribution job directory")
        if not JOB_ID_PATTERN.fullmatch(path.name):
            raise CorpusValidationError(path, "invalid attribution job id")
        expected_names = {
            METADATA_NAME,
            INPUTS_NAME,
            REPLAYS_NAME,
            ELFS_NAME,
            HOST_ORACLE_NAME,
        }
        names = {
            item.name
            for item in path.iterdir()
            if not METADATA_TEMP_PATTERN.fullmatch(item.name)
        }
        if names != expected_names:
            raise CorpusValidationError(
                path,
                f"attribution job files mismatch: {sorted(names)}",
            )
        metadata = read_json(path / METADATA_NAME)
        validate_job_metadata(metadata, path, self.generator_version)
        validate_job_files(path, metadata)
        return AttributionJob(path.name, path, metadata)

    def _save_replay_in_job(
        self,
        job_path: Path,
        label: str,
        evidence: ReplayEvidence,
    ) -> Path:
        replays_dir = job_path / REPLAYS_NAME
        destination = replays_dir / label
        if destination.exists():
            return destination
        elf_digest = sha256_file(evidence.starry_elf_path)
        self._ensure_elf(job_path, evidence.starry_elf_path, elf_digest)
        metadata_path = job_path / METADATA_NAME
        if metadata_path.exists():
            job_metadata = read_json(metadata_path)
            evidence_schema_version = job_metadata["schema_version"]
            target_set_id = job_target_set_id(job_metadata)
        else:
            evidence_schema_version = ATTRIBUTION_SCHEMA_VERSION
            target_set_id = TARGET_SET_ID
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{label}.tmp-", dir=replays_dir)
        )
        try:
            _copy_file(evidence.ops_path, temporary / "pipe.ops")
            _copy_file(evidence.trace_path, temporary / "linux.trace")
            _write_bytes(temporary / "guest.log", evidence.guest_log.encode("utf-8"))
            profraw_dir = temporary / "profraws"
            profraw_dir.mkdir()
            profraw_metadata = []
            for index, profraw in enumerate(evidence.profraw_paths):
                name = f"{index:04d}-{profraw.name}"
                destination_profraw = profraw_dir / name
                _copy_file(profraw, destination_profraw)
                profraw_metadata.append(
                    {
                        "name": name,
                        "sha256": sha256_file(destination_profraw),
                        "size": destination_profraw.stat().st_size,
                    }
                )
            coverage = {
                "schema_version": evidence_schema_version,
                "starry_elf_sha256": elf_digest,
                "covered_regions": sorted(evidence.covered_regions),
                "result_category": evidence.result_category,
                "ops_sha256": sha256_file(temporary / "pipe.ops"),
                "trace_sha256": sha256_file(temporary / "linux.trace"),
                "profraws": profraw_metadata,
            }
            if evidence_schema_version in (
                FD_ATTRIBUTION_SCHEMA_VERSION,
                VECTOR_ATTRIBUTION_SCHEMA_VERSION,
                POLL_ATTRIBUTION_SCHEMA_VERSION,
                ATTRIBUTION_SCHEMA_VERSION,
            ):
                coverage["target_set_id"] = target_set_id
            _write_json(temporary / "coverage.json", coverage)
            _sync_directory(profraw_dir)
            _sync_directory(temporary)
            os.replace(temporary, destination)
            _sync_directory(replays_dir)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return destination

    def _ensure_elf(self, job_path: Path, source: Path, digest: str) -> None:
        destination_dir = job_path / ELFS_NAME / digest
        destination = destination_dir / "starryos"
        if destination.exists():
            if sha256_file(destination) != digest:
                raise CorpusValidationError(destination, "saved Starry ELF is corrupt")
            return
        destination_dir.mkdir()
        try:
            _copy_file(source, destination)
            _sync_directory(destination_dir)
            _sync_directory(destination_dir.parent)
        except BaseException:
            shutil.rmtree(destination_dir, ignore_errors=True)
            raise

    def _load_replay_evidence(
        self,
        job: AttributionJob,
        label: str,
    ) -> Optional[ReplayEvidence]:
        replay = job.path / REPLAYS_NAME / label
        if not replay.exists():
            return None
        coverage = validate_replay(job.path, replay)
        elf_digest = coverage["starry_elf_sha256"]
        return ReplayEvidence(
            ops_path=replay / "pipe.ops",
            trace_path=replay / "linux.trace",
            guest_log=(replay / "guest.log").read_text(encoding="utf-8"),
            profraw_paths=tuple(
                replay / "profraws" / item["name"]
                for item in coverage["profraws"]
            ),
            starry_elf_path=job.path / ELFS_NAME / elf_digest / "starryos",
            host_oracle_path=job.path / HOST_ORACLE_NAME,
            covered_regions=frozenset(coverage["covered_regions"]),
            result_category=coverage["result_category"],
        )

    def _require_same_elf(
        self,
        metadata: Dict[str, Any],
        evidence: ReplayEvidence,
    ) -> None:
        actual = sha256_file(evidence.starry_elf_path)
        if actual != metadata["starry_elf_sha256"]:
            raise AttributionInstability(
                "Starry ELF changed during attribution: "
                f"expected {metadata['starry_elf_sha256']}, got {actual}"
            )

    def _save_metadata(self, job_path: Path, metadata: Dict[str, Any]) -> None:
        metadata["updated_at"] = _now()
        _atomic_write_json(job_path / METADATA_NAME, metadata)


def _validate_inputs(entries: Tuple[AttributionInput, ...]) -> None:
    if not entries:
        raise ValueError("attribution job requires at least one input")
    digests = []
    for entry in entries:
        if not is_digest(entry.digest):
            raise ValueError(f"invalid attribution input digest: {entry.digest}")
        canonical = serialize_document(parse_document(entry.encoded)).encode("utf-8")
        if canonical != entry.encoded:
            raise ValueError(f"attribution input {entry.digest} is not canonical")
        if hashlib.sha256(entry.encoded).hexdigest() != entry.digest:
            raise ValueError(f"attribution input digest mismatch: {entry.digest}")
        entry.provenance.as_metadata()
        digests.append(entry.digest)
    if digests != sorted(set(digests)):
        raise ValueError("attribution inputs must be unique and sorted")


def _validate_region_partition(
    baseline_regions: Set[str],
    target_regions: Set[str],
    covered_regions: Set[str],
    *,
    require_target: bool = True,
) -> None:
    _sorted_strings(baseline_regions)
    _sorted_strings(target_regions)
    _sorted_strings(covered_regions)
    if require_target and not target_regions:
        raise ValueError("new attribution job requires target regions")
    if baseline_regions & target_regions:
        raise ValueError("baseline and target regions overlap")
    if not target_regions <= covered_regions:
        raise ValueError("target regions are absent from batch evidence")


def _add_duration(metadata: Dict[str, Any], seconds: float) -> None:
    if not isinstance(seconds, (int, float)) or isinstance(seconds, bool) or seconds < 0:
        raise ValueError("replay duration must be nonnegative")
    metadata["duration_seconds"] = round(metadata["duration_seconds"] + seconds, 6)


def _validate_job_id(job_id: str) -> None:
    if not isinstance(job_id, str) or not JOB_ID_PATTERN.fullmatch(job_id):
        raise ValueError(f"invalid attribution job id: {job_id}")


def _write_json(path: Path, metadata: Dict[str, Any]) -> None:
    encoded = json.dumps(
        metadata,
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    _write_bytes(path, encoded)


def _atomic_write_json(path: Path, metadata: Dict[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-", dir=path.parent
    )
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
    if not source.is_file():
        raise FileNotFoundError(f"attribution evidence is missing: {source}")
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


def _sorted_strings(values: Iterable[str]) -> List[str]:
    values = list(values)
    if not all(isinstance(value, str) and value for value in values):
        raise ValueError("coverage regions must be non-empty strings")
    return sorted(set(values))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "AttributionInput",
    "AttributionInstability",
    "AttributionJob",
    "AttributionStore",
    "ReplayEvidence",
    "representative_label",
    "select_representatives",
]
