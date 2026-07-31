"""Persistent canonical corpus, run records, and ELF-scoped coverage state."""

import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from common import CORPUS_DIR
from generator import GENERATOR_VERSION, legacy_document_from_input
from scenario import (
    ScenarioDocument,
    parse_document,
    serialize_document,
    validate_entry_limits,
)


CORPUS_SCHEMA_VERSION = 1
COVERAGE_STATE_SCHEMA_VERSION = 1
RUN_SCHEMA_VERSION = 1

CORPUS_ENTRIES_NAME = "corpus"
RUNS_NAME = "runs"
COVERAGE_STATE_NAME = "coverage-state"
FAILURES_NAME = "failures"
OPS_NAME = "pipe.ops"
METADATA_NAME = "metadata.json"
LOCK_NAME = ".campaign.lock"

LEGACY_INITIAL_SEEDS = (
    bytes(range(256)),
    bytes(reversed(range(256))),
    b"\x00" * 32,
    b"\xff" * 32,
    b"pipe" * 64,
)

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_ENTRY_TEMP_PATTERN = re.compile(r"^\.[0-9a-f]{64}\.tmp-.+$")
_METADATA_TEMP_PATTERN = re.compile(r"^\.metadata\.json\.tmp-.+$")
_RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class CorpusStorageError(RuntimeError):
    """Base error for persistent campaign state."""


class CorpusValidationError(CorpusStorageError):
    """A persisted entry or coverage state failed closed validation."""

    def __init__(self, path: Path, reason: str):
        self.path = path
        self.reason = reason
        super().__init__(f"invalid persistent state at {path}: {reason}")


class CampaignLockError(CorpusStorageError):
    """Another campaign already owns the workspace persistence lock."""


@dataclass(frozen=True)
class CorpusProvenance:
    source: str
    parent_digest: Optional[str] = None
    donor_digest: Optional[str] = None
    mutation_type: Optional[str] = None

    @classmethod
    def generated(cls) -> "CorpusProvenance":
        return cls("generated")

    @classmethod
    def mutated(
        cls,
        parent_digest: str,
        donor_digest: Optional[str],
        mutation_type: str,
    ) -> "CorpusProvenance":
        return cls("mutation", parent_digest, donor_digest, mutation_type)

    def as_metadata(self) -> Dict[str, Any]:
        _validate_provenance(self)
        return {
            "source": self.source,
            "parent_digest": self.parent_digest,
            "donor_digest": self.donor_digest,
            "mutation_type": self.mutation_type,
        }


@dataclass(frozen=True)
class CorpusEntry:
    digest: str
    encoded: bytes
    document: ScenarioDocument


class CanonicalCorpus:
    """A canonical-digest map with deterministic iteration order."""

    def __init__(self):
        self._entries: Dict[str, CorpusEntry] = {}

    @classmethod
    def initial(cls) -> "CanonicalCorpus":
        corpus = cls()
        for raw_seed in LEGACY_INITIAL_SEEDS:
            corpus.add(legacy_document_from_input(raw_seed))
        return corpus

    def add(self, document: ScenarioDocument) -> bool:
        encoded = serialize_document(document).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        if digest in self._entries:
            return False
        self._entries[digest] = CorpusEntry(digest, encoded, document)
        return True

    def ordered_entries(self) -> List[CorpusEntry]:
        return [self._entries[digest] for digest in sorted(self._entries)]

    def __len__(self) -> int:
        return len(self._entries)


class CorpusStore:
    """Owns all ignored, workspace-local state for one pipe campaign."""

    def __init__(self, workspace: Path, generator_version: str = GENERATOR_VERSION):
        self.workspace = workspace.resolve()
        self.generator_version = generator_version
        self.root = self.workspace / CORPUS_DIR
        self.corpus_dir = self.root / CORPUS_ENTRIES_NAME
        self.runs_dir = self.root / RUNS_NAME
        self.coverage_state_dir = self.root / COVERAGE_STATE_NAME
        self.failures_dir = self.root / FAILURES_NAME

    def prepare(self) -> None:
        for directory in (
            self.corpus_dir,
            self.runs_dir,
            self.coverage_state_dir,
            self.failures_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    def campaign_lock(self) -> "CampaignLock":
        self.prepare()
        return CampaignLock(self.root / LOCK_NAME)

    def load_corpus(self) -> CanonicalCorpus:
        self.prepare()
        corpus = CanonicalCorpus()
        for path in sorted(self.corpus_dir.iterdir(), key=lambda item: item.name):
            if _ENTRY_TEMP_PATTERN.fullmatch(path.name):
                continue
            if path.is_symlink() or not path.is_dir():
                raise CorpusValidationError(path, "expected a canonical entry directory")
            entry = self._load_entry(path)
            if not corpus.add(entry.document):
                raise CorpusValidationError(path, "duplicate canonical digest")
        return corpus

    def save_entry(
        self,
        document: ScenarioDocument,
        provenance: CorpusProvenance,
        new_regions: Set[str],
    ) -> bool:
        self.prepare()
        _validate_provenance(provenance)
        validate_entry_limits(document)
        encoded = serialize_document(document).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        destination = self.corpus_dir / digest

        if destination.exists():
            self._update_last_verified(destination)
            return False

        environment = self.verification_environment()
        metadata = {
            "schema_version": CORPUS_SCHEMA_VERSION,
            "canonical_digest": digest,
            "pipe_ops_sha256": digest,
            "generator_version": self.generator_version,
            "origin": provenance.as_metadata(),
            "coverage": {
                "attribution": "batch-pending",
                "first_batch_new_regions": _sorted_regions(new_regions),
            },
            "first_observed": environment,
            "last_verified": environment,
            "stability": {
                "status": "unverified",
                "successful_batch_verifications": 1,
            },
            "batch_status": {
                "compare": "passed",
                "replay": "not-run",
            },
        }
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{digest}.tmp-", dir=self.corpus_dir)
        )
        try:
            _write_bytes(temporary / OPS_NAME, encoded)
            _write_json(temporary / METADATA_NAME, metadata)
            _sync_directory(temporary)
            os.replace(temporary, destination)
            _sync_directory(self.corpus_dir)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return True

    def elf_digest(self, elf_path: Path) -> str:
        if not elf_path.is_file():
            raise CorpusValidationError(elf_path, "instrumented StarryOS ELF is missing")
        return _sha256_file(elf_path)

    def load_coverage_regions(self, elf_path: Path) -> Set[str]:
        self.prepare()
        elf_digest = self.elf_digest(elf_path)
        state_path = self.coverage_state_dir / f"{elf_digest}.json"
        if not state_path.exists():
            return set()
        metadata = _read_json(state_path)
        _require_exact_keys(
            metadata,
            {"schema_version", "starry_elf_sha256", "covered_regions", "last_updated"},
            state_path,
        )
        if metadata["schema_version"] != COVERAGE_STATE_SCHEMA_VERSION:
            raise CorpusValidationError(state_path, "unsupported coverage-state schema")
        if metadata["starry_elf_sha256"] != elf_digest:
            raise CorpusValidationError(state_path, "coverage-state ELF digest mismatch")
        regions = metadata["covered_regions"]
        if not _is_sorted_unique_strings(regions):
            raise CorpusValidationError(
                state_path, "covered_regions must be sorted unique strings"
            )
        _validate_environment(metadata["last_updated"], state_path)
        return set(regions)

    def save_coverage_regions(self, elf_path: Path, regions: Set[str]) -> str:
        self.prepare()
        elf_digest = self.elf_digest(elf_path)
        state_path = self.coverage_state_dir / f"{elf_digest}.json"
        if state_path.exists():
            self.load_coverage_regions(elf_path)
        metadata = {
            "schema_version": COVERAGE_STATE_SCHEMA_VERSION,
            "starry_elf_sha256": elf_digest,
            "covered_regions": _sorted_regions(regions),
            "last_updated": self.verification_environment(),
        }
        _atomic_write_json(state_path, metadata)
        return elf_digest

    def save_run(self, run_id: str, metadata: Dict[str, Any]) -> Path:
        self.prepare()
        if not _RUN_ID_PATTERN.fullmatch(run_id):
            raise ValueError(f"invalid run id: {run_id}")
        destination = self.runs_dir / run_id
        if destination.exists():
            raise CorpusStorageError(f"run directory already exists: {destination}")
        payload = {
            **metadata,
            "schema_version": RUN_SCHEMA_VERSION,
            "generator_version": self.generator_version,
        }
        temporary = Path(
            tempfile.mkdtemp(prefix=f".{run_id}.tmp-", dir=self.runs_dir)
        )
        try:
            _write_json(temporary / METADATA_NAME, payload)
            _sync_directory(temporary)
            os.replace(temporary, destination)
            _sync_directory(self.runs_dir)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return destination

    def verification_environment(self) -> Dict[str, Any]:
        return {
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "git_commit": _git_commit(self.workspace),
            "git_dirty": _git_dirty(self.workspace),
            "architecture": "x86_64",
            "host": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "page_size": os.sysconf("SC_PAGE_SIZE"),
            },
        }

    def _load_entry(self, entry_dir: Path) -> CorpusEntry:
        try:
            if not _DIGEST_PATTERN.fullmatch(entry_dir.name):
                raise CorpusValidationError(entry_dir, "directory name is not a SHA-256")
            names = {
                path.name
                for path in entry_dir.iterdir()
                if not _METADATA_TEMP_PATTERN.fullmatch(path.name)
            }
            if names != {OPS_NAME, METADATA_NAME}:
                raise CorpusValidationError(
                    entry_dir,
                    f"entry files must be exactly {OPS_NAME} and {METADATA_NAME}",
                )
            ops_path = entry_dir / OPS_NAME
            metadata_path = entry_dir / METADATA_NAME
            if ops_path.is_symlink() or not ops_path.is_file():
                raise CorpusValidationError(ops_path, "pipe.ops is not a regular file")
            if metadata_path.is_symlink() or not metadata_path.is_file():
                raise CorpusValidationError(
                    metadata_path, "metadata.json is not a regular file"
                )

            encoded = ops_path.read_bytes()
            document = parse_document(encoded)
            validate_entry_limits(document)
            canonical = serialize_document(document).encode("utf-8")
            if encoded != canonical:
                raise CorpusValidationError(ops_path, "pipe.ops is not canonical")
            digest = hashlib.sha256(encoded).hexdigest()
            if digest != entry_dir.name:
                raise CorpusValidationError(ops_path, "pipe.ops digest mismatches directory")

            metadata = _read_json(metadata_path)
            self._validate_entry_metadata(metadata, entry_dir, digest)
            return CorpusEntry(digest, encoded, document)
        except CorpusValidationError:
            raise
        except (OSError, UnicodeError, ValueError, TypeError) as error:
            raise CorpusValidationError(entry_dir, str(error)) from error

    def _validate_entry_metadata(
        self,
        metadata: Dict[str, Any],
        entry_dir: Path,
        digest: str,
    ) -> None:
        _require_exact_keys(
            metadata,
            {
                "schema_version",
                "canonical_digest",
                "pipe_ops_sha256",
                "generator_version",
                "origin",
                "coverage",
                "first_observed",
                "last_verified",
                "stability",
                "batch_status",
            },
            entry_dir / METADATA_NAME,
        )
        if metadata["schema_version"] != CORPUS_SCHEMA_VERSION:
            raise CorpusValidationError(entry_dir, "unsupported corpus schema")
        if metadata["generator_version"] != self.generator_version:
            raise CorpusValidationError(entry_dir, "incompatible generator version")
        if metadata["canonical_digest"] != digest:
            raise CorpusValidationError(entry_dir, "canonical digest mismatch")
        if metadata["pipe_ops_sha256"] != digest:
            raise CorpusValidationError(entry_dir, "pipe.ops metadata digest mismatch")
        _validate_origin_metadata(metadata["origin"], entry_dir)
        _validate_coverage_metadata(metadata["coverage"], entry_dir)
        _validate_environment(metadata["first_observed"], entry_dir)
        _validate_environment(metadata["last_verified"], entry_dir)
        _validate_stability(metadata["stability"], entry_dir)
        _validate_batch_status(metadata["batch_status"], entry_dir)

    def _update_last_verified(self, entry_dir: Path) -> None:
        entry = self._load_entry(entry_dir)
        metadata_path = entry_dir / METADATA_NAME
        metadata = _read_json(metadata_path)
        self._validate_entry_metadata(metadata, entry_dir, entry.digest)
        metadata["last_verified"] = self.verification_environment()
        metadata["stability"]["successful_batch_verifications"] += 1
        _atomic_write_json(metadata_path, metadata)


class CampaignLock:
    def __init__(self, path: Path):
        self.path = path
        self._file = None

    def __enter__(self) -> "CampaignLock":
        self._file = self.path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            self._file.close()
            self._file = None
            raise CampaignLockError(
                f"another pipe-oracle campaign holds {self.path}"
            ) from error
        self._file.seek(0)
        self._file.truncate()
        self._file.write(f"pid={os.getpid()}\n")
        self._file.flush()
        return self

    def __exit__(self, _error_type, _error, _traceback) -> None:
        if self._file is not None:
            fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            self._file.close()
            self._file = None


def _validate_provenance(provenance: CorpusProvenance) -> None:
    if provenance.source == "generated":
        if any(
            value is not None
            for value in (
                provenance.parent_digest,
                provenance.donor_digest,
                provenance.mutation_type,
            )
        ):
            raise ValueError("generated provenance cannot have mutation ancestry")
        return
    if provenance.source != "mutation":
        raise ValueError(f"unknown corpus source: {provenance.source}")
    if not _is_digest(provenance.parent_digest):
        raise ValueError("mutation provenance requires a parent digest")
    if provenance.donor_digest is not None and not _is_digest(provenance.donor_digest):
        raise ValueError("mutation donor digest is invalid")
    if not provenance.mutation_type:
        raise ValueError("mutation provenance requires a mutation type")


def _validate_origin_metadata(metadata: Any, path: Path) -> None:
    _require_exact_keys(
        metadata,
        {"source", "parent_digest", "donor_digest", "mutation_type"},
        path,
    )
    try:
        provenance = CorpusProvenance(
            metadata["source"],
            metadata["parent_digest"],
            metadata["donor_digest"],
            metadata["mutation_type"],
        )
        _validate_provenance(provenance)
    except ValueError as error:
        raise CorpusValidationError(path, str(error)) from error


def _validate_coverage_metadata(metadata: Any, path: Path) -> None:
    _require_exact_keys(metadata, {"attribution", "first_batch_new_regions"}, path)
    if metadata["attribution"] != "batch-pending":
        raise CorpusValidationError(path, "unsupported coverage attribution")
    if not _is_sorted_unique_strings(metadata["first_batch_new_regions"]):
        raise CorpusValidationError(path, "new regions must be sorted unique strings")


def _validate_environment(metadata: Any, path: Path) -> None:
    _require_exact_keys(
        metadata,
        {"observed_at", "git_commit", "git_dirty", "architecture", "host"},
        path,
    )
    if not isinstance(metadata["observed_at"], str) or not metadata["observed_at"]:
        raise CorpusValidationError(path, "observed_at must be a string")
    if not isinstance(metadata["git_commit"], str) or not metadata["git_commit"]:
        raise CorpusValidationError(path, "git_commit must be a string")
    if not isinstance(metadata["git_dirty"], bool):
        raise CorpusValidationError(path, "git_dirty must be boolean")
    if metadata["architecture"] != "x86_64":
        raise CorpusValidationError(path, "unsupported corpus architecture")
    host = metadata["host"]
    _require_exact_keys(host, {"system", "release", "version", "machine", "page_size"}, path)
    if not all(isinstance(host[key], str) for key in ("system", "release", "version", "machine")):
        raise CorpusValidationError(path, "host environment fields must be strings")
    if not isinstance(host["page_size"], int) or host["page_size"] <= 0:
        raise CorpusValidationError(path, "host page size must be positive")


def _validate_stability(metadata: Any, path: Path) -> None:
    _require_exact_keys(metadata, {"status", "successful_batch_verifications"}, path)
    if metadata["status"] != "unverified":
        raise CorpusValidationError(path, "unsupported stability status")
    count = metadata["successful_batch_verifications"]
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise CorpusValidationError(path, "verification count must be positive")


def _validate_batch_status(metadata: Any, path: Path) -> None:
    _require_exact_keys(metadata, {"compare", "replay"}, path)
    if metadata["compare"] != "passed" or metadata["replay"] != "not-run":
        raise CorpusValidationError(path, "unsupported batch compare/replay status")


def _require_exact_keys(metadata: Any, keys: Set[str], path: Path) -> None:
    if not isinstance(metadata, dict):
        raise CorpusValidationError(path, "metadata object is not a JSON object")
    actual = set(metadata)
    if actual != keys:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys)
        raise CorpusValidationError(
            path,
            f"metadata keys mismatch: missing={missing} extra={extra}",
        )


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CorpusValidationError(path, f"cannot read JSON: {error}") from error
    if not isinstance(value, dict):
        raise CorpusValidationError(path, "top-level JSON value is not an object")
    return value


def _write_bytes(path: Path, data: bytes) -> None:
    with path.open("wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def _write_json(path: Path, metadata: Dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as output:
        json.dump(metadata, output, indent=2, ensure_ascii=False, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


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


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sorted_regions(regions: Set[str]) -> List[str]:
    if not all(isinstance(region, str) and region for region in regions):
        raise ValueError("coverage regions must be non-empty strings")
    return sorted(regions)


def _is_sorted_unique_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) and item for item in value)
        and value == sorted(set(value))
    )


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST_PATTERN.fullmatch(value) is not None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _git_commit(workspace: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=workspace,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _git_dirty(workspace: Path) -> bool:
    try:
        status = subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=workspace,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return bool(status.strip())
    except (OSError, subprocess.CalledProcessError):
        return False


__all__ = [
    "CampaignLockError",
    "CanonicalCorpus",
    "CorpusEntry",
    "CorpusProvenance",
    "CorpusStorageError",
    "CorpusStore",
    "CorpusValidationError",
    "LEGACY_INITIAL_SEEDS",
]
