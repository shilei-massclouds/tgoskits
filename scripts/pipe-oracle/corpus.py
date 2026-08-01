"""Persistent canonical corpus, run records, and ELF-scoped coverage state."""

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
from campaign_lock import CampaignLock
from corpus_errors import (
    CampaignLockError,
    CorpusStorageError,
    CorpusValidationError,
)
from coverage import (
    FD_TARGET_SET_ID,
    LEGACY_TARGET_SET_ID,
    TARGET_SET_ID,
    VECTOR_TARGET_SET_ID,
)
from generator import (
    GENERATOR_VERSION,
    SUPPORTED_CORPUS_GENERATOR_VERSIONS,
    legacy_document_from_input,
)
from scenario import (
    ScenarioDocument,
    parse_document,
    serialize_document,
    validate_entry_limits,
)


LEGACY_CORPUS_SCHEMA_VERSION = 1
ATTRIBUTED_CORPUS_SCHEMA_VERSION = 2
CORPUS_SCHEMA_VERSION = 3
LEGACY_COVERAGE_STATE_SCHEMA_VERSION = 1
FD_COVERAGE_STATE_SCHEMA_VERSION = 2
VECTOR_COVERAGE_STATE_SCHEMA_VERSION = 3
COVERAGE_STATE_SCHEMA_VERSION = 4
RUN_SCHEMA_VERSION = 6

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
        loaded_entries = []
        for path in sorted(self.corpus_dir.iterdir(), key=lambda item: item.name):
            if _ENTRY_TEMP_PATTERN.fullmatch(path.name):
                continue
            if path.is_symlink() or not path.is_dir():
                raise CorpusValidationError(path, "expected a canonical entry directory")
            entry = self._load_entry(path)
            metadata = _read_json(path / METADATA_NAME)
            loaded_entries.append((path, entry, metadata))
        entries_by_digest = {
            entry.digest: (path, metadata)
            for path, entry, metadata in loaded_entries
        }
        for path, entry, metadata in loaded_entries:
            if (
                metadata["schema_version"] == CORPUS_SCHEMA_VERSION
                and metadata["lifecycle"]["status"] == "superseded"
            ):
                replacement_digest = metadata["lifecycle"]["superseded_by"]
                replacement = entries_by_digest.get(replacement_digest)
                if replacement is None:
                    raise CorpusValidationError(
                        path,
                        "superseded corpus replacement is missing",
                    )
                _replacement_path, replacement_metadata = replacement
                if (
                    replacement_metadata["schema_version"] != CORPUS_SCHEMA_VERSION
                    or replacement_metadata["lifecycle"]["status"] != "active"
                ):
                    raise CorpusValidationError(
                        path,
                        "superseded corpus replacement is not active schema v3",
                    )
                continue
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
            "schema_version": LEGACY_CORPUS_SCHEMA_VERSION,
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

    def admit_attributed_entry(
        self,
        document: ScenarioDocument,
        provenance: CorpusProvenance,
        attributed_regions: Set[str],
        attribution_job_id: str,
    ) -> bool:
        """Admit an exact-attribution representative or update it atomically."""
        self.prepare()
        _validate_provenance(provenance)
        _validate_attribution(attributed_regions, attribution_job_id)
        validate_entry_limits(document)
        encoded = serialize_document(document).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        destination = self.corpus_dir / digest

        if destination.exists():
            self._update_exact_attribution(
                destination,
                attributed_regions,
                attribution_job_id,
            )
            return False

        environment = self.verification_environment()
        metadata = {
            "schema_version": ATTRIBUTED_CORPUS_SCHEMA_VERSION,
            "canonical_digest": digest,
            "pipe_ops_sha256": digest,
            "generator_version": self.generator_version,
            "origin": provenance.as_metadata(),
            "coverage": {
                "attribution": "exact",
                "first_batch_new_regions": _sorted_regions(attributed_regions),
                "attributed_regions": _sorted_regions(attributed_regions),
                "attribution_jobs": [attribution_job_id],
            },
            "first_observed": environment,
            "last_verified": environment,
            "stability": {
                "status": "stable",
                "successful_batch_verifications": 1,
                "successful_attribution_verifications": 1,
            },
            "batch_status": {
                "compare": "passed",
                "replay": "passed",
            },
        }
        self._save_new_entry(destination, encoded, metadata)
        return True

    def admit_minimized_entry(
        self,
        document: ScenarioDocument,
        provenance: CorpusProvenance,
        attributed_regions: Set[str],
        minimization_job_id: str,
        original_digests: Set[str],
    ) -> bool:
        """Activate a proved minimized entry before any source is superseded."""
        self.prepare()
        _validate_provenance(provenance)
        _validate_attribution(attributed_regions, minimization_job_id)
        _validate_digest_set(original_digests, "minimization originals")
        validate_entry_limits(document)
        encoded = serialize_document(document).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        if digest in original_digests:
            raise ValueError("minimized digest must differ from every original")
        destination = self.corpus_dir / digest
        if destination.exists():
            self._merge_minimization_lineage(
                destination,
                attributed_regions,
                minimization_job_id,
                original_digests,
            )
            return False

        environment = self.verification_environment()
        metadata = {
            "schema_version": CORPUS_SCHEMA_VERSION,
            "canonical_digest": digest,
            "pipe_ops_sha256": digest,
            "generator_version": self.generator_version,
            "origin": provenance.as_metadata(),
            "coverage": {
                "attribution": "exact",
                "first_batch_new_regions": _sorted_regions(attributed_regions),
                "attributed_regions": _sorted_regions(attributed_regions),
                "attribution_jobs": [minimization_job_id],
            },
            "first_observed": environment,
            "last_verified": environment,
            "stability": {
                "status": "stable",
                "successful_batch_verifications": 1,
                "successful_attribution_verifications": 1,
            },
            "batch_status": {"compare": "passed", "replay": "passed"},
            "lifecycle": {"status": "active", "superseded_by": None},
            "minimization": {
                "original_digests": sorted(original_digests),
                "minimization_jobs": [minimization_job_id],
            },
        }
        self._save_new_entry(destination, encoded, metadata)
        return True

    def supersede_entry(
        self,
        original_digest: str,
        replacement_digest: str,
        minimization_job_id: str,
    ) -> None:
        """Atomically mark one historical entry superseded after replacement activation."""
        self.prepare()
        if not _is_digest(original_digest) or not _is_digest(replacement_digest):
            raise ValueError("supersede requires canonical digests")
        if original_digest == replacement_digest:
            raise ValueError("corpus entry cannot supersede itself")
        if not _RUN_ID_PATTERN.fullmatch(minimization_job_id):
            raise ValueError("invalid minimization job id")
        replacement = self.corpus_dir / replacement_digest
        if not replacement.exists():
            raise CorpusStorageError(f"replacement corpus entry is missing: {replacement}")
        replacement_entry = self._load_entry(replacement)
        replacement_metadata = _read_json(replacement / METADATA_NAME)
        if (
            replacement_entry.digest != replacement_digest
            or replacement_metadata["schema_version"] != CORPUS_SCHEMA_VERSION
            or replacement_metadata["lifecycle"]["status"] != "active"
        ):
            raise CorpusStorageError("replacement corpus entry is not active schema v3")

        original = self.corpus_dir / original_digest
        entry = self._load_entry(original)
        metadata = _read_json(original / METADATA_NAME)
        if metadata["schema_version"] == CORPUS_SCHEMA_VERSION:
            lifecycle = metadata["lifecycle"]
            if lifecycle["status"] == "superseded":
                if lifecycle["superseded_by"] != replacement_digest:
                    raise CorpusStorageError("corpus entry has a different replacement")
                return
        else:
            metadata = self._upgrade_metadata_to_v3(
                metadata,
                entry.digest,
                minimization_job_id,
            )
        metadata["lifecycle"] = {
            "status": "superseded",
            "superseded_by": replacement_digest,
        }
        metadata["minimization"]["minimization_jobs"] = sorted(
            set(metadata["minimization"]["minimization_jobs"])
            | {minimization_job_id}
        )
        metadata["last_verified"] = self.verification_environment()
        _atomic_write_json(original / METADATA_NAME, metadata)

    def entry_metadata(self, digest: str) -> Dict[str, Any]:
        if not _is_digest(digest):
            raise ValueError("invalid corpus digest")
        entry_dir = self.corpus_dir / digest
        entry = self._load_entry(entry_dir)
        metadata = _read_json(entry_dir / METADATA_NAME)
        self._validate_entry_metadata(metadata, entry_dir, entry.digest)
        return metadata

    def update_existing_attribution(
        self,
        document: ScenarioDocument,
        attributed_regions: Set[str],
        attribution_job_id: str,
    ) -> bool:
        """Lazily upgrade an existing contributor without admitting a new entry."""
        self.prepare()
        _validate_attribution(attributed_regions, attribution_job_id)
        validate_entry_limits(document)
        encoded = serialize_document(document).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        destination = self.corpus_dir / digest
        if not destination.exists():
            return False
        self._update_exact_attribution(
            destination,
            attributed_regions,
            attribution_job_id,
        )
        return True

    def elf_digest(self, elf_path: Path) -> str:
        if not elf_path.is_file():
            raise CorpusValidationError(elf_path, "instrumented StarryOS ELF is missing")
        return _sha256_file(elf_path)

    def load_coverage_regions(
        self,
        elf_path: Path,
        target_set_id: str = TARGET_SET_ID,
    ) -> Set[str]:
        self.prepare()
        elf_digest = self.elf_digest(elf_path)
        state_path = self._coverage_state_path(elf_digest, target_set_id)
        if target_set_id == LEGACY_TARGET_SET_ID and not state_path.exists():
            state_path = self.coverage_state_dir / f"{elf_digest}.json"
        if not state_path.exists():
            return set()
        if state_path.is_symlink() or not state_path.is_file():
            raise CorpusValidationError(
                state_path,
                "coverage-state is not a regular file",
            )
        metadata = _read_json(state_path)
        schema_version = metadata.get("schema_version")
        if schema_version == LEGACY_COVERAGE_STATE_SCHEMA_VERSION:
            _require_exact_keys(
                metadata,
                {
                    "schema_version",
                    "starry_elf_sha256",
                    "covered_regions",
                    "last_updated",
                },
                state_path,
            )
            if target_set_id != LEGACY_TARGET_SET_ID:
                raise CorpusValidationError(
                    state_path,
                    "legacy coverage-state belongs to the pipe-v1 target set",
                )
        elif schema_version in (
            FD_COVERAGE_STATE_SCHEMA_VERSION,
            VECTOR_COVERAGE_STATE_SCHEMA_VERSION,
            COVERAGE_STATE_SCHEMA_VERSION,
        ):
            _require_exact_keys(
                metadata,
                {
                    "schema_version",
                    "target_set_id",
                    "starry_elf_sha256",
                    "covered_regions",
                    "last_updated",
                },
                state_path,
            )
            expected_target_set_id = (
                FD_TARGET_SET_ID
                if schema_version == FD_COVERAGE_STATE_SCHEMA_VERSION
                else (
                    VECTOR_TARGET_SET_ID
                    if schema_version == VECTOR_COVERAGE_STATE_SCHEMA_VERSION
                    else TARGET_SET_ID
                )
            )
            if metadata.get("target_set_id") != expected_target_set_id:
                raise CorpusValidationError(
                    state_path,
                    "coverage-state schema target set mismatch",
                )
            if expected_target_set_id != target_set_id:
                raise CorpusValidationError(
                    state_path,
                    "coverage-state target set mismatch",
                )
        else:
            raise CorpusValidationError(state_path, "unsupported coverage-state schema")
        if schema_version not in (
            LEGACY_COVERAGE_STATE_SCHEMA_VERSION,
            FD_COVERAGE_STATE_SCHEMA_VERSION,
            VECTOR_COVERAGE_STATE_SCHEMA_VERSION,
            COVERAGE_STATE_SCHEMA_VERSION,
        ):
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

    def save_coverage_regions(
        self,
        elf_path: Path,
        regions: Set[str],
        target_set_id: str = TARGET_SET_ID,
    ) -> str:
        self.prepare()
        elf_digest = self.elf_digest(elf_path)
        state_path = self._coverage_state_path(elf_digest, target_set_id)
        if state_path.exists():
            self.load_coverage_regions(elf_path, target_set_id)
        schema_version = {
            LEGACY_TARGET_SET_ID: LEGACY_COVERAGE_STATE_SCHEMA_VERSION,
            FD_TARGET_SET_ID: FD_COVERAGE_STATE_SCHEMA_VERSION,
            VECTOR_TARGET_SET_ID: VECTOR_COVERAGE_STATE_SCHEMA_VERSION,
            TARGET_SET_ID: COVERAGE_STATE_SCHEMA_VERSION,
        }.get(target_set_id)
        if schema_version is None:
            raise ValueError(f"unknown coverage target set: {target_set_id}")
        metadata = {
            "schema_version": schema_version,
            "starry_elf_sha256": elf_digest,
            "covered_regions": _sorted_regions(regions),
            "last_updated": self.verification_environment(),
        }
        if schema_version != LEGACY_COVERAGE_STATE_SCHEMA_VERSION:
            metadata["target_set_id"] = target_set_id
        _atomic_write_json(state_path, metadata)
        return elf_digest

    def _coverage_state_path(self, elf_digest: str, target_set_id: str) -> Path:
        if target_set_id not in (
            LEGACY_TARGET_SET_ID,
            FD_TARGET_SET_ID,
            VECTOR_TARGET_SET_ID,
            TARGET_SET_ID,
        ):
            raise ValueError(f"unknown coverage target set: {target_set_id}")
        return self.coverage_state_dir / f"{elf_digest}-{target_set_id}.json"

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
            "target_set_id": TARGET_SET_ID,
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
        common_keys = {
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
        }
        schema_version = metadata["schema_version"]
        if schema_version not in (
            LEGACY_CORPUS_SCHEMA_VERSION,
            ATTRIBUTED_CORPUS_SCHEMA_VERSION,
            CORPUS_SCHEMA_VERSION,
        ):
            raise CorpusValidationError(entry_dir, "unsupported corpus schema")
        expected_keys = set(common_keys)
        if schema_version == CORPUS_SCHEMA_VERSION:
            expected_keys |= {"lifecycle", "minimization"}
        _require_exact_keys(metadata, expected_keys, entry_dir / METADATA_NAME)
        if metadata["generator_version"] not in SUPPORTED_CORPUS_GENERATOR_VERSIONS:
            raise CorpusValidationError(entry_dir, "incompatible generator version")
        if metadata["canonical_digest"] != digest:
            raise CorpusValidationError(entry_dir, "canonical digest mismatch")
        if metadata["pipe_ops_sha256"] != digest:
            raise CorpusValidationError(entry_dir, "pipe.ops metadata digest mismatch")
        _validate_origin_metadata(metadata["origin"], entry_dir)
        _validate_coverage_metadata(metadata["coverage"], entry_dir, schema_version)
        _validate_environment(metadata["first_observed"], entry_dir)
        _validate_environment(metadata["last_verified"], entry_dir)
        _validate_stability(metadata["stability"], entry_dir, schema_version)
        _validate_batch_status(metadata["batch_status"], entry_dir, schema_version)
        if schema_version == CORPUS_SCHEMA_VERSION:
            _validate_lifecycle(metadata["lifecycle"], digest, entry_dir)
            _validate_minimization(metadata["minimization"], entry_dir)

    def _update_last_verified(self, entry_dir: Path) -> None:
        entry = self._load_entry(entry_dir)
        metadata_path = entry_dir / METADATA_NAME
        metadata = _read_json(metadata_path)
        self._validate_entry_metadata(metadata, entry_dir, entry.digest)
        metadata["last_verified"] = self.verification_environment()
        metadata["stability"]["successful_batch_verifications"] += 1
        _atomic_write_json(metadata_path, metadata)

    def _update_exact_attribution(
        self,
        entry_dir: Path,
        attributed_regions: Set[str],
        attribution_job_id: str,
    ) -> None:
        entry = self._load_entry(entry_dir)
        metadata_path = entry_dir / METADATA_NAME
        metadata = _read_json(metadata_path)
        self._validate_entry_metadata(metadata, entry_dir, entry.digest)
        if metadata["schema_version"] == LEGACY_CORPUS_SCHEMA_VERSION:
            metadata["schema_version"] = ATTRIBUTED_CORPUS_SCHEMA_VERSION
            metadata["coverage"] = {
                **metadata["coverage"],
                "attribution": "exact",
                "attributed_regions": _sorted_regions(attributed_regions),
                "attribution_jobs": [attribution_job_id],
            }
            metadata["stability"] = {
                **metadata["stability"],
                "status": "stable",
                "successful_attribution_verifications": 1,
            }
        else:
            coverage = metadata["coverage"]
            if attribution_job_id in coverage["attribution_jobs"]:
                return
            coverage["attributed_regions"] = _sorted_regions(
                set(coverage["attributed_regions"]) | attributed_regions
            )
            coverage["attribution_jobs"] = sorted(
                set(coverage["attribution_jobs"]) | {attribution_job_id}
            )
            metadata["stability"]["successful_attribution_verifications"] += 1
        metadata["last_verified"] = self.verification_environment()
        metadata["stability"]["successful_batch_verifications"] += 1
        metadata["batch_status"]["replay"] = "passed"
        _atomic_write_json(metadata_path, metadata)

    def _merge_minimization_lineage(
        self,
        entry_dir: Path,
        attributed_regions: Set[str],
        minimization_job_id: str,
        original_digests: Set[str],
    ) -> None:
        entry = self._load_entry(entry_dir)
        metadata = _read_json(entry_dir / METADATA_NAME)
        if metadata["schema_version"] == CORPUS_SCHEMA_VERSION:
            coverage = metadata["coverage"]
            lineage = metadata["minimization"]
            if (
                minimization_job_id in lineage["minimization_jobs"]
                and original_digests <= set(lineage["original_digests"])
                and attributed_regions <= set(coverage["attributed_regions"])
            ):
                return
        if metadata["schema_version"] != CORPUS_SCHEMA_VERSION:
            metadata = self._upgrade_metadata_to_v3(
                metadata,
                entry.digest,
                minimization_job_id,
            )
        if metadata["lifecycle"]["status"] != "active":
            raise CorpusStorageError("cannot reactivate a superseded corpus entry")
        coverage = metadata["coverage"]
        if coverage["attribution"] != "exact":
            coverage.update(
                {
                    "attribution": "exact",
                    "attributed_regions": [],
                    "attribution_jobs": [],
                }
            )
        coverage["attributed_regions"] = _sorted_regions(
            set(coverage["attributed_regions"]) | attributed_regions
        )
        coverage["attribution_jobs"] = sorted(
            set(coverage["attribution_jobs"]) | {minimization_job_id}
        )
        lineage = metadata["minimization"]
        lineage["original_digests"] = sorted(
            set(lineage["original_digests"]) | original_digests
        )
        lineage["minimization_jobs"] = sorted(
            set(lineage["minimization_jobs"]) | {minimization_job_id}
        )
        metadata["last_verified"] = self.verification_environment()
        metadata["stability"]["successful_batch_verifications"] += 1
        metadata["stability"]["successful_attribution_verifications"] += 1
        _atomic_write_json(entry_dir / METADATA_NAME, metadata)

    def _upgrade_metadata_to_v3(
        self,
        metadata: Dict[str, Any],
        digest: str,
        minimization_job_id: str,
    ) -> Dict[str, Any]:
        if metadata["schema_version"] == LEGACY_CORPUS_SCHEMA_VERSION:
            regions = set(metadata["coverage"]["first_batch_new_regions"])
            metadata["coverage"] = {
                **metadata["coverage"],
                "attribution": "exact",
                "attributed_regions": _sorted_regions(regions),
                "attribution_jobs": [minimization_job_id],
            }
            metadata["stability"] = {
                **metadata["stability"],
                "status": "stable",
                "successful_attribution_verifications": 1,
            }
            metadata["batch_status"]["replay"] = "passed"
        metadata["schema_version"] = CORPUS_SCHEMA_VERSION
        metadata["lifecycle"] = {"status": "active", "superseded_by": None}
        metadata["minimization"] = {
            "original_digests": [digest],
            "minimization_jobs": [minimization_job_id],
        }
        return metadata

    def _save_new_entry(
        self,
        destination: Path,
        encoded: bytes,
        metadata: Dict[str, Any],
    ) -> None:
        digest = destination.name
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


def _validate_coverage_metadata(
    metadata: Any,
    path: Path,
    schema_version: int,
) -> None:
    if schema_version == LEGACY_CORPUS_SCHEMA_VERSION:
        _require_exact_keys(
            metadata,
            {"attribution", "first_batch_new_regions"},
            path,
        )
        if metadata["attribution"] != "batch-pending":
            raise CorpusValidationError(path, "unsupported coverage attribution")
    else:
        _require_exact_keys(
            metadata,
            {
                "attribution",
                "first_batch_new_regions",
                "attributed_regions",
                "attribution_jobs",
            },
            path,
        )
        if metadata["attribution"] != "exact":
            raise CorpusValidationError(path, "unsupported coverage attribution")
        if not _is_sorted_unique_strings(metadata["attributed_regions"]):
            raise CorpusValidationError(
                path,
                "attributed regions must be sorted unique strings",
            )
        if not metadata["attributed_regions"]:
            raise CorpusValidationError(path, "exact attribution must not be empty")
        jobs = metadata["attribution_jobs"]
        if (
            not _is_sorted_unique_strings(jobs)
            or not jobs
            or not all(_RUN_ID_PATTERN.fullmatch(job) for job in jobs)
        ):
            raise CorpusValidationError(
                path,
                "attribution jobs must be sorted unique run ids",
            )
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


def _validate_stability(metadata: Any, path: Path, schema_version: int) -> None:
    keys = {"status", "successful_batch_verifications"}
    if schema_version != LEGACY_CORPUS_SCHEMA_VERSION:
        keys.add("successful_attribution_verifications")
    _require_exact_keys(metadata, keys, path)
    expected_status = (
        "unverified"
        if schema_version == LEGACY_CORPUS_SCHEMA_VERSION
        else "stable"
    )
    if metadata["status"] != expected_status:
        raise CorpusValidationError(path, "unsupported stability status")
    count = metadata["successful_batch_verifications"]
    if not _is_positive_integer(count):
        raise CorpusValidationError(path, "verification count must be positive")
    if schema_version != LEGACY_CORPUS_SCHEMA_VERSION:
        attribution_count = metadata["successful_attribution_verifications"]
        if not _is_positive_integer(attribution_count):
            raise CorpusValidationError(
                path,
                "attribution verification count must be positive",
            )


def _validate_batch_status(metadata: Any, path: Path, schema_version: int) -> None:
    _require_exact_keys(metadata, {"compare", "replay"}, path)
    expected_replay = (
        "not-run"
        if schema_version == LEGACY_CORPUS_SCHEMA_VERSION
        else "passed"
    )
    if metadata["compare"] != "passed" or metadata["replay"] != expected_replay:
        raise CorpusValidationError(path, "unsupported batch compare/replay status")


def _validate_attribution(regions: Set[str], job_id: str) -> None:
    if not regions:
        raise ValueError("exact attribution requires at least one region")
    _sorted_regions(regions)
    if not isinstance(job_id, str) or not _RUN_ID_PATTERN.fullmatch(job_id):
        raise ValueError(f"invalid attribution job id: {job_id}")


def _validate_lifecycle(metadata: Any, digest: str, path: Path) -> None:
    _require_exact_keys(metadata, {"status", "superseded_by"}, path)
    status = metadata["status"]
    replacement = metadata["superseded_by"]
    if status == "active":
        if replacement is not None:
            raise CorpusValidationError(path, "active corpus entry has a replacement")
    elif status == "superseded":
        if not _is_digest(replacement) or replacement == digest:
            raise CorpusValidationError(path, "superseded corpus replacement is invalid")
    else:
        raise CorpusValidationError(path, "unsupported corpus lifecycle status")


def _validate_minimization(metadata: Any, path: Path) -> None:
    _require_exact_keys(
        metadata,
        {"original_digests", "minimization_jobs"},
        path,
    )
    originals = metadata["original_digests"]
    jobs = metadata["minimization_jobs"]
    if (
        not isinstance(originals, list)
        or not originals
        or originals != sorted(set(originals))
        or not all(_is_digest(digest) for digest in originals)
    ):
        raise CorpusValidationError(path, "minimization originals are invalid")
    if (
        not _is_sorted_unique_strings(jobs)
        or not jobs
        or not all(_RUN_ID_PATTERN.fullmatch(job) for job in jobs)
    ):
        raise CorpusValidationError(path, "minimization jobs are invalid")


def _validate_digest_set(values: Set[str], name: str) -> None:
    if not isinstance(values, set) or not values or not all(_is_digest(value) for value in values):
        raise ValueError(f"{name} must be a non-empty digest set")


def _is_positive_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


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
