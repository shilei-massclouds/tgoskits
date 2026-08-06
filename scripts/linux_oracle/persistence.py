"""Strict schemas and crash-safe storage for adapter campaign state."""

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, Mapping, Tuple

from .spec import AdapterSpec


CORPUS_SCHEMA_NAME = "linux-oracle-corpus-entry"
CORPUS_SCHEMA_VERSION = 1
COVERAGE_SCHEMA_NAME = "linux-oracle-coverage-state"
COVERAGE_SCHEMA_VERSION = 1
RUN_SCHEMA_NAME = "linux-oracle-run"
RUN_SCHEMA_VERSION = 1


class PersistentStateError(RuntimeError):
    pass


@dataclass(frozen=True)
class CorpusEntry:
    digest: str
    encoded: bytes
    attributed_regions: Tuple[str, ...]
    path: Path


class CampaignStore:
    def __init__(self, spec: AdapterSpec, workspace: Path):
        self.spec = spec
        self.workspace = workspace.resolve()
        self.root = self.workspace / spec.campaign.root
        self.corpus_root = self.root / spec.campaign.corpus_directory
        self.runs_root = self.root / spec.campaign.run_directory
        self.coverage_root = self.root / spec.campaign.coverage_directory
        self.failures_root = self.root / spec.campaign.failure_directory
        self.questions_root = self.root / spec.campaign.question_directory

    def load_entries(self) -> Tuple[CorpusEntry, ...]:
        if not self.corpus_root.exists():
            return ()
        validate_regular_directory(self.corpus_root)
        entries = []
        for path in sorted(self.corpus_root.iterdir(), key=lambda item: item.name):
            if path.name.startswith("."):
                continue
            if not is_digest(path.name):
                raise PersistentStateError(f"unexpected corpus entry: {path.name}")
            entries.append(self._load_entry(path))
        return tuple(entries)

    def save_entry(
        self, encoded: bytes, attributed_regions: Iterable[str] = ()
    ) -> CorpusEntry:
        canonical = self._validate_canonical(encoded, entry=True)
        digest = hashlib.sha256(canonical).hexdigest()
        regions = tuple(sorted(set(attributed_regions)))
        path = self.corpus_root / digest
        if path.exists():
            existing = self._load_entry(path)
            merged = tuple(sorted(set(existing.attributed_regions) | set(regions)))
            if merged != existing.attributed_regions:
                atomic_replace_file(
                    path / "metadata.json",
                    lambda temporary: write_json(
                        temporary, self._corpus_metadata(digest, merged)
                    ),
                )
                return self._load_entry(path)
            return existing
        metadata = self._corpus_metadata(digest, regions)

        def save(temporary: Path) -> None:
            (temporary / self.spec.artifacts.scenario_filename).write_bytes(canonical)
            write_json(temporary / "metadata.json", metadata)

        atomic_save_directory(path, save)
        return self._load_entry(path)

    def save_run(self, run_id: str, metadata: Mapping[str, object]) -> Path:
        if not run_id or Path(run_id).name != run_id:
            raise PersistentStateError("invalid run id")
        expected = {
            "schema_name",
            "schema_version",
            "adapter_id",
            "target_set_id",
            "scenario_sha256",
            "result",
            "seed",
            "batch_index",
            "candidate_count",
            "qemu_count",
            "new_regions",
            "admitted_digests",
        }
        validate_exact_keys(metadata, expected, "run metadata")
        if (
            metadata["schema_name"] != RUN_SCHEMA_NAME
            or metadata["schema_version"] != RUN_SCHEMA_VERSION
            or metadata["adapter_id"] != self.spec.adapter_id
            or metadata["target_set_id"] != self.spec.coverage.target_set_id
            or not is_digest(metadata["scenario_sha256"])
            or not sorted_unique_strings(metadata["new_regions"])
            or not sorted_unique_digests(metadata["admitted_digests"])
        ):
            raise PersistentStateError("run metadata identity or values are invalid")
        path = self.runs_root / run_id
        atomic_save_directory(
            path, lambda temporary: write_json(temporary / "metadata.json", metadata)
        )
        return path

    def load_coverage(self, starry_elf_digest: str) -> Tuple[str, ...]:
        path = self._coverage_path(starry_elf_digest)
        if not path.exists():
            return ()
        metadata = read_json(path)
        expected = {
            "schema_name",
            "schema_version",
            "adapter_id",
            "target_set_id",
            "starry_elf_sha256",
            "covered_regions",
        }
        validate_exact_keys(metadata, expected, "coverage metadata")
        if (
            metadata["schema_name"] != COVERAGE_SCHEMA_NAME
            or metadata["schema_version"] != COVERAGE_SCHEMA_VERSION
            or metadata["adapter_id"] != self.spec.adapter_id
            or metadata["target_set_id"] != self.spec.coverage.target_set_id
            or metadata["starry_elf_sha256"] != starry_elf_digest
            or not sorted_unique_strings(metadata["covered_regions"])
        ):
            raise PersistentStateError("coverage metadata is invalid")
        return tuple(metadata["covered_regions"])

    def save_coverage(self, starry_elf_digest: str, regions: Iterable[str]) -> Path:
        if not is_digest(starry_elf_digest):
            raise PersistentStateError("invalid StarryOS ELF digest")
        metadata = {
            "schema_name": COVERAGE_SCHEMA_NAME,
            "schema_version": COVERAGE_SCHEMA_VERSION,
            "adapter_id": self.spec.adapter_id,
            "target_set_id": self.spec.coverage.target_set_id,
            "starry_elf_sha256": starry_elf_digest,
            "covered_regions": sorted(set(regions)),
        }
        path = self._coverage_path(starry_elf_digest)
        atomic_replace_file(path, lambda temporary: write_json(temporary, metadata))
        return path

    def _load_entry(self, path: Path) -> CorpusEntry:
        validate_directory_shape(
            path, {self.spec.artifacts.scenario_filename, "metadata.json"}
        )
        encoded = (path / self.spec.artifacts.scenario_filename).read_bytes()
        metadata = read_json(path / "metadata.json")
        expected = {
            "schema_name",
            "schema_version",
            "adapter_id",
            "scenario_sha256",
            "target_set_id",
            "generator_version",
            "active",
            "attributed_regions",
        }
        validate_exact_keys(metadata, expected, "corpus metadata")
        digest = hashlib.sha256(encoded).hexdigest()
        if (
            metadata["schema_name"] != CORPUS_SCHEMA_NAME
            or metadata["schema_version"] != CORPUS_SCHEMA_VERSION
            or metadata["adapter_id"] != self.spec.adapter_id
            or metadata["target_set_id"] != self.spec.coverage.target_set_id
            or metadata["generator_version"] != self.spec.generator_version
            or metadata["scenario_sha256"] != digest
            or path.name != digest
            or metadata["active"] is not True
            or not sorted_unique_strings(metadata["attributed_regions"])
        ):
            raise PersistentStateError(f"corpus metadata is invalid: {path}")
        self._validate_canonical(encoded, entry=True)
        return CorpusEntry(
            digest, encoded, tuple(metadata["attributed_regions"]), path
        )

    def _validate_canonical(self, encoded: bytes, *, entry: bool) -> bytes:
        document = self.spec.codec.parse(encoded)
        if entry:
            self.spec.codec.validate_entry(document)
        canonical = self.spec.codec.serialize(document)
        if canonical != encoded:
            raise PersistentStateError("scenario input is not canonical")
        return canonical

    def _corpus_metadata(self, digest: str, regions: Tuple[str, ...]) -> Dict:
        return {
            "schema_name": CORPUS_SCHEMA_NAME,
            "schema_version": CORPUS_SCHEMA_VERSION,
            "adapter_id": self.spec.adapter_id,
            "scenario_sha256": digest,
            "target_set_id": self.spec.coverage.target_set_id,
            "generator_version": self.spec.generator_version,
            "active": True,
            "attributed_regions": list(regions),
        }

    def _coverage_path(self, starry_elf_digest: str) -> Path:
        return self.coverage_root / (
            f"{starry_elf_digest}-{self.spec.coverage.target_set_id}.json"
        )


def atomic_save_directory(path: Path, save: Callable[[Path], None]) -> None:
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{path.name}.", dir=path.parent))
    try:
        save(temporary)
        fsync_tree(temporary)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def atomic_replace_file(path: Path, save: Callable[[Path], None]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        save(temporary)
        with temporary.open("rb") as file:
            os.fsync(file.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def read_json(path: Path) -> Dict:
    if path.is_symlink() or not path.is_file():
        raise PersistentStateError(f"metadata is not a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PersistentStateError(f"cannot read metadata: {path}") from error
    if not isinstance(value, dict):
        raise PersistentStateError(f"metadata is not an object: {path}")
    return value


def write_json(path: Path, metadata: Mapping[str, object]) -> None:
    path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def validate_regular_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise PersistentStateError(f"persistent path is not a regular directory: {path}")


def validate_directory_shape(path: Path, expected_files: set[str]) -> None:
    validate_regular_directory(path)
    actual = set()
    for child in path.iterdir():
        if child.is_symlink() or not child.is_file():
            raise PersistentStateError(f"unexpected persistent path: {child}")
        actual.add(child.name)
    if actual != expected_files:
        raise PersistentStateError(f"persistent directory shape is invalid: {path}")


def validate_exact_keys(
    metadata: Mapping[str, object], expected: set[str], label: str
) -> None:
    if set(metadata) != expected:
        raise PersistentStateError(f"{label} keys are invalid")


def is_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def sorted_unique_strings(value: object) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) and item for item in value)
        and value == sorted(set(value))
    )


def sorted_unique_digests(value: object) -> bool:
    return sorted_unique_strings(value) and all(is_digest(item) for item in value)


def fsync_tree(path: Path) -> None:
    for child in path.iterdir():
        if child.is_dir():
            fsync_tree(child)
        elif child.is_file():
            with child.open("rb") as file:
                os.fsync(file.fileno())
    fsync_directory(path)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
