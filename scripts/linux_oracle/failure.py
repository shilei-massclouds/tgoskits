"""Strict failure artifact capture and replay-time integrity validation."""

import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

from .persistence import (
    PersistentStateError,
    atomic_save_directory,
    is_digest,
    read_json,
    validate_exact_keys,
    write_json,
)
from .spec import AdapterSpec


SCHEMA_NAME = "linux-oracle-failure"
SCHEMA_VERSION = 1


@dataclass(frozen=True)
class FailureArtifact:
    path: Path
    metadata: Dict
    scenario_path: Path
    trace_path: Path
    host_elf_path: Path
    starry_elf_path: Path
    guest_log_path: Path
    profraw_paths: Tuple[Path, ...]

    @property
    def ops_path(self) -> Path:
        return self.scenario_path


def save_failure(
    spec: AdapterSpec,
    destination: Path,
    *,
    scenario_path: Path,
    trace_path: Path,
    host_elf_path: Path,
    starry_elf_path: Path,
    guest_log: str,
    profraw_paths: Iterable[Path],
    result_category: str,
    mismatch: Optional[Dict],
) -> FailureArtifact:
    sources = {
        spec.artifacts.scenario_filename: scenario_path,
        spec.artifacts.trace_filename: trace_path,
        spec.artifacts.host_executable_filename: host_elf_path,
        spec.artifacts.starry_elf_filename: starry_elf_path,
    }
    for name, path in sources.items():
        validate_regular_file(path, f"failure source {name}")
    encoded = scenario_path.read_bytes()
    validate_canonical(spec, encoded)
    scenario_digest = hashlib.sha256(encoded).hexdigest()
    profraws = tuple(profraw_paths)
    if len({path.name for path in profraws}) != len(profraws):
        raise PersistentStateError("failure profraw names must be unique")
    for path in profraws:
        validate_regular_file(path, "failure profraw")
        validate_filename(path.name)
    artifact_metadata = {
        name: evidence(path) for name, path in sources.items()
    }
    metadata = {
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "adapter_id": spec.adapter_id,
        "scenario_sha256": scenario_digest,
        "target_set_id": spec.coverage.target_set_id,
        "result_category": result_category,
        "mismatch": mismatch,
        "artifacts": artifact_metadata,
        "profraws": [
            {"name": path.name, **evidence(path)} for path in profraws
        ],
    }

    def save(temporary: Path) -> None:
        for name, path in sources.items():
            shutil.copy2(path, temporary / name)
        guest_log_path = temporary / spec.artifacts.guest_log_filename
        guest_log_path.write_text(guest_log, encoding="utf-8")
        metadata["artifacts"][spec.artifacts.guest_log_filename] = evidence(
            guest_log_path
        )
        if profraws:
            profraw_root = temporary / spec.artifacts.profraw_directory
            profraw_root.mkdir()
            for path in profraws:
                shutil.copy2(path, profraw_root / path.name)
        write_json(temporary / "metadata.json", metadata)

    atomic_save_directory(destination, save)
    return load_failure(spec, destination)


def load_failure(spec: AdapterSpec, path: Path) -> FailureArtifact:
    if path.is_symlink() or not path.is_dir():
        raise PersistentStateError("failure path is not a regular directory")
    path = path.resolve()
    metadata = read_json(path / "metadata.json")
    expected_keys = {
        "schema_name",
        "schema_version",
        "adapter_id",
        "scenario_sha256",
        "target_set_id",
        "result_category",
        "mismatch",
        "artifacts",
        "profraws",
    }
    validate_exact_keys(metadata, expected_keys, "failure metadata")
    if (
        metadata["schema_name"] != SCHEMA_NAME
        or metadata["schema_version"] != SCHEMA_VERSION
        or metadata["adapter_id"] != spec.adapter_id
        or metadata["target_set_id"] != spec.coverage.target_set_id
        or not is_digest(metadata["scenario_sha256"])
        or not isinstance(metadata["artifacts"], dict)
        or not isinstance(metadata["profraws"], list)
    ):
        raise PersistentStateError("failure metadata identity is invalid")
    artifact_names = {
        spec.artifacts.scenario_filename,
        spec.artifacts.trace_filename,
        spec.artifacts.host_executable_filename,
        spec.artifacts.starry_elf_filename,
        spec.artifacts.guest_log_filename,
    }
    if set(metadata["artifacts"]) != artifact_names:
        raise PersistentStateError("failure artifact manifest is invalid")
    allowed = artifact_names | {"metadata.json"}
    if metadata["profraws"]:
        allowed.add(spec.artifacts.profraw_directory)
    actual = set()
    for child in path.iterdir():
        if child.is_symlink():
            raise PersistentStateError("failure artifact contains a symlink")
        actual.add(child.name)
    if actual != allowed:
        raise PersistentStateError("failure directory shape is invalid")
    for name, recorded in metadata["artifacts"].items():
        validate_evidence(path / name, recorded, include_name=False)
    profraw_paths = []
    expected_profraw_names = set()
    for recorded in metadata["profraws"]:
        if not isinstance(recorded, dict) or set(recorded) != {
            "name",
            "sha256",
            "size",
        }:
            raise PersistentStateError("failure profraw evidence is invalid")
        name = recorded["name"]
        validate_filename(name)
        if name in expected_profraw_names:
            raise PersistentStateError("failure profraw manifest contains duplicates")
        expected_profraw_names.add(name)
        profraw_path = path / spec.artifacts.profraw_directory / name
        validate_evidence(profraw_path, recorded, include_name=True)
        profraw_paths.append(profraw_path)
    if metadata["profraws"]:
        profraw_root = path / spec.artifacts.profraw_directory
        if profraw_root.is_symlink() or not profraw_root.is_dir():
            raise PersistentStateError("failure profraw root is invalid")
        if {child.name for child in profraw_root.iterdir()} != expected_profraw_names:
            raise PersistentStateError("failure profraw directory shape is invalid")
    scenario_path = path / spec.artifacts.scenario_filename
    encoded = scenario_path.read_bytes()
    if hashlib.sha256(encoded).hexdigest() != metadata["scenario_sha256"]:
        raise PersistentStateError("failure scenario digest is invalid")
    validate_canonical(spec, encoded)
    return FailureArtifact(
        path,
        metadata,
        scenario_path,
        path / spec.artifacts.trace_filename,
        path / spec.artifacts.host_executable_filename,
        path / spec.artifacts.starry_elf_filename,
        path / spec.artifacts.guest_log_filename,
        tuple(profraw_paths),
    )


def validate_canonical(spec: AdapterSpec, encoded: bytes) -> None:
    """Validate canonical execution bytes without corpus-entry size limits."""
    document = spec.codec.parse(encoded)
    if spec.codec.serialize(document) != encoded:
        raise PersistentStateError("failure scenario is not canonical")


def evidence(path: Path) -> Dict:
    return {"sha256": file_sha256(path), "size": path.stat().st_size}


def validate_evidence(path: Path, recorded: Dict, *, include_name: bool) -> None:
    expected = {"sha256", "size"} | ({"name"} if include_name else set())
    if not isinstance(recorded, dict) or set(recorded) != expected:
        raise PersistentStateError(f"invalid artifact evidence: {path.name}")
    validate_regular_file(path, "artifact")
    if recorded["size"] != path.stat().st_size or recorded["sha256"] != file_sha256(
        path
    ):
        raise PersistentStateError(f"artifact digest or size mismatch: {path.name}")


def validate_regular_file(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise PersistentStateError(f"{label} is not a regular file: {path}")


def validate_filename(value: object) -> None:
    if not isinstance(value, str) or not value or Path(value).name != value:
        raise PersistentStateError("artifact filename is invalid")


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
