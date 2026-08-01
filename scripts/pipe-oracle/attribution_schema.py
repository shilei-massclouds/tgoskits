"""Strict validation for persisted attribution jobs and replay evidence."""

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Set, Tuple

from corpus import CorpusProvenance, CorpusValidationError
from coverage import (
    FD_TARGET_SET_ID,
    LEGACY_TARGET_SET_ID,
    TARGET_SET_ID,
    VECTOR_TARGET_SET_ID,
)
from generator import SUPPORTED_CORPUS_GENERATOR_VERSIONS
from scenario import parse_document, serialize_document


LEGACY_ATTRIBUTION_SCHEMA_VERSION = 2
FD_ATTRIBUTION_SCHEMA_VERSION = 3
VECTOR_ATTRIBUTION_SCHEMA_VERSION = 4
ATTRIBUTION_SCHEMA_VERSION = 5
ATTRIBUTION_JOBS_NAME = "attribution-jobs"
FAILURES_NAME = "failures"
METADATA_NAME = "metadata.json"
INPUTS_NAME = "inputs"
REPLAYS_NAME = "replays"
ELFS_NAME = "elfs"
HOST_ORACLE_NAME = "pipe-linux-oracle"

DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
JOB_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
JOB_TEMP_PATTERN = re.compile(r"^\..+\.tmp-.+$")
METADATA_TEMP_PATTERN = re.compile(r"^\.metadata\.json\.tmp-.+$")
REPLAY_TEMP_PATTERN = re.compile(r"^\..+\.tmp-.+$")
JOB_STATES = {"entry-replays", "representative-replay", "completed", "unstable"}


def validate_job_metadata(
    metadata: Dict[str, Any],
    path: Path,
    generator_version: str,
) -> None:
    expected = {
        "schema_version",
        "generator_version",
        "job_id",
        "state",
        "run_recorded",
        "fuzz_seed",
        "batch_index",
        "created_at",
        "updated_at",
        "duration_seconds",
        "attempt",
        "starry_elf_sha256",
        "baseline_regions",
        "target_regions",
        "entries",
        "completed_entry_digests",
        "entry_regions",
        "representative_digests",
        "representative_regions",
        "qemu_replays",
        "elf_transitions",
        "failure_reason",
    }
    schema_version = metadata.get("schema_version")
    if schema_version in (
        FD_ATTRIBUTION_SCHEMA_VERSION,
        VECTOR_ATTRIBUTION_SCHEMA_VERSION,
        ATTRIBUTION_SCHEMA_VERSION,
    ):
        expected.add("target_set_id")
    require_exact_keys(metadata, expected, path)
    if schema_version not in (
        LEGACY_ATTRIBUTION_SCHEMA_VERSION,
        FD_ATTRIBUTION_SCHEMA_VERSION,
        VECTOR_ATTRIBUTION_SCHEMA_VERSION,
        ATTRIBUTION_SCHEMA_VERSION,
    ):
        raise CorpusValidationError(path, "unsupported attribution schema")
    compatible_generator_versions = (
        SUPPORTED_CORPUS_GENERATOR_VERSIONS
        if generator_version == SUPPORTED_CORPUS_GENERATOR_VERSIONS[-1]
        else (generator_version,)
    )
    if metadata["generator_version"] not in compatible_generator_versions:
        raise CorpusValidationError(path, "incompatible generator version")
    if schema_version in (
        FD_ATTRIBUTION_SCHEMA_VERSION,
        VECTOR_ATTRIBUTION_SCHEMA_VERSION,
        ATTRIBUTION_SCHEMA_VERSION,
    ):
        expected_target_set_id = (
            FD_TARGET_SET_ID
            if schema_version == FD_ATTRIBUTION_SCHEMA_VERSION
            else (
                VECTOR_TARGET_SET_ID
                if schema_version == VECTOR_ATTRIBUTION_SCHEMA_VERSION
                else TARGET_SET_ID
            )
        )
        if metadata["target_set_id"] != expected_target_set_id:
            raise CorpusValidationError(path, "unsupported attribution target set")
    if metadata["job_id"] != path.name:
        raise CorpusValidationError(path, "attribution job id mismatch")
    if metadata["state"] not in JOB_STATES:
        raise CorpusValidationError(path, "unsupported attribution state")
    if not isinstance(metadata["run_recorded"], bool):
        raise CorpusValidationError(path, "run_recorded must be boolean")
    if metadata["run_recorded"] and metadata["state"] != "completed":
        raise CorpusValidationError(path, "only completed jobs can record a run")
    for key in ("fuzz_seed", "batch_index", "qemu_replays"):
        if not is_nonnegative_integer(metadata[key]):
            raise CorpusValidationError(path, f"{key} must be nonnegative")
    if not is_positive_integer(metadata["attempt"]):
        raise CorpusValidationError(path, "attempt must be positive")
    if (
        not isinstance(metadata["duration_seconds"], (int, float))
        or isinstance(metadata["duration_seconds"], bool)
        or metadata["duration_seconds"] < 0
    ):
        raise CorpusValidationError(path, "duration must be nonnegative")
    for key in ("created_at", "updated_at"):
        if not isinstance(metadata[key], str) or not metadata[key]:
            raise CorpusValidationError(path, f"{key} must be non-empty")
    if not is_digest(metadata["starry_elf_sha256"]):
        raise CorpusValidationError(path, "invalid Starry ELF digest")
    for key in (
        "baseline_regions",
        "target_regions",
        "completed_entry_digests",
        "representative_digests",
        "representative_regions",
    ):
        if not is_sorted_unique_strings(metadata[key]):
            raise CorpusValidationError(path, f"{key} must be sorted unique strings")

    entry_digests = _validate_entries(metadata["entries"], path)
    _validate_attribution_state(metadata, entry_digests, path)
    _validate_transitions(metadata["elf_transitions"], path)
    failure_reason = metadata["failure_reason"]
    if metadata["state"] == "unstable":
        if not isinstance(failure_reason, str) or not failure_reason:
            raise CorpusValidationError(path, "unstable job lacks a reason")
    elif failure_reason is not None:
        raise CorpusValidationError(path, "active job has a failure reason")


def validate_job_files(path: Path, metadata: Dict[str, Any]) -> None:
    oracle = path / HOST_ORACLE_NAME
    if oracle.is_symlink() or not oracle.is_file():
        raise CorpusValidationError(oracle, "host oracle is not a regular file")
    inputs_dir = path / INPUTS_NAME
    replays_dir = path / REPLAYS_NAME
    elfs_dir = path / ELFS_NAME
    for directory in (inputs_dir, replays_dir, elfs_dir):
        if directory.is_symlink() or not directory.is_dir():
            raise CorpusValidationError(directory, "expected a regular directory")
    expected_inputs = {f"{entry['digest']}.ops" for entry in metadata["entries"]}
    actual_inputs = {item.name for item in inputs_dir.iterdir()}
    if actual_inputs != expected_inputs:
        raise CorpusValidationError(inputs_dir, "attribution input files mismatch")
    for entry in metadata["entries"]:
        input_path = inputs_dir / f"{entry['digest']}.ops"
        if input_path.is_symlink() or not input_path.is_file():
            raise CorpusValidationError(input_path, "input is not a regular file")
        encoded = input_path.read_bytes()
        canonical = serialize_document(parse_document(encoded)).encode("utf-8")
        if encoded != canonical or hashlib.sha256(encoded).hexdigest() != entry["digest"]:
            raise CorpusValidationError(input_path, "input is not canonical")
    batch_replay = replays_dir / batch_label(metadata["attempt"])
    if not batch_replay.is_dir():
        raise CorpusValidationError(batch_replay, "current batch evidence is missing")
    for replay in replays_dir.iterdir():
        if REPLAY_TEMP_PATTERN.fullmatch(replay.name):
            continue
        validate_replay(path, replay)
    for elf_dir in elfs_dir.iterdir():
        if elf_dir.is_symlink() or not elf_dir.is_dir() or not is_digest(elf_dir.name):
            raise CorpusValidationError(elf_dir, "invalid saved ELF directory")
        if {item.name for item in elf_dir.iterdir()} != {"starryos"}:
            raise CorpusValidationError(elf_dir, "saved ELF files mismatch")
        elf_path = elf_dir / "starryos"
        if elf_path.is_symlink() or sha256_file(elf_path) != elf_dir.name:
            raise CorpusValidationError(elf_path, "saved Starry ELF digest mismatch")
    elf = elfs_dir / metadata["starry_elf_sha256"] / "starryos"
    if not elf.is_file() or sha256_file(elf) != metadata["starry_elf_sha256"]:
        raise CorpusValidationError(elf, "saved Starry ELF digest mismatch")


def validate_replay(job_path: Path, replay: Path) -> Dict[str, Any]:
    if replay.is_symlink() or not replay.is_dir():
        raise CorpusValidationError(replay, "invalid replay evidence directory")
    expected_names = {
        "pipe.ops",
        "linux.trace",
        "guest.log",
        "profraws",
        "coverage.json",
    }
    if {item.name for item in replay.iterdir()} != expected_names:
        raise CorpusValidationError(replay, "replay evidence files mismatch")
    for name in ("pipe.ops", "linux.trace", "guest.log", "coverage.json"):
        item = replay / name
        if item.is_symlink() or not item.is_file():
            raise CorpusValidationError(item, "replay evidence is not a regular file")
    profraws_dir = replay / "profraws"
    if profraws_dir.is_symlink() or not profraws_dir.is_dir():
        raise CorpusValidationError(profraws_dir, "invalid profraw directory")
    coverage = read_json(replay / "coverage.json")
    job_metadata = read_json(job_path / METADATA_NAME)
    evidence_version = coverage.get("schema_version")
    evidence_keys = {
        "schema_version",
        "starry_elf_sha256",
        "covered_regions",
        "result_category",
        "ops_sha256",
        "trace_sha256",
        "profraws",
    }
    if evidence_version in (
        FD_ATTRIBUTION_SCHEMA_VERSION,
        VECTOR_ATTRIBUTION_SCHEMA_VERSION,
        ATTRIBUTION_SCHEMA_VERSION,
    ):
        evidence_keys.add("target_set_id")
    require_exact_keys(coverage, evidence_keys, replay)
    if evidence_version not in (
        LEGACY_ATTRIBUTION_SCHEMA_VERSION,
        FD_ATTRIBUTION_SCHEMA_VERSION,
        VECTOR_ATTRIBUTION_SCHEMA_VERSION,
        ATTRIBUTION_SCHEMA_VERSION,
    ):
        raise CorpusValidationError(replay, "unsupported replay evidence schema")
    if evidence_version != job_metadata.get("schema_version"):
        raise CorpusValidationError(replay, "replay evidence schema mismatch")
    if (
        evidence_version
        in (
            FD_ATTRIBUTION_SCHEMA_VERSION,
            VECTOR_ATTRIBUTION_SCHEMA_VERSION,
            ATTRIBUTION_SCHEMA_VERSION,
        )
        and coverage["target_set_id"] != job_target_set_id(job_metadata)
    ):
        raise CorpusValidationError(replay, "replay evidence target set mismatch")
    for key in ("starry_elf_sha256", "ops_sha256", "trace_sha256"):
        if not is_digest(coverage[key]):
            raise CorpusValidationError(replay, f"invalid replay {key}")
    if not is_sorted_unique_strings(coverage["covered_regions"]):
        raise CorpusValidationError(replay, "invalid replay coverage regions")
    if not isinstance(coverage["result_category"], str) or not coverage[
        "result_category"
    ]:
        raise CorpusValidationError(replay, "invalid replay result category")
    if sha256_file(replay / "pipe.ops") != coverage["ops_sha256"]:
        raise CorpusValidationError(replay, "replay pipe.ops digest mismatch")
    if sha256_file(replay / "linux.trace") != coverage["trace_sha256"]:
        raise CorpusValidationError(replay, "replay trace digest mismatch")
    _validate_profraws(profraws_dir, coverage["profraws"], replay)
    saved_elf = job_path / ELFS_NAME / coverage["starry_elf_sha256"] / "starryos"
    if not saved_elf.is_file():
        raise CorpusValidationError(saved_elf, "replay Starry ELF is missing")
    return coverage


def representative_label(attempt: int, digests: Tuple[str, ...]) -> str:
    joined = "\n".join(digests).encode("ascii")
    digest = hashlib.sha256(joined).hexdigest()[:16]
    return f"attempt-{attempt:04d}-representative-{digest}"


def batch_label(attempt: int) -> str:
    return f"attempt-{attempt:04d}-batch"


def entry_label(attempt: int, digest: str) -> str:
    return f"attempt-{attempt:04d}-entry-{digest}"


def job_target_set_id(metadata: Dict[str, Any]) -> str:
    if metadata["schema_version"] == LEGACY_ATTRIBUTION_SCHEMA_VERSION:
        return LEGACY_TARGET_SET_ID
    if metadata["schema_version"] == FD_ATTRIBUTION_SCHEMA_VERSION:
        return FD_TARGET_SET_ID
    if metadata["schema_version"] == VECTOR_ATTRIBUTION_SCHEMA_VERSION:
        return VECTOR_TARGET_SET_ID
    return metadata["target_set_id"]


def require_exact_keys(metadata: Any, expected: Set[str], path: Path) -> None:
    if not isinstance(metadata, dict):
        raise CorpusValidationError(path, "metadata is not a JSON object")
    actual = set(metadata)
    if actual != expected:
        raise CorpusValidationError(
            path,
            "metadata keys mismatch: "
            f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}",
        )


def read_json(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CorpusValidationError(path, f"cannot read JSON: {error}") from error
    if not isinstance(value, dict):
        raise CorpusValidationError(path, "top-level JSON value is not an object")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def is_digest(value: Any) -> bool:
    return isinstance(value, str) and DIGEST_PATTERN.fullmatch(value) is not None


def _validate_entries(entries: Any, path: Path) -> Tuple[str, ...]:
    if not isinstance(entries, list) or not entries:
        raise CorpusValidationError(path, "attribution entries must be non-empty")
    entry_digests = []
    for entry in entries:
        require_exact_keys(entry, {"digest", "origin"}, path)
        if not is_digest(entry["digest"]):
            raise CorpusValidationError(path, "invalid attribution entry digest")
        _validate_origin(entry["origin"], path)
        entry_digests.append(entry["digest"])
    if entry_digests != sorted(set(entry_digests)):
        raise CorpusValidationError(path, "attribution entries are not unique and sorted")
    return tuple(entry_digests)


def _validate_attribution_state(
    metadata: Dict[str, Any],
    entry_digests: Tuple[str, ...],
    path: Path,
) -> None:
    completed = set(metadata["completed_entry_digests"])
    representatives = set(metadata["representative_digests"])
    target = set(metadata["target_regions"])
    if not completed <= set(entry_digests):
        raise CorpusValidationError(path, "completed entry is not a job input")
    if not representatives <= set(entry_digests):
        raise CorpusValidationError(path, "representative is not a job input")
    entry_regions = metadata["entry_regions"]
    if not isinstance(entry_regions, dict) or set(entry_regions) != completed:
        raise CorpusValidationError(path, "entry-region mapping is incomplete")
    for digest, regions in entry_regions.items():
        if not is_digest(digest) or not is_sorted_unique_strings(regions):
            raise CorpusValidationError(path, "invalid entry-region mapping")
        if not set(regions) <= target:
            raise CorpusValidationError(path, "entry mapping escapes target regions")
    if set(metadata["baseline_regions"]) & target:
        raise CorpusValidationError(path, "baseline and target regions overlap")
    if metadata["state"] == "entry-replays":
        if representatives or metadata["representative_regions"]:
            raise CorpusValidationError(path, "entry replay job has representatives")
    elif metadata["state"] in {"representative-replay", "completed"}:
        if target and completed != set(entry_digests):
            raise CorpusValidationError(path, "attribution mapping is not complete")
        if target and not representatives:
            raise CorpusValidationError(path, "target regions lack representatives")
    if metadata["state"] == "representative-replay" and metadata[
        "representative_regions"
    ]:
        raise CorpusValidationError(path, "representative replay is already recorded")
    if metadata["state"] == "completed":
        if target and set(metadata["representative_regions"]) != target:
            raise CorpusValidationError(path, "representative regions are incomplete")
        if not target and any(
            (
                completed,
                representatives,
                metadata["entry_regions"],
                metadata["representative_regions"],
            )
        ):
            raise CorpusValidationError(path, "nonproductive restart retained attribution")


def _validate_origin(metadata: Any, path: Path) -> None:
    require_exact_keys(
        metadata,
        {"source", "parent_digest", "donor_digest", "mutation_type"},
        path,
    )
    try:
        CorpusProvenance(
            metadata["source"],
            metadata["parent_digest"],
            metadata["donor_digest"],
            metadata["mutation_type"],
        ).as_metadata()
    except ValueError as error:
        raise CorpusValidationError(path, str(error)) from error


def _validate_transitions(transitions: Any, path: Path) -> None:
    if not isinstance(transitions, list):
        raise CorpusValidationError(path, "ELF transitions must be a list")
    for transition in transitions:
        require_exact_keys(
            transition,
            {"previous_sha256", "restarted_sha256", "observed_at"},
            path,
        )
        if not is_digest(transition["previous_sha256"]) or not is_digest(
            transition["restarted_sha256"]
        ):
            raise CorpusValidationError(path, "invalid ELF transition digest")
        if transition["previous_sha256"] == transition["restarted_sha256"]:
            raise CorpusValidationError(path, "ELF transition did not change digest")
        if not isinstance(transition["observed_at"], str) or not transition[
            "observed_at"
        ]:
            raise CorpusValidationError(path, "ELF transition lacks timestamp")


def _validate_profraws(
    profraws_dir: Path,
    profraw_metadata: Any,
    replay: Path,
) -> None:
    if not isinstance(profraw_metadata, list):
        raise CorpusValidationError(replay, "profraw metadata must be a list")
    expected_profraws = set()
    for item in profraw_metadata:
        require_exact_keys(item, {"name", "sha256", "size"}, replay)
        if (
            not isinstance(item["name"], str)
            or not item["name"]
            or "/" in item["name"]
            or not is_digest(item["sha256"])
            or not is_nonnegative_integer(item["size"])
        ):
            raise CorpusValidationError(replay, "invalid profraw metadata")
        profraw_path = profraws_dir / item["name"]
        if (
            profraw_path.is_symlink()
            or not profraw_path.is_file()
            or profraw_path.stat().st_size != item["size"]
            or sha256_file(profraw_path) != item["sha256"]
        ):
            raise CorpusValidationError(profraw_path, "profraw evidence mismatch")
        expected_profraws.add(item["name"])
    if {item.name for item in profraws_dir.iterdir()} != expected_profraws:
        raise CorpusValidationError(profraws_dir, "profraw files mismatch")


def is_sorted_unique_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) and item for item in value)
        and value == sorted(set(value))
    )


def is_nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def is_positive_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


__all__ = [
    "ATTRIBUTION_JOBS_NAME",
    "ATTRIBUTION_SCHEMA_VERSION",
    "FD_ATTRIBUTION_SCHEMA_VERSION",
    "VECTOR_ATTRIBUTION_SCHEMA_VERSION",
    "ELFS_NAME",
    "FAILURES_NAME",
    "HOST_ORACLE_NAME",
    "INPUTS_NAME",
    "JOB_ID_PATTERN",
    "JOB_TEMP_PATTERN",
    "METADATA_NAME",
    "METADATA_TEMP_PATTERN",
    "REPLAYS_NAME",
    "batch_label",
    "entry_label",
    "is_digest",
    "read_json",
    "representative_label",
    "require_exact_keys",
    "sha256_file",
    "validate_job_files",
    "validate_job_metadata",
    "validate_replay",
]
