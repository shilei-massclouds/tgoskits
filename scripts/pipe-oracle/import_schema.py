"""Strict schema validation for resumable syzkaller import jobs."""

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Set, Tuple

from corpus_errors import CorpusValidationError
from scenario import parse_document, serialize_document


IMPORT_JOB_SCHEMA_VERSION = 1
IMPORT_JOBS_NAME = "import-jobs"
METADATA_NAME = "metadata.json"
SOURCES_NAME = "sources"
CONVERSIONS_NAME = "conversions"
INPUTS_NAME = "inputs"

JOB_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
TEMP_PATTERN = re.compile(r"^\..+\.tmp-.+$")
JOB_STATES = {
    "classified",
    "host-stability",
    "qemu-batches",
    "attribution",
    "minimization",
    "completed",
    "failed",
}


def validate_job_metadata(metadata: Dict[str, Any], path: Path) -> None:
    expected = {
        "schema_version",
        "job_id",
        "state",
        "run_recorded",
        "syzkaller_revision",
        "importer_version",
        "created_at",
        "updated_at",
        "duration_seconds",
        "settings",
        "sources",
        "canonical_inputs",
        "batches",
        "next_batch_index",
        "qemu_runs",
        "attribution_job_ids",
        "minimization_job_ids",
        "result_category",
        "failure_reason",
    }
    require_exact_keys(metadata, expected, path / METADATA_NAME)
    if metadata["schema_version"] != IMPORT_JOB_SCHEMA_VERSION:
        raise CorpusValidationError(path, "unsupported import-job schema")
    if metadata["job_id"] != path.name or not JOB_ID_PATTERN.fullmatch(path.name):
        raise CorpusValidationError(path, "import job id mismatch")
    state = metadata["state"]
    if state not in JOB_STATES:
        raise CorpusValidationError(path, "unsupported import job state")
    if not isinstance(metadata["run_recorded"], bool):
        raise CorpusValidationError(path, "run_recorded must be boolean")
    if metadata["run_recorded"] and state != "completed":
        raise CorpusValidationError(path, "only completed imports can record a run")
    if (
        not isinstance(metadata["syzkaller_revision"], str)
        or re.fullmatch(r"[0-9a-f]{40}", metadata["syzkaller_revision"]) is None
    ):
        raise CorpusValidationError(path, "invalid syzkaller revision")
    if not isinstance(metadata["importer_version"], str) or not metadata["importer_version"]:
        raise CorpusValidationError(path, "invalid importer version")
    for key in ("created_at", "updated_at"):
        if not isinstance(metadata[key], str) or not metadata[key]:
            raise CorpusValidationError(path, f"{key} must be non-empty")
    duration = metadata["duration_seconds"]
    if (
        not isinstance(duration, (int, float))
        or isinstance(duration, bool)
        or duration < 0
    ):
        raise CorpusValidationError(path, "duration must be nonnegative")
    settings = _validate_settings(metadata["settings"], path)
    source_ids, accepted = _validate_sources(metadata["sources"], path)
    canonical_digests = _validate_canonical_inputs(
        metadata["canonical_inputs"],
        source_ids,
        accepted,
        path,
    )
    _validate_batches(metadata["batches"], canonical_digests, path)
    if (
        not is_nonnegative_integer(metadata["next_batch_index"])
        or metadata["next_batch_index"] > len(metadata["batches"])
    ):
        raise CorpusValidationError(path, "next batch index is invalid")
    if (
        not is_nonnegative_integer(metadata["qemu_runs"])
        or metadata["qemu_runs"] > settings["max_qemu"]
    ):
        raise CorpusValidationError(path, "import QEMU count is invalid")
    for key in ("attribution_job_ids", "minimization_job_ids"):
        if not is_sorted_unique_strings(metadata[key]):
            raise CorpusValidationError(path, f"{key} must be sorted unique strings")
    result_category = metadata["result_category"]
    failure_reason = metadata["failure_reason"]
    if state in {"completed", "failed"}:
        if not isinstance(result_category, str) or not result_category:
            raise CorpusValidationError(path, "terminal import lacks a result category")
    elif result_category is not None:
        raise CorpusValidationError(path, "active import has a result category")
    if state == "failed":
        if not isinstance(failure_reason, str) or not failure_reason:
            raise CorpusValidationError(path, "failed import lacks a reason")
    elif failure_reason is not None:
        raise CorpusValidationError(path, "non-failed import has a failure reason")


def validate_job_files(path: Path, metadata: Dict[str, Any]) -> None:
    expected_names = {METADATA_NAME, SOURCES_NAME, CONVERSIONS_NAME, INPUTS_NAME}
    names = {
        item.name for item in path.iterdir() if not TEMP_PATTERN.fullmatch(item.name)
    }
    if names != expected_names:
        raise CorpusValidationError(path, "import job files mismatch")
    for name in (SOURCES_NAME, CONVERSIONS_NAME, INPUTS_NAME):
        directory = path / name
        if directory.is_symlink() or not directory.is_dir():
            raise CorpusValidationError(directory, "expected a regular directory")

    expected_sources = {
        f"{source['evidence_id']}.syz"
        for source in metadata["sources"]
        if source["program_sha256"] is not None
    }
    source_dir = path / SOURCES_NAME
    if {item.name for item in source_dir.iterdir()} != expected_sources:
        raise CorpusValidationError(source_dir, "import source files mismatch")
    for source in metadata["sources"]:
        if source["program_sha256"] is None:
            continue
        source_path = source_dir / f"{source['evidence_id']}.syz"
        require_regular_file(source_path)
        if (
            source_path.stat().st_size != source["program_size"]
            or sha256_file(source_path) != source["program_sha256"]
        ):
            raise CorpusValidationError(source_path, "import source digest mismatch")

    conversion_dir = path / CONVERSIONS_NAME
    expected_conversions = {
        f"{source['evidence_id']}.json" for source in metadata["sources"]
    }
    if {item.name for item in conversion_dir.iterdir()} != expected_conversions:
        raise CorpusValidationError(conversion_dir, "conversion evidence files mismatch")
    for source in metadata["sources"]:
        conversion = conversion_dir / f"{source['evidence_id']}.json"
        require_regular_file(conversion)
        if (
            conversion.stat().st_size != source["conversion_log_size"]
            or sha256_file(conversion) != source["conversion_log_sha256"]
        ):
            raise CorpusValidationError(conversion, "conversion log digest mismatch")

    inputs_dir = path / INPUTS_NAME
    expected_inputs = {
        f"{item['digest']}.ops" for item in metadata["canonical_inputs"]
    }
    if {item.name for item in inputs_dir.iterdir()} != expected_inputs:
        raise CorpusValidationError(inputs_dir, "canonical import inputs mismatch")
    for item in metadata["canonical_inputs"]:
        input_path = inputs_dir / f"{item['digest']}.ops"
        require_regular_file(input_path)
        encoded = input_path.read_bytes()
        try:
            canonical = serialize_document(parse_document(encoded)).encode("utf-8")
        except (UnicodeError, ValueError) as error:
            raise CorpusValidationError(input_path, str(error)) from error
        if encoded != canonical or sha256_bytes(encoded) != item["digest"]:
            raise CorpusValidationError(input_path, "import input is not canonical")


def read_json(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CorpusValidationError(path, f"cannot read JSON: {error}") from error
    if not isinstance(value, dict):
        raise CorpusValidationError(path, "top-level JSON value is not an object")
    return value


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


def require_regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise CorpusValidationError(path, "expected a regular file")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_digest(value: Any) -> bool:
    return isinstance(value, str) and DIGEST_PATTERN.fullmatch(value) is not None


def is_nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def is_positive_integer(value: Any) -> bool:
    return is_nonnegative_integer(value) and value > 0


def is_sorted_unique_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) and item for item in value)
        and value == sorted(set(value))
    )


def _validate_settings(settings: Any, path: Path) -> Dict[str, int]:
    require_exact_keys(
        settings,
        {"host_repetitions", "batch_size", "max_qemu"},
        path,
    )
    if not is_positive_integer(settings["host_repetitions"]):
        raise CorpusValidationError(path, "host repetitions must be positive")
    if not is_positive_integer(settings["batch_size"]):
        raise CorpusValidationError(path, "batch size must be positive")
    if not is_nonnegative_integer(settings["max_qemu"]):
        raise CorpusValidationError(path, "max QEMU must be nonnegative")
    return settings


def _validate_sources(
    sources: Any,
    path: Path,
) -> Tuple[Set[str], Dict[str, str]]:
    if not isinstance(sources, list):
        raise CorpusValidationError(path, "import sources must be a list")
    evidence_ids = []
    accepted = {}
    for source in sources:
        require_exact_keys(
            source,
            {
                "evidence_id",
                "path",
                "status",
                "program_sha256",
                "program_size",
                "conversion_log_sha256",
                "conversion_log_size",
                "canonical_digest",
                "rejection_category",
                "rejection_detail",
            },
            path,
        )
        evidence_id = source["evidence_id"]
        if not isinstance(evidence_id, str) or re.fullmatch(r"[0-9]{6}", evidence_id) is None:
            raise CorpusValidationError(path, "invalid import evidence id")
        evidence_ids.append(evidence_id)
        if not isinstance(source["path"], str) or not source["path"]:
            raise CorpusValidationError(path, "invalid import source path")
        if source["status"] not in {"accepted", "rejected"}:
            raise CorpusValidationError(path, "invalid import source status")
        if not is_digest(source["conversion_log_sha256"]) or not is_positive_integer(
            source["conversion_log_size"]
        ):
            raise CorpusValidationError(path, "invalid conversion log metadata")
        program_digest = source["program_sha256"]
        program_size = source["program_size"]
        if program_digest is None:
            if program_size is not None and not is_nonnegative_integer(program_size):
                raise CorpusValidationError(path, "invalid import program size")
        elif not is_digest(program_digest) or not is_nonnegative_integer(program_size):
            raise CorpusValidationError(path, "invalid import program metadata")
        if source["status"] == "accepted":
            if program_digest is None or not is_digest(source["canonical_digest"]):
                raise CorpusValidationError(path, "accepted source lacks canonical input")
            if source["rejection_category"] is not None or source["rejection_detail"] is not None:
                raise CorpusValidationError(path, "accepted source retains a rejection")
            accepted[evidence_id] = source["canonical_digest"]
        else:
            if source["canonical_digest"] is not None:
                raise CorpusValidationError(path, "rejected source has canonical input")
            if not isinstance(source["rejection_category"], str) or not source[
                "rejection_category"
            ]:
                raise CorpusValidationError(path, "rejected source lacks a category")
            if not isinstance(source["rejection_detail"], str) or not source[
                "rejection_detail"
            ]:
                raise CorpusValidationError(path, "rejected source lacks detail")
    if evidence_ids != sorted(set(evidence_ids)):
        raise CorpusValidationError(path, "import evidence ids are not sorted and unique")
    return set(evidence_ids), accepted


def _validate_canonical_inputs(
    inputs: Any,
    source_ids: Set[str],
    accepted: Dict[str, str],
    path: Path,
) -> Set[str]:
    if not isinstance(inputs, list):
        raise CorpusValidationError(path, "canonical inputs must be a list")
    digests = []
    mapped_sources = set()
    for item in inputs:
        require_exact_keys(
            item,
            {"digest", "source_evidence_ids", "host_status", "host_trace_sha256"},
            path,
        )
        digest = item["digest"]
        if not is_digest(digest):
            raise CorpusValidationError(path, "invalid canonical import digest")
        source_evidence_ids = item["source_evidence_ids"]
        if (
            not is_sorted_unique_strings(source_evidence_ids)
            or not source_evidence_ids
            or not set(source_evidence_ids) <= source_ids
        ):
            raise CorpusValidationError(path, "invalid canonical source mapping")
        if any(accepted.get(source_id) != digest for source_id in source_evidence_ids):
            raise CorpusValidationError(path, "canonical source mapping digest mismatch")
        mapped_sources.update(source_evidence_ids)
        if item["host_status"] not in {"pending", "stable", "unstable"}:
            raise CorpusValidationError(path, "invalid host stability status")
        trace_digest = item["host_trace_sha256"]
        if item["host_status"] == "pending":
            if trace_digest is not None:
                raise CorpusValidationError(path, "pending host input has a trace")
        elif not is_digest(trace_digest):
            raise CorpusValidationError(path, "host result lacks a trace digest")
        digests.append(digest)
    if digests != sorted(set(digests)):
        raise CorpusValidationError(path, "canonical inputs are not sorted and unique")
    if mapped_sources != set(accepted):
        raise CorpusValidationError(path, "accepted source mapping is incomplete")
    return set(digests)


def _validate_batches(batches: Any, canonical_digests: Set[str], path: Path) -> None:
    if not isinstance(batches, list):
        raise CorpusValidationError(path, "import batches must be a list")
    batched = set()
    for index, batch in enumerate(batches):
        require_exact_keys(
            batch,
            {
                "index",
                "digests",
                "state",
                "result_category",
                "qemu_runs",
                "attribution_job_id",
                "minimization_job_ids",
            },
            path,
        )
        if batch["index"] != index:
            raise CorpusValidationError(path, "import batch indices are not dense")
        if (
            not is_sorted_unique_strings(batch["digests"])
            or not batch["digests"]
            or not set(batch["digests"]) <= canonical_digests
            or batched & set(batch["digests"])
        ):
            raise CorpusValidationError(path, "invalid import batch digests")
        batched.update(batch["digests"])
        if batch["state"] not in {"pending", "completed", "failed"}:
            raise CorpusValidationError(path, "invalid import batch state")
        if not is_nonnegative_integer(batch["qemu_runs"]):
            raise CorpusValidationError(path, "invalid import batch QEMU count")
        if batch["state"] == "pending":
            if any(
                value
                for value in (
                    batch["result_category"],
                    batch["attribution_job_id"],
                    batch["minimization_job_ids"],
                    batch["qemu_runs"],
                )
            ):
                raise CorpusValidationError(path, "pending batch retains progress")
        elif not isinstance(batch["result_category"], str) or not batch[
            "result_category"
        ]:
            raise CorpusValidationError(path, "finished batch lacks a result category")
        if batch["attribution_job_id"] is not None and (
            not isinstance(batch["attribution_job_id"], str)
            or not JOB_ID_PATTERN.fullmatch(batch["attribution_job_id"])
        ):
            raise CorpusValidationError(path, "invalid attribution job id")
        if not is_sorted_unique_strings(batch["minimization_job_ids"]):
            raise CorpusValidationError(path, "invalid minimization job ids")


__all__ = [
    "CONVERSIONS_NAME",
    "IMPORT_JOBS_NAME",
    "IMPORT_JOB_SCHEMA_VERSION",
    "INPUTS_NAME",
    "JOB_ID_PATTERN",
    "JOB_STATES",
    "METADATA_NAME",
    "SOURCES_NAME",
    "TEMP_PATTERN",
    "read_json",
    "sha256_bytes",
    "sha256_file",
    "validate_job_files",
    "validate_job_metadata",
]
