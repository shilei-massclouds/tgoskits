"""Strict validation for persistent minimization jobs and evidence."""

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Set

from corpus_errors import CorpusValidationError
from corpus import CorpusProvenance
from coverage import FD_TARGET_SET_ID, LEGACY_TARGET_SET_ID, TARGET_SET_ID
from generator import SUPPORTED_CORPUS_GENERATOR_VERSIONS
from fingerprint import MismatchFingerprint
from guest_result import GuestResultCategory
from reducer import OperationOrigin, ReductionInput, StructuredReducer
from scenario import ScenarioDocument, parse_document, serialize_document


LEGACY_MINIMIZATION_SCHEMA_VERSION = 1
FD_MINIMIZATION_SCHEMA_VERSION = 2
MINIMIZATION_SCHEMA_VERSION = 3
MINIMIZATION_JOBS_NAME = "minimization-jobs"
JOB_STATES = {
    "validating",
    "reducing",
    "final-proof",
    "completed",
    "stale",
    "unstable",
}
JOB_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
TEMP_PATTERN = re.compile(r"^\..+\.tmp-.+$")
METADATA_NAME = "metadata.json"
INPUTS_NAME = "inputs"
BEST_NAME = "best"
EVIDENCE_NAME = "evidence"
STARRY_ELF_NAME = "starryos"
HOST_ORACLE_NAME = "pipe-linux-oracle"
RESULT_CATEGORIES = {category.value for category in GuestResultCategory}


def validate_job_metadata(
    metadata: Dict[str, Any],
    path: Path,
    generator_version: str,
    expected_job_id: str | None = None,
) -> None:
    expected_keys = {
        "schema_version",
        "generator_version",
        "job_id",
        "kind",
        "source",
        "state",
        "completion",
        "run_recorded",
        "created_at",
        "updated_at",
        "duration_seconds",
        "max_candidate_qemu",
        "candidate_qemu",
        "validation_qemu",
        "proof_qemu",
        "starry_elf_sha256",
        "host_oracle_sha256",
        "expected_fingerprint",
        "items",
        "schedule_cursor",
        "attempts",
        "proofs",
        "validation",
        "failure_reason",
    }
    schema_version = metadata.get("schema_version")
    if schema_version in (FD_MINIMIZATION_SCHEMA_VERSION, MINIMIZATION_SCHEMA_VERSION):
        expected_keys.add("target_set_id")
    require_exact_keys(metadata, expected_keys, path)
    if schema_version not in (
        LEGACY_MINIMIZATION_SCHEMA_VERSION,
        FD_MINIMIZATION_SCHEMA_VERSION,
        MINIMIZATION_SCHEMA_VERSION,
    ):
        raise CorpusValidationError(path, "unsupported minimization schema")
    compatible_generator_versions = (
        SUPPORTED_CORPUS_GENERATOR_VERSIONS
        if generator_version == SUPPORTED_CORPUS_GENERATOR_VERSIONS[-1]
        else (generator_version,)
    )
    if metadata["generator_version"] not in compatible_generator_versions:
        raise CorpusValidationError(path, "incompatible generator version")
    if schema_version in (FD_MINIMIZATION_SCHEMA_VERSION, MINIMIZATION_SCHEMA_VERSION):
        expected_target_set_id = (
            FD_TARGET_SET_ID
            if schema_version == FD_MINIMIZATION_SCHEMA_VERSION
            else TARGET_SET_ID
        )
        if metadata["target_set_id"] != expected_target_set_id:
            raise CorpusValidationError(path, "unsupported minimization target set")
    job_id = path.name if expected_job_id is None else expected_job_id
    if metadata["job_id"] != job_id or not JOB_ID_PATTERN.fullmatch(job_id):
        raise CorpusValidationError(path, "minimization job id mismatch")
    kind = metadata["kind"]
    if kind not in {"coverage", "mismatch"}:
        raise CorpusValidationError(path, "unsupported minimization kind")
    _validate_source(metadata["source"], path)
    state = metadata["state"]
    if state not in JOB_STATES:
        raise CorpusValidationError(path, "unsupported minimization state")
    completion = metadata["completion"]
    if state == "completed":
        if completion not in {"minimized", "already-minimal", "budget-limited"}:
            raise CorpusValidationError(path, "completed minimization lacks a mode")
    elif completion is not None:
        raise CorpusValidationError(path, "unfinished minimization has a completion mode")
    if not isinstance(metadata["run_recorded"], bool):
        raise CorpusValidationError(path, "run_recorded must be boolean")
    if metadata["run_recorded"] and state != "completed":
        raise CorpusValidationError(path, "only completed jobs can record a run")
    for key in ("created_at", "updated_at"):
        if not isinstance(metadata[key], str) or not metadata[key]:
            raise CorpusValidationError(path, f"{key} must be non-empty")
    if (
        not isinstance(metadata["duration_seconds"], (int, float))
        or isinstance(metadata["duration_seconds"], bool)
        or metadata["duration_seconds"] < 0
    ):
        raise CorpusValidationError(path, "duration must be nonnegative")
    for key in (
        "max_candidate_qemu",
        "candidate_qemu",
        "validation_qemu",
        "proof_qemu",
        "schedule_cursor",
    ):
        if not is_nonnegative_integer(metadata[key]):
            raise CorpusValidationError(path, f"{key} must be nonnegative")
    if metadata["candidate_qemu"] > metadata["max_candidate_qemu"]:
        raise CorpusValidationError(path, "candidate QEMU count exceeds budget")
    if metadata["validation_qemu"] > 1 or metadata["proof_qemu"] > 2:
        raise CorpusValidationError(path, "validation/proof QEMU count is invalid")
    for key in ("starry_elf_sha256", "host_oracle_sha256"):
        if not is_digest(metadata[key]):
            raise CorpusValidationError(path, f"invalid {key}")
    fingerprint = metadata["expected_fingerprint"]
    if kind == "mismatch":
        try:
            MismatchFingerprint.from_metadata(fingerprint)
        except ValueError as error:
            raise CorpusValidationError(path, str(error)) from error
    elif fingerprint is not None:
        raise CorpusValidationError(path, "coverage job has a mismatch fingerprint")
    items = _validate_items(metadata["items"], kind, path)
    if metadata["schedule_cursor"] >= len(items):
        raise CorpusValidationError(path, "schedule cursor is outside minimization items")
    _validate_attempts(metadata["attempts"], len(items), path)
    _validate_proofs(metadata["proofs"], path)
    _validate_validation(metadata["validation"], path)
    _validate_state_progress(metadata, path)
    reason = metadata["failure_reason"]
    if state in {"stale", "unstable"}:
        if not isinstance(reason, str) or not reason:
            raise CorpusValidationError(path, "terminal minimization lacks a reason")
    elif reason is not None:
        raise CorpusValidationError(path, "active minimization has a failure reason")


def validate_job_files(path: Path, metadata: Dict[str, Any]) -> None:
    expected_names = {
        METADATA_NAME,
        INPUTS_NAME,
        BEST_NAME,
        EVIDENCE_NAME,
        STARRY_ELF_NAME,
        HOST_ORACLE_NAME,
    }
    names = {
        item.name for item in path.iterdir() if not TEMP_PATTERN.fullmatch(item.name)
    }
    if names != expected_names:
        raise CorpusValidationError(path, f"minimization job files mismatch: {sorted(names)}")
    for name in (METADATA_NAME, STARRY_ELF_NAME, HOST_ORACLE_NAME):
        require_regular_file(path / name)
    for name in (INPUTS_NAME, BEST_NAME, EVIDENCE_NAME):
        directory = path / name
        if directory.is_symlink() or not directory.is_dir():
            raise CorpusValidationError(directory, "expected a regular directory")
    if sha256_file(path / STARRY_ELF_NAME) != metadata["starry_elf_sha256"]:
        raise CorpusValidationError(path / STARRY_ELF_NAME, "saved Starry ELF digest mismatch")
    if sha256_file(path / HOST_ORACLE_NAME) != metadata["host_oracle_sha256"]:
        raise CorpusValidationError(path / HOST_ORACLE_NAME, "saved host oracle digest mismatch")
    expected_inputs = {f"{item['original_digest']}.ops" for item in metadata["items"]}
    inputs_dir = path / INPUTS_NAME
    if {item.name for item in inputs_dir.iterdir()} != expected_inputs:
        raise CorpusValidationError(inputs_dir, "minimization input files mismatch")
    for item in metadata["items"]:
        original = inputs_dir / f"{item['original_digest']}.ops"
        _validate_canonical_document(original, item["original_digest"])
    best_dir = path / BEST_NAME
    expected_item_dirs = {f"{item['index']:04d}" for item in metadata["items"]}
    actual_item_dirs = {
        entry.name
        for entry in best_dir.iterdir()
        if not TEMP_PATTERN.fullmatch(entry.name)
    }
    if actual_item_dirs != expected_item_dirs:
        raise CorpusValidationError(best_dir, "minimization best item directories mismatch")
    for item in metadata["items"]:
        item_dir = best_dir / f"{item['index']:04d}"
        if item_dir.is_symlink() or not item_dir.is_dir():
            raise CorpusValidationError(item_dir, "invalid best item directory")
        for checkpoint in item_dir.iterdir():
            if TEMP_PATTERN.fullmatch(checkpoint.name):
                continue
            if not is_digest(checkpoint.name):
                raise CorpusValidationError(checkpoint, "invalid best checkpoint digest")
            _validate_checkpoint_files(checkpoint, checkpoint.name)
        checkpoint = (
            item_dir / item["best_digest"]
        )
        _validate_best_checkpoint(checkpoint, item)
    for evidence in (path / EVIDENCE_NAME).iterdir():
        if TEMP_PATTERN.fullmatch(evidence.name):
            continue
        _validate_evidence(evidence, metadata)


def job_target_set_id(metadata: Dict[str, Any]) -> str:
    if metadata["schema_version"] == LEGACY_MINIMIZATION_SCHEMA_VERSION:
        return LEGACY_TARGET_SET_ID
    if metadata["schema_version"] == FD_MINIMIZATION_SCHEMA_VERSION:
        return FD_TARGET_SET_ID
    return metadata["target_set_id"]


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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def is_digest(value: Any) -> bool:
    return isinstance(value, str) and DIGEST_PATTERN.fullmatch(value) is not None


def is_nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def require_regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise CorpusValidationError(path, "expected a regular file")


def _validate_source(source: Any, path: Path) -> None:
    require_exact_keys(source, {"kind", "path", "id"}, path)
    if source["kind"] not in {"failure", "attribution"}:
        raise CorpusValidationError(path, "invalid minimization source kind")
    if not isinstance(source["path"], str) or not source["path"]:
        raise CorpusValidationError(path, "invalid minimization source path")
    if not isinstance(source["id"], str) or not source["id"]:
        raise CorpusValidationError(path, "invalid minimization source id")


def _validate_items(items: Any, kind: str, path: Path) -> tuple:
    if not isinstance(items, list) or not items:
        raise CorpusValidationError(path, "minimization items must be non-empty")
    if kind == "mismatch" and len(items) != 1:
        raise CorpusValidationError(path, "mismatch job must contain one item")
    originals = []
    for expected_index, item in enumerate(items):
        require_exact_keys(
            item,
            {
                "index",
                "original_digest",
                "best_digest",
                "original_size",
                "best_size",
                "responsibility_regions",
                "critical_origin",
                "reducer",
                "origin",
            },
            path,
        )
        if item["index"] != expected_index:
            raise CorpusValidationError(path, "minimization item indices are not dense")
        if not is_digest(item["original_digest"]) or not is_digest(item["best_digest"]):
            raise CorpusValidationError(path, "invalid minimization item digest")
        if not is_nonnegative_integer(item["original_size"]) or not is_nonnegative_integer(item["best_size"]):
            raise CorpusValidationError(path, "invalid minimization item size")
        regions = item["responsibility_regions"]
        if (
            not isinstance(regions, list)
            or regions != sorted(set(regions))
            or not all(isinstance(region, str) and region for region in regions)
        ):
            raise CorpusValidationError(path, "invalid responsibility regions")
        critical = item["critical_origin"]
        if critical is not None and (
            not isinstance(critical, list)
            or len(critical) != 2
            or not all(is_nonnegative_integer(value) for value in critical)
        ):
            raise CorpusValidationError(path, "invalid critical operation origin")
        origin = item["origin"]
        require_exact_keys(
            origin,
            {"source", "parent_digest", "donor_digest", "mutation_type"},
            path,
        )
        try:
            CorpusProvenance(
                origin["source"],
                origin["parent_digest"],
                origin["donor_digest"],
                origin["mutation_type"],
            ).as_metadata()
        except ValueError as error:
            raise CorpusValidationError(path, str(error)) from error
        try:
            StructuredReducer.restore(
                _placeholder_reduction_input(item["best_digest"]),
                item["reducer"],
            )
        except (ValueError, CorpusValidationError):
            # The real document is validated in validate_job_files. Here only the
            # exact snapshot shape is checked without duplicating the codec.
            _validate_reducer_snapshot_shape(item["reducer"], path)
        originals.append(item["original_digest"])
    if originals != sorted(set(originals)):
        raise CorpusValidationError(path, "minimization items are not digest sorted")
    return tuple(originals)


def _validate_reducer_snapshot_shape(snapshot: Any, path: Path) -> None:
    require_exact_keys(
        snapshot,
        {"stage_index", "candidate_index", "seen_digests", "critical_origin"},
        path,
    )
    if (
        not is_nonnegative_integer(snapshot["stage_index"])
        or snapshot["stage_index"] > len(StructuredReducer._STAGES)
        or not is_nonnegative_integer(snapshot["candidate_index"])
        or not isinstance(snapshot["seen_digests"], list)
        or snapshot["seen_digests"] != sorted(set(snapshot["seen_digests"]))
        or not all(is_digest(digest) for digest in snapshot["seen_digests"])
    ):
        raise CorpusValidationError(path, "invalid reducer snapshot")


def _validate_attempts(attempts: Any, item_count: int, path: Path) -> None:
    if not isinstance(attempts, list):
        raise CorpusValidationError(path, "minimization attempts must be a list")
    for sequence, attempt in enumerate(attempts, start=1):
        require_exact_keys(
            attempt,
            {
                "sequence",
                "item_index",
                "candidate_digest",
                "transform",
                "result_category",
                "decision",
                "region_summary",
                "fingerprint",
                "evidence_digest",
            },
            path,
        )
        if attempt["sequence"] != sequence:
            raise CorpusValidationError(path, "minimization attempt sequence is invalid")
        if not is_nonnegative_integer(attempt["item_index"]) or attempt["item_index"] >= item_count:
            raise CorpusValidationError(path, "minimization attempt item is invalid")
        if not is_digest(attempt["candidate_digest"]):
            raise CorpusValidationError(path, "minimization candidate digest is invalid")
        if not isinstance(attempt["transform"], str) or not attempt["transform"]:
            raise CorpusValidationError(path, "minimization transform is invalid")
        if attempt["decision"] not in {"accept", "reject", "exceptional"}:
            raise CorpusValidationError(path, "minimization decision is invalid")
        if attempt["result_category"] not in RESULT_CATEGORIES:
            raise CorpusValidationError(path, "minimization result category is invalid")
        regions = attempt["region_summary"]
        if (
            not isinstance(regions, list)
            or regions != sorted(set(regions))
            or not all(isinstance(region, str) and region for region in regions)
        ):
            raise CorpusValidationError(path, "minimization region summary is invalid")
        if attempt["fingerprint"] is not None:
            try:
                MismatchFingerprint.from_metadata(attempt["fingerprint"])
            except ValueError as error:
                raise CorpusValidationError(path, str(error)) from error
        if attempt["evidence_digest"] is not None and not is_digest(attempt["evidence_digest"]):
            raise CorpusValidationError(path, "minimization evidence digest is invalid")


def _validate_proofs(proofs: Any, path: Path) -> None:
    if not isinstance(proofs, list) or len(proofs) > 2:
        raise CorpusValidationError(path, "minimization proofs are invalid")
    for index, proof in enumerate(proofs, start=1):
        require_exact_keys(
            proof,
            {
                "index",
                "result_category",
                "decision",
                "satisfied",
                "evidence_digest",
            },
            path,
        )
        if proof["index"] != index or not isinstance(proof["satisfied"], bool):
            raise CorpusValidationError(path, "minimization proof index is invalid")
        if proof["decision"] not in {"accept", "reject", "exceptional"}:
            raise CorpusValidationError(path, "minimization proof decision is invalid")
        if proof["satisfied"] != (proof["decision"] == "accept"):
            raise CorpusValidationError(path, "minimization proof decision is inconsistent")
        if proof["result_category"] not in RESULT_CATEGORIES:
            raise CorpusValidationError(path, "minimization proof result is invalid")
        if not is_digest(proof["evidence_digest"]):
            raise CorpusValidationError(path, "minimization proof evidence is invalid")


def _validate_validation(validation: Any, path: Path) -> None:
    if validation is None:
        return
    require_exact_keys(
        validation,
        {"result_category", "satisfied", "evidence_digest"},
        path,
    )
    if validation["result_category"] not in RESULT_CATEGORIES:
        raise CorpusValidationError(path, "minimization validation result is invalid")
    if not isinstance(validation["satisfied"], bool) or not is_digest(validation["evidence_digest"]):
        raise CorpusValidationError(path, "minimization validation evidence is invalid")


def _validate_evidence(path: Path, job_metadata: Dict[str, Any]) -> None:
    if path.is_symlink() or not path.is_dir():
        raise CorpusValidationError(path, "invalid minimization evidence directory")
    expected = {"pipe.ops", "linux.trace", "guest.log", "profraws", "result.json"}
    if {item.name for item in path.iterdir()} != expected:
        raise CorpusValidationError(path, "minimization evidence files mismatch")
    for name in ("pipe.ops", "linux.trace", "guest.log", "result.json"):
        require_regular_file(path / name)
    profraws_dir = path / "profraws"
    if profraws_dir.is_symlink() or not profraws_dir.is_dir():
        raise CorpusValidationError(profraws_dir, "invalid evidence profraw directory")
    result = read_json(path / "result.json")
    evidence_version = result.get("schema_version")
    expected_keys = {
        "schema_version",
        "starry_elf_sha256",
        "result_category",
        "covered_regions",
        "fingerprint",
        "ops_sha256",
        "trace_sha256",
        "guest_log_sha256",
        "profraws",
    }
    if evidence_version in (FD_MINIMIZATION_SCHEMA_VERSION, MINIMIZATION_SCHEMA_VERSION):
        expected_keys.add("target_set_id")
    require_exact_keys(result, expected_keys, path)
    if evidence_version not in (
        LEGACY_MINIMIZATION_SCHEMA_VERSION,
        FD_MINIMIZATION_SCHEMA_VERSION,
        MINIMIZATION_SCHEMA_VERSION,
    ):
        raise CorpusValidationError(path, "unsupported minimization evidence schema")
    if evidence_version != job_metadata["schema_version"]:
        raise CorpusValidationError(path, "minimization evidence schema mismatch")
    if (
        evidence_version in (FD_MINIMIZATION_SCHEMA_VERSION, MINIMIZATION_SCHEMA_VERSION)
        and result["target_set_id"] != job_target_set_id(job_metadata)
    ):
        raise CorpusValidationError(path, "minimization evidence target set mismatch")
    if result["starry_elf_sha256"] != job_metadata["starry_elf_sha256"]:
        raise CorpusValidationError(path, "minimization evidence ELF mismatch")
    if result["result_category"] not in RESULT_CATEGORIES:
        raise CorpusValidationError(path, "invalid minimization evidence result")
    regions = result["covered_regions"]
    if (
        not isinstance(regions, list)
        or regions != sorted(set(regions))
        or not all(isinstance(region, str) and region for region in regions)
    ):
        raise CorpusValidationError(path, "invalid minimization evidence regions")
    if result["fingerprint"] is not None:
        try:
            MismatchFingerprint.from_metadata(result["fingerprint"])
        except ValueError as error:
            raise CorpusValidationError(path, str(error)) from error
    for name, key in (
        ("pipe.ops", "ops_sha256"),
        ("linux.trace", "trace_sha256"),
        ("guest.log", "guest_log_sha256"),
    ):
        if not is_digest(result[key]) or sha256_file(path / name) != result[key]:
            raise CorpusValidationError(path / name, "minimization evidence digest mismatch")
    profraws = result["profraws"]
    if not isinstance(profraws, list):
        raise CorpusValidationError(profraws_dir, "invalid profraw metadata")
    expected_profraws = []
    for item in profraws:
        require_exact_keys(item, {"name", "sha256", "size"}, path)
        if (
            not isinstance(item["name"], str)
            or not item["name"]
            or "/" in item["name"]
            or not is_digest(item["sha256"])
            or not is_nonnegative_integer(item["size"])
        ):
            raise CorpusValidationError(path, "invalid profraw metadata")
        profraw = profraws_dir / item["name"]
        require_regular_file(profraw)
        if profraw.stat().st_size != item["size"] or sha256_file(profraw) != item["sha256"]:
            raise CorpusValidationError(profraw, "profraw evidence mismatch")
        expected_profraws.append(item["name"])
    if expected_profraws != sorted(set(expected_profraws)):
        raise CorpusValidationError(profraws_dir, "profraw evidence is not sorted")
    if {item.name for item in profraws_dir.iterdir()} != set(expected_profraws):
        raise CorpusValidationError(profraws_dir, "profraw evidence files mismatch")


def _validate_best_checkpoint(path: Path, item: Dict[str, Any]) -> None:
    _validate_checkpoint_files(path, item["best_digest"])
    if (path / "pipe.ops").stat().st_size != item["best_size"]:
        raise CorpusValidationError(path, "best checkpoint size mismatch")
    origins = read_json(path / "origins.json")
    document = parse_document((path / "pipe.ops").read_bytes())
    reduction_input = ReductionInput(
        document,
        tuple(
            tuple(OperationOrigin(*origin) for origin in scenario_origins)
            for scenario_origins in origins["origins"]
        ),
    )
    try:
        StructuredReducer.restore(reduction_input, item["reducer"])
    except ValueError as error:
        raise CorpusValidationError(path, str(error)) from error


def _validate_checkpoint_files(path: Path, digest: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise CorpusValidationError(path, "best checkpoint is missing")
    if {entry.name for entry in path.iterdir()} != {"pipe.ops", "origins.json"}:
        raise CorpusValidationError(path, "best checkpoint files mismatch")
    _validate_canonical_document(path / "pipe.ops", digest)
    origins = read_json(path / "origins.json")
    require_exact_keys(origins, {"origins"}, path)
    document = parse_document((path / "pipe.ops").read_bytes())
    _validate_origins(origins["origins"], document, path)


def _validate_state_progress(metadata: Dict[str, Any], path: Path) -> None:
    state = metadata["state"]
    validation = metadata["validation"]
    attempts = metadata["attempts"]
    proofs = metadata["proofs"]
    if len(attempts) != metadata["candidate_qemu"]:
        raise CorpusValidationError(path, "candidate QEMU count does not match attempts")
    if metadata["proof_qemu"] > len(proofs):
        raise CorpusValidationError(path, "proof QEMU count exceeds saved proofs")
    if state == "validating":
        if (
            attempts
            or proofs
            or metadata["proof_qemu"] != 0
        ):
            raise CorpusValidationError(path, "validating job has committed progress")
        if validation is None and metadata["validation_qemu"] != 0:
            raise CorpusValidationError(path, "unvalidated job counted a QEMU run")
        if validation is not None and validation["satisfied"]:
            raise CorpusValidationError(path, "successful validation did not advance state")
        return
    if state in {"reducing", "final-proof", "completed"}:
        if validation is None or not validation["satisfied"]:
            raise CorpusValidationError(path, "active minimization lacks validation")
        if metadata["validation_qemu"] != 1:
            raise CorpusValidationError(path, "successful validation must count one QEMU")
    if state in {"final-proof", "completed"} and any(
        attempt["decision"] == "exceptional" for attempt in attempts
    ):
        raise CorpusValidationError(path, "minimization advanced after an exceptional candidate")
    if state == "reducing" and (proofs or metadata["proof_qemu"] != 0):
        raise CorpusValidationError(path, "reducing job has proof progress")
    if state == "completed":
        if len(proofs) != 2 or not all(proof["satisfied"] for proof in proofs):
            raise CorpusValidationError(path, "completed minimization lacks two proofs")
        if metadata["proof_qemu"] != 2:
            raise CorpusValidationError(path, "completed proofs must count two QEMU runs")


def _validate_origins(origins: Any, document: ScenarioDocument, path: Path) -> None:
    if not isinstance(origins, list) or len(origins) != len(document.scenarios):
        raise CorpusValidationError(path, "best checkpoint origins mismatch")
    for scenario_origins, scenario in zip(origins, document.scenarios):
        if not isinstance(scenario_origins, list) or len(scenario_origins) != len(scenario.operations):
            raise CorpusValidationError(path, "best checkpoint operation origins mismatch")
        for origin in scenario_origins:
            if (
                not isinstance(origin, list)
                or len(origin) != 2
                or not all(is_nonnegative_integer(value) for value in origin)
            ):
                raise CorpusValidationError(path, "best checkpoint origin is invalid")


def _validate_canonical_document(path: Path, digest: str) -> None:
    require_regular_file(path)
    encoded = path.read_bytes()
    try:
        canonical = serialize_document(parse_document(encoded)).encode("utf-8")
    except (UnicodeError, ValueError) as error:
        raise CorpusValidationError(path, str(error)) from error
    if encoded != canonical or hashlib.sha256(encoded).hexdigest() != digest:
        raise CorpusValidationError(path, "minimization input is not canonical")


def _placeholder_reduction_input(_digest: str) -> ReductionInput:
    document = parse_document("version 1\nscenario generated-0001\npipe2 0 1\n")
    return ReductionInput.initial(document)


__all__ = [
    "BEST_NAME",
    "EVIDENCE_NAME",
    "FD_MINIMIZATION_SCHEMA_VERSION",
    "HOST_ORACLE_NAME",
    "INPUTS_NAME",
    "JOB_ID_PATTERN",
    "JOB_STATES",
    "METADATA_NAME",
    "MINIMIZATION_JOBS_NAME",
    "MINIMIZATION_SCHEMA_VERSION",
    "STARRY_ELF_NAME",
    "TEMP_PATTERN",
    "is_digest",
    "read_json",
    "sha256_file",
    "validate_job_files",
    "validate_job_metadata",
]
