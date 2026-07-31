import shutil
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from common import (
    FAILURES_DIR,
    atomic_save,
    build_metadata,
    load_metadata,
    save_metadata,
    sha256_file,
    METADATA_NAME,
)
from corpus_errors import CorpusValidationError
from fingerprint import MismatchFingerprint
from guest_result import GuestResultCategory
from scenario import parse_document, serialize_document


FAILURE_SCHEMA_VERSION = 2
_FAILURE_V2_KEYS = {
    "schema_version",
    "generator_version",
    "fuzz_seed",
    "batch_index",
    "command",
    "git_commit",
    "git_dirty",
    "host_uname",
    "guest_result_category",
    "failure_category",
    "mismatch_fingerprint",
    "host_oracle_sha256",
    "host_oracle_size",
    "starry_elf_sha256",
    "starry_elf_size",
    "ops_sha256",
    "ops_size",
    "trace_sha256",
    "trace_size",
    "guest_log_sha256",
    "guest_log_size",
    "input",
    "inputs",
    "profraws",
}


def save_failure(
    failure_id: str,
    input_path: Optional[Path],
    ops_text: str,
    elf_path: Path,
    trace_path: Path,
    guest_log: str,
    profraws: Optional[List[Path]],
    metadata_overrides: Dict,
):
    dest = FAILURES_DIR / failure_id
    atomic_save(dest, lambda tmp: _write_failure(
        tmp, input_path, ops_text, elf_path, trace_path,
        guest_log, profraws, metadata_overrides,
    ))
    return dest


def build_failure_metadata_v2(
    failure_dir: Path,
    *,
    generator_version: str,
    fuzz_seed: Optional[int],
    batch_index: int,
    command: str,
    result_category: GuestResultCategory,
    mismatch_fingerprint: Optional[MismatchFingerprint],
    failure_category: Optional[str] = None,
) -> Dict[str, Any]:
    """Build strict metadata after every v2 evidence file has been persisted."""
    if not isinstance(result_category, GuestResultCategory):
        result_category = GuestResultCategory(result_category)
    if result_category == GuestResultCategory.SEMANTIC_MISMATCH:
        if mismatch_fingerprint is None:
            raise ValueError("semantic mismatch failure requires a fingerprint")
        fingerprint_metadata = mismatch_fingerprint.as_metadata()
    elif mismatch_fingerprint is not None:
        raise ValueError("non-mismatch failure cannot retain a fingerprint")
    else:
        fingerprint_metadata = None

    base = build_metadata(
        seed=fuzz_seed,
        batch_index=batch_index,
        generator_version=generator_version,
        input_path=None,
        elf_path=None,
        ops_path=None,
        trace_path=None,
        guest_log_path=None,
        profraw_paths=None,
        command=command,
        result_category=result_category.value,
    )
    host_oracle = failure_dir / "pipe-linux-oracle"
    starry_elf = failure_dir / "starryos"
    ops = failure_dir / "pipe.ops"
    trace = failure_dir / "linux.trace"
    guest_log = failure_dir / "guest.log"
    for path in (host_oracle, ops, trace, guest_log):
        if not path.is_file():
            raise FileNotFoundError(f"failure evidence is missing: {path}")
    if result_category == GuestResultCategory.SEMANTIC_MISMATCH and not starry_elf.is_file():
        raise FileNotFoundError(f"semantic mismatch Starry ELF is missing: {starry_elf}")

    input_metadata = _optional_file_metadata(failure_dir / "input.bin")
    inputs = _directory_file_metadata(failure_dir / "inputs")
    if input_metadata is not None and inputs:
        raise ValueError("failure artifact cannot contain both input.bin and inputs")
    profraws = _directory_file_metadata(failure_dir / "profraws")
    return {
        "schema_version": FAILURE_SCHEMA_VERSION,
        "generator_version": generator_version,
        "fuzz_seed": fuzz_seed,
        "batch_index": batch_index,
        "command": command,
        "git_commit": base["git_commit"],
        "git_dirty": base["git_dirty"],
        "host_uname": base["host_uname"],
        "guest_result_category": result_category.value,
        "failure_category": failure_category or result_category.value,
        "mismatch_fingerprint": fingerprint_metadata,
        "host_oracle_sha256": sha256_file(host_oracle),
        "host_oracle_size": host_oracle.stat().st_size,
        "starry_elf_sha256": sha256_file(starry_elf) if starry_elf.is_file() else None,
        "starry_elf_size": starry_elf.stat().st_size if starry_elf.is_file() else None,
        "ops_sha256": sha256_file(ops),
        "ops_size": ops.stat().st_size,
        "trace_sha256": sha256_file(trace),
        "trace_size": trace.stat().st_size,
        "guest_log_sha256": sha256_file(guest_log),
        "guest_log_size": guest_log.stat().st_size,
        "input": input_metadata,
        "inputs": inputs,
        "profraws": profraws,
    }


def _write_failure(
    tmp: Path,
    input_path: Optional[Path],
    ops_text: str,
    elf_path: Path,
    trace_path: Path,
    guest_log: str,
    profraws: Optional[List[Path]],
    metadata_overrides: Dict,
):
    if input_path and input_path.exists():
        shutil.copy2(input_path, tmp / "input.bin")
    (tmp / "pipe.ops").write_text(ops_text)
    shutil.copy2(elf_path, tmp / "pipe-linux-oracle")
    shutil.copy2(trace_path, tmp / "linux.trace")
    (tmp / "guest.log").write_text(guest_log)
    if profraws:
        profraw_dir = tmp / "profraws"
        profraw_dir.mkdir(exist_ok=True)
        for p in profraws:
            if p.exists():
                shutil.copy2(p, profraw_dir / p.name)
    meta_overrides = dict(metadata_overrides)
    meta_overrides.setdefault("input_path", tmp / "input.bin" if (tmp / "input.bin").exists() else None)
    meta_overrides.setdefault("elf_path", tmp / "pipe-linux-oracle")
    meta_overrides.setdefault("ops_path", tmp / "pipe.ops")
    meta_overrides.setdefault("trace_path", tmp / "linux.trace")
    meta_overrides.setdefault("guest_log_path", tmp / "guest.log")
    if profraws:
        meta_overrides.setdefault("profraw_paths", list((tmp / "profraws").iterdir()))
    meta = build_metadata(**meta_overrides)
    save_metadata(tmp, meta)


def validate_failure(dir_path: Path) -> Dict:
    required = ["pipe.ops", "linux.trace", "pipe-linux-oracle", "guest.log", METADATA_NAME]
    for name in required:
        path = dir_path / name
        if path.is_symlink() or not path.is_file():
            raise CorpusValidationError(path, "failure evidence is not a regular file")
    meta = load_metadata(dir_path)
    assert meta.get("schema_version") is not None
    if meta["schema_version"] == FAILURE_SCHEMA_VERSION:
        _validate_failure_v2(dir_path, meta)
        return meta
    if meta["schema_version"] != 1:
        raise CorpusValidationError(dir_path, "unsupported failure schema")
    for key in ["input", "elf", "ops", "trace", "guest_log"]:
        sha_key = f"{key}_sha256"
        if sha_key in meta:
            file_key = key if key != "guest_log" else "guest_log"
            path = dir_path / {
                "input": "input.bin",
                "elf": "pipe-linux-oracle",
                "ops": "pipe.ops",
                "trace": "linux.trace",
                "guest_log": "guest.log",
            }[key]
            if path.exists():
                actual = sha256_file(path)
                assert actual == meta[sha_key], f"{sha_key} mismatch for {path}"
    _validate_x86_64_elf(dir_path / "pipe-linux-oracle", legacy=True)
    return meta


def _validate_failure_v2(dir_path: Path, metadata: Dict[str, Any]) -> None:
    _require_exact_keys(metadata, _FAILURE_V2_KEYS, dir_path / METADATA_NAME)
    category = _validate_failure_v2_scalars(metadata, dir_path)
    required_files = {
        "pipe-linux-oracle",
        "pipe.ops",
        "linux.trace",
        "guest.log",
        METADATA_NAME,
    }
    allowed_files = required_files | {"starryos", "input.bin", "inputs", "profraws"}
    unexpected = {entry.name for entry in dir_path.iterdir()} - allowed_files
    if unexpected:
        raise CorpusValidationError(
            dir_path,
            f"unexpected failure artifact files: {sorted(unexpected)}",
        )
    for name in required_files:
        _require_regular_file(dir_path / name)
    if metadata["starry_elf_sha256"] is not None:
        _require_regular_file(dir_path / "starryos")
    elif (dir_path / "starryos").exists() or (dir_path / "starryos").is_symlink():
        raise CorpusValidationError(dir_path / "starryos", "unexpected Starry ELF")
    if category == GuestResultCategory.SEMANTIC_MISMATCH:
        if metadata["starry_elf_sha256"] is None:
            raise CorpusValidationError(dir_path, "semantic mismatch lacks a Starry ELF")
        try:
            MismatchFingerprint.from_metadata(metadata["mismatch_fingerprint"])
        except ValueError as error:
            raise CorpusValidationError(dir_path, str(error)) from error
    elif metadata["mismatch_fingerprint"] is not None:
        raise CorpusValidationError(dir_path, "non-mismatch failure has a fingerprint")

    _validate_file_metadata(
        dir_path / "pipe-linux-oracle",
        metadata["host_oracle_sha256"],
        metadata["host_oracle_size"],
    )
    _validate_file_metadata(
        dir_path / "pipe.ops",
        metadata["ops_sha256"],
        metadata["ops_size"],
    )
    _validate_file_metadata(
        dir_path / "linux.trace",
        metadata["trace_sha256"],
        metadata["trace_size"],
    )
    _validate_file_metadata(
        dir_path / "guest.log",
        metadata["guest_log_sha256"],
        metadata["guest_log_size"],
    )
    if metadata["starry_elf_sha256"] is not None:
        _validate_file_metadata(
            dir_path / "starryos",
            metadata["starry_elf_sha256"],
            metadata["starry_elf_size"],
        )
    encoded = (dir_path / "pipe.ops").read_bytes()
    try:
        canonical = serialize_document(parse_document(encoded)).encode("utf-8")
    except (UnicodeError, ValueError) as error:
        raise CorpusValidationError(dir_path / "pipe.ops", str(error)) from error
    if encoded != canonical:
        raise CorpusValidationError(dir_path / "pipe.ops", "pipe.ops is not canonical")

    _validate_optional_artifact_file(dir_path, "input.bin", metadata["input"])
    _validate_artifact_directory(dir_path, "inputs", metadata["inputs"])
    _validate_artifact_directory(dir_path, "profraws", metadata["profraws"])
    if metadata["input"] is not None and metadata["inputs"]:
        raise CorpusValidationError(dir_path, "failure has duplicate input layouts")
    _validate_x86_64_elf(dir_path / "pipe-linux-oracle")
    if metadata["starry_elf_sha256"] is not None:
        _validate_x86_64_elf(dir_path / "starryos")


def _validate_failure_v2_scalars(
    metadata: Dict[str, Any],
    path: Path,
) -> GuestResultCategory:
    if metadata["schema_version"] != FAILURE_SCHEMA_VERSION:
        raise CorpusValidationError(path, "unsupported failure schema")
    if not isinstance(metadata["generator_version"], str) or not metadata["generator_version"]:
        raise CorpusValidationError(path, "invalid generator version")
    if metadata["fuzz_seed"] is not None and not _is_nonnegative_integer(metadata["fuzz_seed"]):
        raise CorpusValidationError(path, "invalid fuzz seed")
    if not _is_nonnegative_integer(metadata["batch_index"]):
        raise CorpusValidationError(path, "invalid batch index")
    if not isinstance(metadata["command"], str) or not metadata["command"]:
        raise CorpusValidationError(path, "invalid failure command")
    if not isinstance(metadata["failure_category"], str) or not metadata["failure_category"]:
        raise CorpusValidationError(path, "invalid failure category")
    if not isinstance(metadata["git_commit"], str) or not metadata["git_commit"]:
        raise CorpusValidationError(path, "invalid git commit")
    if not isinstance(metadata["git_dirty"], bool):
        raise CorpusValidationError(path, "invalid git dirty state")
    host = metadata["host_uname"]
    _require_exact_keys(
        host,
        {"system", "release", "version", "machine", "page_size"},
        path,
    )
    if not all(isinstance(host[key], str) for key in ("system", "release", "version", "machine")):
        raise CorpusValidationError(path, "invalid host uname")
    if not _is_positive_integer(host["page_size"]):
        raise CorpusValidationError(path, "invalid host page size")
    try:
        category = GuestResultCategory(metadata["guest_result_category"])
    except (TypeError, ValueError) as error:
        raise CorpusValidationError(path, "invalid guest result category") from error
    for digest_key, size_key in (
        ("host_oracle_sha256", "host_oracle_size"),
        ("ops_sha256", "ops_size"),
        ("trace_sha256", "trace_size"),
        ("guest_log_sha256", "guest_log_size"),
    ):
        if not _is_digest(metadata[digest_key]) or not _is_nonnegative_integer(metadata[size_key]):
            raise CorpusValidationError(path, f"invalid {digest_key}")
    starry_digest = metadata["starry_elf_sha256"]
    starry_size = metadata["starry_elf_size"]
    if (starry_digest is None) != (starry_size is None):
        raise CorpusValidationError(path, "incomplete Starry ELF metadata")
    if starry_digest is not None and (
        not _is_digest(starry_digest) or not _is_nonnegative_integer(starry_size)
    ):
        raise CorpusValidationError(path, "invalid Starry ELF metadata")
    return category


def _optional_file_metadata(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"artifact input is not a regular file: {path}")
    return _named_file_metadata(path)


def _directory_file_metadata(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"artifact evidence is not a directory: {path}")
    metadata = []
    for item in sorted(path.iterdir(), key=lambda candidate: candidate.name):
        if item.is_symlink() or not item.is_file():
            raise ValueError(f"artifact evidence is not a regular file: {item}")
        metadata.append(_named_file_metadata(item))
    return metadata


def _named_file_metadata(path: Path) -> Dict[str, Any]:
    return {
        "name": path.name,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def _validate_optional_artifact_file(
    root: Path,
    name: str,
    metadata: Any,
) -> None:
    path = root / name
    if metadata is None:
        if path.exists() or path.is_symlink():
            raise CorpusValidationError(path, "unrecorded artifact file")
        return
    _validate_named_metadata(metadata, path)
    if metadata["name"] != name:
        raise CorpusValidationError(path, "artifact file name mismatch")
    _validate_file_metadata(path, metadata["sha256"], metadata["size"])


def _validate_artifact_directory(
    root: Path,
    name: str,
    entries: Any,
) -> None:
    if not isinstance(entries, list):
        raise CorpusValidationError(root / name, "artifact file metadata is not a list")
    directory = root / name
    if not entries:
        if directory.exists() or directory.is_symlink():
            if directory.is_symlink() or not directory.is_dir() or any(directory.iterdir()):
                raise CorpusValidationError(directory, "unexpected artifact directory")
        return
    if directory.is_symlink() or not directory.is_dir():
        raise CorpusValidationError(directory, "artifact directory is missing")
    expected = []
    for entry in entries:
        _validate_named_metadata(entry, directory)
        if "/" in entry["name"] or entry["name"] in {".", ".."}:
            raise CorpusValidationError(directory, "invalid artifact file name")
        path = directory / entry["name"]
        _validate_file_metadata(path, entry["sha256"], entry["size"])
        expected.append(entry["name"])
    if expected != sorted(set(expected)):
        raise CorpusValidationError(directory, "artifact files are not unique and sorted")
    if {item.name for item in directory.iterdir()} != set(expected):
        raise CorpusValidationError(directory, "artifact directory files mismatch")


def _validate_named_metadata(metadata: Any, path: Path) -> None:
    _require_exact_keys(metadata, {"name", "sha256", "size"}, path)
    if (
        not isinstance(metadata["name"], str)
        or not metadata["name"]
        or not _is_digest(metadata["sha256"])
        or not _is_nonnegative_integer(metadata["size"])
    ):
        raise CorpusValidationError(path, "invalid artifact file metadata")


def _validate_file_metadata(path: Path, digest: str, size: int) -> None:
    _require_regular_file(path)
    if path.stat().st_size != size:
        raise CorpusValidationError(path, "artifact file size mismatch")
    if sha256_file(path) != digest:
        raise CorpusValidationError(path, "artifact file digest mismatch")


def _require_regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise CorpusValidationError(path, "artifact evidence is not a regular file")


def _require_exact_keys(metadata: Any, expected: Set[str], path: Path) -> None:
    if not isinstance(metadata, dict):
        raise CorpusValidationError(path, "metadata is not a JSON object")
    actual = set(metadata)
    if actual != expected:
        raise CorpusValidationError(
            path,
            "metadata keys mismatch: "
            f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}",
        )


def _validate_x86_64_elf(path: Path, *, legacy: bool = False) -> None:
    with path.open("rb") as executable:
        header = executable.read(20)
    def reject(reason: str) -> None:
        if legacy:
            raise AssertionError(reason)
        raise CorpusValidationError(path, reason)
    if header[:4] != b"\x7fELF":
        reject("not an ELF")
    if len(header) < 20 or header[4] != 2:
        reject("not 64-bit ELF")
    byte_order = "<" if header[5] == 1 else ">"
    if struct.unpack(f"{byte_order}H", header[18:20])[0] != 62:
        reject("not x86_64 ELF")


def _is_nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_positive_integer(value: Any) -> bool:
    return _is_nonnegative_integer(value) and value > 0


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
