"""Check-only input discovery and classification for restricted ``.syz`` files."""

import hashlib
import json
import os
import stat
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from scenario import canonical_digest, serialize_document
from syz_converter import (
    IMPORTER_VERSION,
    SUPPORTED_SYZKALLER_REVISION,
    SyzConversionError,
    convert_syz_program,
)
from syz_parser import SyzSyntaxError, parse_syz_program


MAX_SYZ_FILE_BYTES = 64 * 1024


@dataclass(frozen=True)
class DiscoveredInput:
    path: Path
    discovery_rejection: Optional[str] = None


class InputDiscoveryError(RuntimeError):
    pass


def build_check_report(
    paths: Iterable[Path],
    syzkaller_revision: str,
) -> Tuple[Dict[str, object], bool]:
    """Discover and classify inputs; return the report and infrastructure status."""

    inputs = discover_inputs(paths)
    reports = []
    infrastructure_failed = False
    for discovered in inputs:
        report, input_infrastructure_failed = classify_input(
            discovered,
            syzkaller_revision,
        )
        reports.append(report)
        infrastructure_failed |= input_infrastructure_failed

    rejection_counts = Counter(
        report["rejection_category"]
        for report in reports
        if report["status"] == "rejected"
    )
    accepted = [report for report in reports if report["status"] == "accepted"]
    return (
        {
            "schema_version": 1,
            "mode": "check-only",
            "syzkaller_revision": syzkaller_revision,
            "supported_syzkaller_revision": SUPPORTED_SYZKALLER_REVISION,
            "importer_version": IMPORTER_VERSION,
            "summary": {
                "total_inputs": len(reports),
                "accepted": len(accepted),
                "rejected": len(reports) - len(accepted),
                "unique_canonical": len(
                    {report["canonical_digest"] for report in accepted}
                ),
                "rejection_categories": dict(sorted(rejection_counts.items())),
            },
            "inputs": reports,
        },
        infrastructure_failed,
    )


def discover_inputs(paths: Iterable[Path]) -> Tuple[DiscoveredInput, ...]:
    discovered: Dict[str, DiscoveredInput] = {}
    for original in paths:
        path = original.absolute()
        key = str(path)
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            raise InputDiscoveryError(f"cannot inspect input {path}: {error}") from error
        if stat.S_ISLNK(mode):
            discovered[key] = DiscoveredInput(path, "symlink")
        elif stat.S_ISREG(mode):
            rejection = None if path.suffix == ".syz" else "not-syz-file"
            discovered[key] = DiscoveredInput(path, rejection)
        elif stat.S_ISDIR(mode):
            _discover_directory(path, discovered)
        else:
            discovered[key] = DiscoveredInput(path, "not-regular-file")
    return tuple(discovered[key] for key in sorted(discovered))


def classify_input(
    discovered: DiscoveredInput,
    syzkaller_revision: str,
) -> Tuple[Dict[str, object], bool]:
    path = discovered.path
    base: Dict[str, object] = {
        "path": str(path),
        "status": "rejected",
        "program_sha256": None,
        "program_size": None,
        "canonical_digest": None,
        "canonical_pipe_ops": None,
        "conversion_log": [],
        "conversion_log_sha256": None,
        "rejection_category": None,
        "rejection_detail": None,
    }
    if discovered.discovery_rejection is not None:
        base["rejection_category"] = discovered.discovery_rejection
        base["rejection_detail"] = "input is not an ordinary .syz file"
        return _finalize_classification(base, syzkaller_revision), False

    try:
        file_stat = path.lstat()
        if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
            base["rejection_category"] = "symlink"
            base["rejection_detail"] = "input changed into a non-regular file"
            return _finalize_classification(base, syzkaller_revision), False
        base["program_size"] = file_stat.st_size
        if file_stat.st_size > MAX_SYZ_FILE_BYTES:
            base["rejection_category"] = "file-too-large"
            base["rejection_detail"] = (
                f"{file_stat.st_size} exceeds {MAX_SYZ_FILE_BYTES} bytes"
            )
            return _finalize_classification(base, syzkaller_revision), False
        encoded = path.read_bytes()
    except OSError as error:
        base["rejection_category"] = "input-read-failure"
        base["rejection_detail"] = str(error)
        return _finalize_classification(base, syzkaller_revision), True

    base["program_size"] = len(encoded)
    base["program_sha256"] = hashlib.sha256(encoded).hexdigest()
    try:
        program = parse_syz_program(encoded)
        conversion = convert_syz_program(program)
    except SyzSyntaxError as error:
        base["rejection_category"] = f"syntax-{error.category.value}"
        base["rejection_detail"] = str(error)
        return _finalize_classification(base, syzkaller_revision), False
    except SyzConversionError as error:
        base["rejection_category"] = error.category.value
        base["rejection_detail"] = str(error)
        return _finalize_classification(base, syzkaller_revision), False

    base.update(
        {
            "status": "accepted",
            "canonical_digest": canonical_digest(conversion.document),
            "canonical_pipe_ops": serialize_document(conversion.document),
            "conversion_log": list(conversion.operation_log),
        }
    )
    return _finalize_classification(base, syzkaller_revision), False


def conversion_log_bytes(
    report: Dict[str, object],
    syzkaller_revision: str,
) -> bytes:
    """Encode the path-independent conversion evidence for one input."""
    document = {
        "schema_version": 1,
        "syzkaller_revision": syzkaller_revision,
        "importer_version": IMPORTER_VERSION,
        "program_sha256": report["program_sha256"],
        "program_size": report["program_size"],
        "status": report["status"],
        "canonical_digest": report["canonical_digest"],
        "conversion_log": report["conversion_log"],
        "rejection_category": report["rejection_category"],
        "rejection_detail": report["rejection_detail"],
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _finalize_classification(
    report: Dict[str, object],
    syzkaller_revision: str,
) -> Dict[str, object]:
    encoded_log = conversion_log_bytes(report, syzkaller_revision)
    report["conversion_log_sha256"] = hashlib.sha256(encoded_log).hexdigest()
    return report


def write_json_report(path: Path, report: Dict[str, object]) -> None:
    """Atomically persist one deterministic JSON report."""

    path = path.absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(encoded)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _discover_directory(
    directory: Path,
    discovered: Dict[str, DiscoveredInput],
) -> None:
    try:
        entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
    except OSError as error:
        raise InputDiscoveryError(f"cannot scan input directory {directory}: {error}") from error
    for entry in entries:
        path = Path(entry.path).absolute()
        key = str(path)
        try:
            if entry.is_symlink():
                if path.suffix == ".syz" or entry.is_dir(follow_symlinks=True):
                    discovered[key] = DiscoveredInput(path, "symlink")
            elif entry.is_dir(follow_symlinks=False):
                _discover_directory(path, discovered)
            elif entry.is_file(follow_symlinks=False) and path.suffix == ".syz":
                discovered[key] = DiscoveredInput(path)
        except OSError as error:
            raise InputDiscoveryError(f"cannot inspect input {path}: {error}") from error


__all__ = [
    "DiscoveredInput",
    "InputDiscoveryError",
    "MAX_SYZ_FILE_BYTES",
    "build_check_report",
    "classify_input",
    "conversion_log_bytes",
    "discover_inputs",
    "write_json_report",
]
