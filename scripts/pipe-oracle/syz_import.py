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
from syz_projection import (
    PROJECTED_IMPORTER_VERSION,
    empty_projection_diagnostics,
    project_vector_slices as convert_projected_vector_slices,
    projection_summary,
)


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
    *,
    max_admit_unique: Optional[int] = None,
    project_vector_slices: bool = False,
) -> Tuple[Dict[str, object], bool]:
    """Discover and classify inputs; return the report and infrastructure status."""

    if max_admit_unique is not None and (
        not isinstance(max_admit_unique, int)
        or isinstance(max_admit_unique, bool)
        or max_admit_unique <= 0
    ):
        raise ValueError("max_admit_unique must be positive")

    importer_version = (
        PROJECTED_IMPORTER_VERSION if project_vector_slices else IMPORTER_VERSION
    )
    inputs = discover_inputs(paths)
    reports = []
    infrastructure_failed = False
    for discovered in inputs:
        report, input_infrastructure_failed = classify_input(
            discovered,
            syzkaller_revision,
            project_vector_slices=project_vector_slices,
        )
        reports.append(report)
        infrastructure_failed |= input_infrastructure_failed

    rejection_counts = Counter(
        report["rejection_category"]
        for report in reports
        if report["status"] == "rejected"
    )
    accepted = [report for report in reports if report["status"] == "accepted"]
    eligible_digests = sorted(
        {str(report["canonical_digest"]) for report in accepted}
    )
    selected_digests = (
        eligible_digests
        if max_admit_unique is None
        else eligible_digests[:max_admit_unique]
    )
    deferred_digests = eligible_digests[len(selected_digests) :]
    report = {
        "schema_version": 3 if project_vector_slices else 2,
        "mode": "check-only",
        "syzkaller_revision": syzkaller_revision,
        "supported_syzkaller_revision": SUPPORTED_SYZKALLER_REVISION,
        "importer_version": importer_version,
        "summary": {
            "total_inputs": len(reports),
            "accepted": len(accepted),
            "rejected": len(reports) - len(accepted),
            "unique_canonical": len(
                {report["canonical_digest"] for report in accepted}
            ),
            "rejection_categories": dict(sorted(rejection_counts.items())),
        },
        "admission_selection": {
            "policy": "canonical-digest",
            "max_unique": max_admit_unique,
            "eligible_unique": len(eligible_digests),
            "selected_unique": len(selected_digests),
            "deferred_unique": len(deferred_digests),
            "selected_digests": selected_digests,
            "deferred_digests": deferred_digests,
        },
        "inputs": reports,
    }
    if project_vector_slices:
        report["summary"].update(projection_summary(reports))
    return report, infrastructure_failed


def selected_admission_reports(
    report: Dict[str, object],
) -> Tuple[Dict[str, object], ...]:
    """Return every accepted source for the report's selected canonical inputs."""

    schema_version = report.get("schema_version")
    if schema_version not in {2, 3}:
        raise ValueError("admission requires check report schema 2 or 3")
    expected_importer = "2" if schema_version == 2 else PROJECTED_IMPORTER_VERSION
    if report.get("importer_version") != expected_importer:
        raise ValueError("check report schema/importer version mismatch")
    inputs = report.get("inputs")
    if not isinstance(inputs, list) or any(
        not isinstance(input_report, dict) for input_report in inputs
    ):
        raise ValueError("check report inputs are invalid")
    eligible_values = [
        input_report.get("canonical_digest")
        for input_report in inputs
        if input_report.get("status") == "accepted"
    ]
    if any(
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        for digest in eligible_values
    ):
        raise ValueError("eligible admission digests are invalid")
    eligible = sorted(set(eligible_values))
    selection = report["admission_selection"]
    if not isinstance(selection, dict):
        raise ValueError("admission selection is not an object")
    maximum = selection.get("max_unique")
    if maximum is not None and (
        not isinstance(maximum, int)
        or isinstance(maximum, bool)
        or maximum <= 0
    ):
        raise ValueError("admission selection maximum is invalid")
    selected = eligible if maximum is None else eligible[:maximum]
    deferred = eligible[len(selected) :]
    expected = {
        "policy": "canonical-digest",
        "max_unique": maximum,
        "eligible_unique": len(eligible),
        "selected_unique": len(selected),
        "deferred_unique": len(deferred),
        "selected_digests": selected,
        "deferred_digests": deferred,
    }
    if selection != expected:
        raise ValueError("admission selection does not match classified inputs")
    selected_set = set(selected)
    return tuple(
        input_report
        for input_report in inputs
        if input_report.get("status") == "accepted"
        and input_report.get("canonical_digest") in selected_set
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
    *,
    project_vector_slices: bool = False,
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
    importer_version = (
        PROJECTED_IMPORTER_VERSION if project_vector_slices else IMPORTER_VERSION
    )
    if project_vector_slices:
        base.update(
            {
                "conversion_kind": None,
                "projection": empty_projection_diagnostics(),
            }
        )
    if discovered.discovery_rejection is not None:
        base["rejection_category"] = discovered.discovery_rejection
        base["rejection_detail"] = "input is not an ordinary .syz file"
        return _finalize_classification(
            base,
            syzkaller_revision,
            importer_version,
        ), False

    try:
        file_stat = path.lstat()
        if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
            base["rejection_category"] = "symlink"
            base["rejection_detail"] = "input changed into a non-regular file"
            return _finalize_classification(
                base,
                syzkaller_revision,
                importer_version,
            ), False
        base["program_size"] = file_stat.st_size
        if file_stat.st_size > MAX_SYZ_FILE_BYTES:
            base["rejection_category"] = "file-too-large"
            base["rejection_detail"] = (
                f"{file_stat.st_size} exceeds {MAX_SYZ_FILE_BYTES} bytes"
            )
            return _finalize_classification(
                base,
                syzkaller_revision,
                importer_version,
            ), False
        encoded = path.read_bytes()
    except OSError as error:
        base["rejection_category"] = "input-read-failure"
        base["rejection_detail"] = str(error)
        return _finalize_classification(
            base,
            syzkaller_revision,
            importer_version,
        ), True

    base["program_size"] = len(encoded)
    base["program_sha256"] = hashlib.sha256(encoded).hexdigest()
    try:
        program = parse_syz_program(encoded)
    except SyzSyntaxError as error:
        base["rejection_category"] = f"syntax-{error.category.value}"
        base["rejection_detail"] = str(error)
        return _finalize_classification(
            base,
            syzkaller_revision,
            importer_version,
        ), False

    try:
        conversion = convert_syz_program(program)
    except SyzConversionError as error:
        if not project_vector_slices:
            base["rejection_category"] = error.category.value
            base["rejection_detail"] = str(error)
            return _finalize_classification(
                base,
                syzkaller_revision,
                importer_version,
            ), False
        projection = convert_projected_vector_slices(program, error)
        base["projection"] = projection.diagnostics
        if projection.document is None:
            base["rejection_category"] = projection.rejection_category
            base["rejection_detail"] = projection.rejection_detail
            return _finalize_classification(
                base,
                syzkaller_revision,
                importer_version,
            ), False
        conversion_document = projection.document
        conversion_log = projection.operation_log
        conversion_kind = "projected"
    else:
        conversion_document = conversion.document
        conversion_log = conversion.operation_log
        conversion_kind = "lossless"

    base.update(
        {
            "status": "accepted",
            "canonical_digest": canonical_digest(conversion_document),
            "canonical_pipe_ops": serialize_document(conversion_document),
            "conversion_log": list(conversion_log),
        }
    )
    if project_vector_slices:
        base["conversion_kind"] = conversion_kind
    return _finalize_classification(
        base,
        syzkaller_revision,
        importer_version,
    ), False


def conversion_log_bytes(
    report: Dict[str, object],
    syzkaller_revision: str,
    *,
    importer_version: str = IMPORTER_VERSION,
) -> bytes:
    """Encode the path-independent conversion evidence for one input."""
    document = {
        "schema_version": 2 if importer_version == PROJECTED_IMPORTER_VERSION else 1,
        "syzkaller_revision": syzkaller_revision,
        "importer_version": importer_version,
        "program_sha256": report["program_sha256"],
        "program_size": report["program_size"],
        "status": report["status"],
        "canonical_digest": report["canonical_digest"],
        "conversion_log": report["conversion_log"],
        "rejection_category": report["rejection_category"],
        "rejection_detail": report["rejection_detail"],
    }
    if importer_version == PROJECTED_IMPORTER_VERSION:
        document.update(
            {
                "conversion_kind": report["conversion_kind"],
                "projection": report["projection"],
            }
        )
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _finalize_classification(
    report: Dict[str, object],
    syzkaller_revision: str,
    importer_version: str = IMPORTER_VERSION,
) -> Dict[str, object]:
    encoded_log = conversion_log_bytes(
        report,
        syzkaller_revision,
        importer_version=importer_version,
    )
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
    "selected_admission_reports",
    "write_json_report",
]
