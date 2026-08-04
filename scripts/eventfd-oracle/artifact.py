"""Eventfd compatibility binding for common failure artifact storage."""

import sys
from pathlib import Path
from typing import Dict, Iterable, Optional

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from adapter import SPEC
from linux_oracle.failure import (
    SCHEMA_NAME,
    SCHEMA_VERSION,
    FailureArtifact,
)
from linux_oracle.failure import load_failure as _load_failure
from linux_oracle.failure import save_failure as _save_failure


REQUIRED_FILES = {
    SPEC.artifacts.scenario_filename,
    SPEC.artifacts.trace_filename,
    SPEC.artifacts.host_executable_filename,
    SPEC.artifacts.starry_elf_filename,
    SPEC.artifacts.guest_log_filename,
    "metadata.json",
}


def save_failure(
    destination: Path,
    *,
    ops_path: Path,
    trace_path: Path,
    host_elf_path: Path,
    starry_elf_path: Path,
    guest_log: str,
    profraw_paths: Iterable[Path],
    result_category: str,
    mismatch: Optional[Dict],
) -> FailureArtifact:
    return _save_failure(
        SPEC,
        destination,
        scenario_path=ops_path,
        trace_path=trace_path,
        host_elf_path=host_elf_path,
        starry_elf_path=starry_elf_path,
        guest_log=guest_log,
        profraw_paths=profraw_paths,
        result_category=result_category,
        mismatch=mismatch,
    )


def load_failure(path: Path) -> FailureArtifact:
    return _load_failure(SPEC, path)


__all__ = ["FailureArtifact", "load_failure", "save_failure"]
