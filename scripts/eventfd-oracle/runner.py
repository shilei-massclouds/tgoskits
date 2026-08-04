"""Compatibility entry points for the common eventfd QEMU runner."""

import subprocess
import sys
from pathlib import Path
from typing import Optional

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from adapter import SPEC
from guest_result import (
    GuestExecutionResult,
    GuestResultCategory,
    classify_guest_execution,
)
from linux_oracle.qemu import coverage_object as _coverage_object
from linux_oracle.qemu import run_guest_compare as _run_guest_compare
from linux_oracle.qemu import validate_artifact_directory


ARTIFACT_DIR_ENV = SPEC.qemu.artifact_environment
PINNED_STARRY_ELF_ENV = SPEC.qemu.pinned_elf_environment
REQUIRED_ARTIFACTS = SPEC.artifacts.required_execution_files
STARRY_PROFRAW = SPEC.qemu.profraw_path
STARRY_COVERAGE_OBJECT = SPEC.qemu.coverage_object_path


def run_guest_compare(
    workspace: Path,
    artifact_dir: Path,
    pinned_starry_elf: Optional[Path] = None,
) -> GuestExecutionResult:
    return _run_guest_compare(
        SPEC,
        workspace,
        artifact_dir,
        pinned_starry_elf=pinned_starry_elf,
    )


def coverage_object(workspace: Path) -> Path:
    return _coverage_object(SPEC, workspace)


def _validate_artifact_dir(artifact_dir: Path) -> None:
    validate_artifact_directory(SPEC, artifact_dir)


__all__ = [
    "ARTIFACT_DIR_ENV",
    "GuestExecutionResult",
    "GuestResultCategory",
    "PINNED_STARRY_ELF_ENV",
    "REQUIRED_ARTIFACTS",
    "STARRY_COVERAGE_OBJECT",
    "STARRY_PROFRAW",
    "classify_guest_execution",
    "coverage_object",
    "run_guest_compare",
]
