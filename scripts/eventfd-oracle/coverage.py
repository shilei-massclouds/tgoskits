"""Eventfd coverage target bound to the common LLVM coverage machinery."""

import sys
from pathlib import Path
from typing import Dict, Iterable, Optional, Set

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from linux_oracle.coverage import covered_region_set as _covered_region_set
from linux_oracle.coverage import extract_regions as _extract_regions
from linux_oracle.coverage import llvm_tool, merge_profraws
from linux_oracle.coverage import region_ids as _common_region_ids
from linux_oracle.coverage import target_source as _common_target_source
from linux_oracle.spec import CoverageTarget


TARGET_SET_ID = "eventfd-v1"
TARGET_SOURCE_PATHS = (
    "kernel/src/file/event.rs",
    "kernel/src/syscall/fs/event.rs",
    "kernel/src/syscall/fs/fd_ops.rs",
    "kernel/src/syscall/fs/io.rs",
    "kernel/src/syscall/io_mpx/mod.rs",
    "kernel/src/syscall/io_mpx/poll.rs",
)
_TARGET = CoverageTarget(TARGET_SET_ID, tuple(sorted(TARGET_SOURCE_PATHS)))


def extract_regions(profdata: Path, elf: Path) -> Dict:
    return _extract_regions(_TARGET, profdata, elf)


def covered_region_set(profdata: Path, elf: Path) -> Set[str]:
    return _covered_region_set(_TARGET, profdata, elf)


def _region_ids(exported: Dict, *, covered_only: bool) -> Set[str]:
    return _common_region_ids(_TARGET, exported, covered_only=covered_only)


def _target_source(filename: str) -> Optional[str]:
    return _common_target_source(filename, _TARGET.source_paths)


__all__ = [
    "TARGET_SET_ID",
    "TARGET_SOURCE_PATHS",
    "covered_region_set",
    "extract_regions",
    "llvm_tool",
    "merge_profraws",
]
