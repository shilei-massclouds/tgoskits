"""Coverage target for the final concurrent pipe adapter."""

import sys
from pathlib import Path
from typing import Dict, Set

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from blocking_coverage import TARGET_SOURCE_PATHS as BLOCKING_TARGET_SOURCE_PATHS
from linux_oracle.coverage import covered_region_set as _covered_region_set
from linux_oracle.coverage import extract_regions as _extract_regions
from linux_oracle.spec import CoverageTarget


TARGET_SET_ID = "pipe-concurrent-v1"
TARGET_SOURCE_PATHS = tuple(
    sorted(
        set(BLOCKING_TARGET_SOURCE_PATHS)
        | {
            "kernel/src/syscall/mod.rs",
            "kernel/src/syscall/signal.rs",
            "kernel/src/syscall/io_mpx/epoll.rs",
            "kernel/src/file/epoll.rs",
            "kernel/src/file/epoll_file.rs",
            "kernel/src/task/signal.rs",
            "kernel/src/task/user.rs",
        }
    )
)
TARGET = CoverageTarget(TARGET_SET_ID, TARGET_SOURCE_PATHS)


def extract_regions(profdata: Path, elf: Path) -> Dict:
    return _extract_regions(TARGET, profdata, elf)


def covered_region_set(profdata: Path, elf: Path) -> Set[str]:
    return _covered_region_set(TARGET, profdata, elf)


__all__ = [
    "TARGET",
    "TARGET_SET_ID",
    "TARGET_SOURCE_PATHS",
    "covered_region_set",
    "extract_regions",
]
