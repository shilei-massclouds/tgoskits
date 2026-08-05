"""Coverage target for controlled pipe wait and wakeup scenarios."""

import sys
from pathlib import Path
from typing import Dict, Set

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from linux_oracle.coverage import covered_region_set as _covered_region_set
from linux_oracle.coverage import extract_regions as _extract_regions
from linux_oracle.spec import CoverageTarget


TARGET_SET_ID = "pipe-blocking-v1"
TARGET_SOURCE_PATHS = tuple(
    sorted(
        (
            "components/axpoll/src/lib.rs",
            "kernel/src/file/pipe.rs",
            "kernel/src/mm/io.rs",
            "kernel/src/syscall/fs/fd_ops.rs",
            "kernel/src/syscall/fs/io.rs",
            "kernel/src/syscall/fs/pipe.rs",
            "kernel/src/syscall/io_mpx/mod.rs",
            "kernel/src/syscall/io_mpx/poll.rs",
            "os/arceos/modules/axtask/src/future/poll.rs",
        )
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
