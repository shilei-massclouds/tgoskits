"""Pipe coverage compatibility API over common LLVM coverage extraction."""

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from linux_oracle.coverage import is_region_segment
from linux_oracle.coverage import llvm_tool, merge_profraws
from linux_oracle.coverage import region_ids as _common_region_ids
from linux_oracle.spec import CoverageTarget


LEGACY_TARGET_SET_ID = "pipe-v1"
FD_TARGET_SET_ID = "pipe-fd-v2"
VECTOR_TARGET_SET_ID = "pipe-vector-v3"
TARGET_SET_ID = "pipe-poll-v4"

TARGET_SOURCE_PATHS = {
    LEGACY_TARGET_SET_ID: ("kernel/src/file/pipe.rs",),
    FD_TARGET_SET_ID: (
        "kernel/src/file/pipe.rs",
        "kernel/src/syscall/fs/pipe.rs",
        "kernel/src/syscall/fs/fd_ops.rs",
    ),
    VECTOR_TARGET_SET_ID: (
        "kernel/src/file/pipe.rs",
        "kernel/src/mm/io.rs",
        "kernel/src/syscall/fs/fd_ops.rs",
        "kernel/src/syscall/fs/io.rs",
        "kernel/src/syscall/fs/pipe.rs",
    ),
    TARGET_SET_ID: (
        "kernel/src/file/pipe.rs",
        "kernel/src/mm/io.rs",
        "kernel/src/syscall/fs/fd_ops.rs",
        "kernel/src/syscall/fs/io.rs",
        "kernel/src/syscall/fs/pipe.rs",
        "kernel/src/syscall/io_mpx/mod.rs",
        "kernel/src/syscall/io_mpx/poll.rs",
    ),
}


def extract_pipe_regions(
    profdata: Path,
    elf: Path,
    target_set_id: str = TARGET_SET_ID,
) -> Dict:
    completed = subprocess.run(
        [
            str(llvm_tool("llvm-cov")),
            "export",
            str(elf),
            f"-instr-profile={profdata}",
        ],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return {"error": completed.stderr.strip(), "regions": [], "pipe_regions": []}
    try:
        exported = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"error": "invalid JSON output", "regions": [], "pipe_regions": []}
    pipe_regions = _pipe_region_ids(exported, False, target_set_id)
    covered = covered_pipe_region_ids(exported, target_set_id)
    return {
        "total_regions": _count_regions(exported),
        "pipe_regions": len(pipe_regions),
        "pipe_region_ids": sorted(pipe_regions),
        "covered_pipe_regions": sorted(covered),
    }


def _count_regions(exported: Dict) -> int:
    return sum(
        is_region_segment(segment)
        for data in exported.get("data", [])
        for file_entry in data.get("files", [])
        for segment in file_entry.get("segments", [])
    )


def covered_pipe_region_ids(
    exported: Dict, target_set_id: str = TARGET_SET_ID
) -> Set[str]:
    return _pipe_region_ids(exported, True, target_set_id)


def _pipe_region_ids(
    exported: Dict, covered_only: bool, target_set_id: str
) -> Set[str]:
    sources = TARGET_SOURCE_PATHS.get(target_set_id)
    if sources is None:
        raise ValueError(f"unknown coverage target set: {target_set_id}")
    target = CoverageTarget(target_set_id, tuple(sorted(sources)))
    return _common_region_ids(target, exported, covered_only=covered_only)


def pipe_region_set(
    profdata: Path,
    elf: Path,
    target_set_id: str = TARGET_SET_ID,
) -> Set[str]:
    result = extract_pipe_regions(profdata, elf, target_set_id)
    if "error" in result:
        raise RuntimeError(result["error"])
    return set(result["covered_pipe_regions"])


__all__ = [
    "FD_TARGET_SET_ID",
    "LEGACY_TARGET_SET_ID",
    "TARGET_SET_ID",
    "TARGET_SOURCE_PATHS",
    "VECTOR_TARGET_SET_ID",
    "covered_pipe_region_ids",
    "extract_pipe_regions",
    "llvm_tool",
    "merge_profraws",
    "pipe_region_set",
]
