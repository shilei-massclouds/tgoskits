"""LLVM profraw merging and source-scoped coverage extraction."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, Optional, Set, Tuple

from .spec import CoverageTarget


def llvm_tool(name: str) -> Path:
    override = os.environ.get(name.upper().replace("-", "_"))
    if override:
        path = Path(override)
        if path.is_file():
            return path
        raise FileNotFoundError(f"{name} override is not a file: {path}")
    target_libdir = Path(
        subprocess.check_output(["rustc", "--print", "target-libdir"], text=True).strip()
    )
    rust_tool = target_libdir.parent / "bin" / name
    if rust_tool.is_file():
        return rust_tool
    system_tool = shutil.which(name)
    if system_tool:
        return Path(system_tool)
    raise FileNotFoundError(f"cannot find {name}")


def merge_profraws(profraws: Iterable[Path], output: Path) -> None:
    paths = tuple(profraws)
    if not paths:
        raise ValueError("coverage merge requires at least one profraw")
    subprocess.run(
        [str(llvm_tool("llvm-profdata")), "merge", "-sparse"]
        + [str(path) for path in paths]
        + ["-o", str(output)],
        check=True,
        capture_output=True,
        text=True,
    )


def extract_regions(target: CoverageTarget, profdata: Path, elf: Path) -> Dict:
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
        return {"error": completed.stderr.strip(), "covered_regions": []}
    try:
        exported = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"error": "invalid JSON output", "covered_regions": []}
    all_regions = region_ids(target, exported, covered_only=False)
    covered = region_ids(target, exported, covered_only=True)
    return {
        "target_set_id": target.target_set_id,
        "target_regions": len(all_regions),
        "covered_regions": sorted(covered),
    }


def covered_region_set(target: CoverageTarget, profdata: Path, elf: Path) -> Set[str]:
    result = extract_regions(target, profdata, elf)
    if "error" in result:
        raise RuntimeError(result["error"])
    return set(result["covered_regions"])


def region_ids(target: CoverageTarget, exported: Dict, *, covered_only: bool) -> Set[str]:
    regions = set()
    for data in exported.get("data", []):
        for file_entry in data.get("files", []):
            source = target_source(file_entry.get("filename", ""), target.source_paths)
            if source is None:
                continue
            for segment in file_entry.get("segments", []):
                if not is_region_segment(segment):
                    continue
                if covered_only and segment[2] <= 0:
                    continue
                regions.add(f"{source}:{segment[0]}:{segment[1]}")
    return regions


def target_source(filename: str, sources: Tuple[str, ...]) -> Optional[str]:
    normalized = filename.replace("\\", "/")
    for source in sources:
        if normalized == source or normalized.endswith(f"/{source}"):
            marker = normalized.rfind("os/StarryOS/")
            return normalized[marker:] if marker >= 0 else source
    return None


def is_region_segment(segment: list) -> bool:
    return len(segment) >= 5 and bool(segment[3]) and bool(segment[4])
