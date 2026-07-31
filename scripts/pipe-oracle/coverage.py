import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Set


def llvm_tool(name: str) -> Path:
    override = os.environ.get(name.upper().replace("-", "_"))
    if override:
        path = Path(override)
        if path.is_file():
            return path
        raise FileNotFoundError(f"{name} override is not a file: {path}")

    target_libdir = Path(
        subprocess.check_output(
            ["rustc", "--print", "target-libdir"], text=True
        ).strip()
    )
    rust_tool = target_libdir.parent / "bin" / name
    if rust_tool.is_file():
        return rust_tool
    system_tool = shutil.which(name)
    if system_tool:
        return Path(system_tool)
    raise FileNotFoundError(
        f"cannot find {name}; install the Rust llvm-tools component or set "
        f"{name.upper().replace('-', '_')}"
    )


def merge_profraws(profraws: List[Path], output: Path):
    subprocess.run(
        [str(llvm_tool("llvm-profdata")), "merge", "-sparse"]
        + [str(path) for path in profraws]
        + ["-o", str(output)],
        check=True, capture_output=True, text=True,
    )


def extract_pipe_regions(profdata: Path, elf: Path) -> Dict:
    result = subprocess.run(
        [
            str(llvm_tool("llvm-cov")), "export", str(elf),
            f"-instr-profile={profdata}",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return {"error": result.stderr.strip(), "regions": [], "pipe_regions": []}
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": "invalid JSON output", "regions": [], "pipe_regions": []}

    pipe_regions = _pipe_region_ids(data, covered_only=False)
    covered_pipe_regions = covered_pipe_region_ids(data)
    all_regions = _count_regions(data)
    return {
        "total_regions": all_regions,
        "pipe_regions": len(pipe_regions),
        "pipe_region_ids": sorted(pipe_regions),
        "covered_pipe_regions": sorted(covered_pipe_regions),
    }


def _count_regions(data: Dict) -> int:
    total = 0
    for export in data.get("data", []):
        for file_entry in export.get("files", []):
            total += sum(_is_region_segment(segment) for segment in file_entry.get("segments", []))
    return total


def covered_pipe_region_ids(data: Dict) -> Set[str]:
    return _pipe_region_ids(data, covered_only=True)


def _pipe_region_ids(data: Dict, covered_only: bool) -> Set[str]:
    pipe_regions = set()
    for export in data.get("data", []):
        for file_entry in export.get("files", []):
            filename = file_entry.get("filename", "")
            if not _is_pipe_source(filename):
                continue
            source = _stable_source_name(filename)
            for segment in file_entry.get("segments", []):
                if not _is_region_segment(segment):
                    continue
                if covered_only and segment[2] <= 0:
                    continue
                pipe_regions.add(f"{source}:{segment[0]}:{segment[1]}")
    return pipe_regions


def _is_region_segment(segment: List) -> bool:
    return len(segment) >= 5 and bool(segment[3]) and bool(segment[4])


def _is_pipe_source(filename: str) -> bool:
    normalized = filename.replace("\\", "/")
    return normalized == "kernel/src/file/pipe.rs" or normalized.endswith(
        "/kernel/src/file/pipe.rs"
    )


def _stable_source_name(filename: str) -> str:
    normalized = filename.replace("\\", "/")
    for marker in ("os/StarryOS/", "kernel/src/file/pipe.rs"):
        marker_index = normalized.rfind(marker)
        if marker_index >= 0:
            return normalized[marker_index:]
    return Path(normalized).name


def pipe_region_set(profdata: Path, elf: Path) -> Set[str]:
    result = extract_pipe_regions(profdata, elf)
    if "error" in result:
        raise RuntimeError(result["error"])
    return set(result.get("covered_pipe_regions", []))
