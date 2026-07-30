import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set


def merge_profraws(profraws: List[Path], output: Path):
    subprocess.run(
        ["llvm-profdata", "merge", "-sparse"] + [str(p) for p in profraws] +
        ["-o", str(output)],
        check=True, capture_output=True, text=True,
    )


def extract_pipe_regions(profdata: Path, elf: Path) -> Dict:
    result = subprocess.run(
        [
            "llvm-cov", "show", str(elf),
            f"-instr-profile={profdata}",
            "-show-regions",
            "-json",
            "-path-equivalence=", ",",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return {"error": result.stderr.strip(), "regions": [], "pipe_regions": []}
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": "invalid JSON output", "regions": [], "pipe_regions": []}

    pipe_regions = _find_pipe_regions(data)
    all_regions = _count_regions(data)
    return {
        "total_regions": all_regions,
        "pipe_regions": len(pipe_regions),
        "pipe_region_ids": pipe_regions,
        "covered_pipe_regions": [r for r in pipe_regions if r.get("count", 0) > 0],
    }


def _count_regions(data: Dict) -> int:
    total = 0
    for file_entry in data.get("files", []):
        for segment in file_entry.get("segments", []):
            if len(segment) >= 4:
                total += 1
    return total


def _find_pipe_regions(data: Dict) -> List[Dict]:
    pipe_regions = []
    for file_entry in data.get("files", []):
        filename = file_entry.get("filename", "")
        if "pipe.rs" not in filename and "kernel/src/file/pipe" not in filename:
            continue
        expansions = file_entry.get("expansions", [])
        for expansion in expansions:
            for region in expansion.get("regions", []):
                region["count"] = expansion.get("count", 0)
                pipe_regions.append(region)
        for segment in file_entry.get("segments", []):
            pipe_regions.append({
                "line": segment[0] if len(segment) > 0 else 0,
                "count": segment[2] if len(segment) > 2 else 0,
            })
    return pipe_regions


def pipe_region_set(profdata: Path, elf: Path) -> Set[str]:
    result = extract_pipe_regions(profdata, elf)
    if "error" in result:
        return set()
    return set(result.get("pipe_region_ids", []))
