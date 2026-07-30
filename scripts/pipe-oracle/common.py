import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = 1

CORPUS_DIR = Path("coverage/pipe-oracle-fuzz")
FAILURES_DIR = CORPUS_DIR / "failures"

ELF_NAME = "pipe-linux-oracle"
OPS_NAME = "pipe.ops"
TRACE_NAME = "linux.trace"
GUEST_LOG_NAME = "guest.log"
METADATA_NAME = "metadata.json"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_save(dir_path: Path, save_fn):
    tmp_dir = dir_path.with_name(dir_path.name + ".tmp")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    try:
        save_fn(tmp_dir)
        os.replace(tmp_dir, dir_path)
    except BaseException:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise


def build_metadata(
    seed: Optional[int],
    batch_index: int,
    generator_version: str,
    input_path: Optional[Path],
    elf_path: Optional[Path],
    ops_path: Optional[Path],
    trace_path: Optional[Path],
    guest_log_path: Optional[Path],
    profraw_paths: Optional[List[Path]],
    command: str,
    result_category: str,
    region_summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    meta: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "git_commit": _git_commit(),
        "git_dirty": _git_dirty(),
        "generator_version": generator_version,
        "batch_index": batch_index,
        "command": command,
        "host_uname": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "page_size": os.sysconf("SC_PAGE_SIZE"),
        },
        "guest_result_category": result_category,
    }
    if seed is not None:
        meta["fuzz_seed"] = seed
    for key, path in [
        ("input", input_path),
        ("elf", elf_path),
        ("ops", ops_path),
        ("trace", trace_path),
        ("guest_log", guest_log_path),
    ]:
        if path and path.exists():
            meta[f"{key}_sha256"] = sha256_file(path)
            meta[f"{key}_size"] = path.stat().st_size
    if profraw_paths:
        meta["profraws"] = [
            {"path": str(p), "sha256": sha256_file(p), "size": p.stat().st_size}
            for p in profraw_paths
            if p and p.exists()
        ]
    if region_summary:
        meta["coverage_region_summary"] = region_summary
    return meta


def save_metadata(dir_path: Path, meta: Dict[str, Any]):
    (dir_path / METADATA_NAME).write_text(
        json.dumps(meta, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    )


def load_metadata(dir_path: Path) -> Dict[str, Any]:
    return json.loads((dir_path / METADATA_NAME).read_text())


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True
        ).strip()
    except Exception:
        return "unknown"


def _git_dirty() -> bool:
    try:
        result = subprocess.check_output(
            ["git", "status", "--porcelain"], stderr=subprocess.DEVNULL, text=True
        ).strip()
        return bool(result)
    except Exception:
        return False
