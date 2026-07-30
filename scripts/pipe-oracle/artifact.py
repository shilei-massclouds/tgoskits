import shutil
from pathlib import Path
from typing import Dict, List, Optional

from .common import (
    FAILURES_DIR,
    atomic_save,
    build_metadata,
    load_metadata,
    save_metadata,
    sha256_file,
    METADATA_NAME,
)


def save_failure(
    failure_id: str,
    input_path: Optional[Path],
    ops_text: str,
    elf_path: Path,
    trace_path: Path,
    guest_log: str,
    profraws: Optional[List[Path]],
    metadata_overrides: Dict,
):
    dest = FAILURES_DIR / failure_id
    atomic_save(dest, lambda tmp: _write_failure(
        tmp, input_path, ops_text, elf_path, trace_path,
        guest_log, profraws, metadata_overrides,
    ))
    return dest


def _write_failure(
    tmp: Path,
    input_path: Optional[Path],
    ops_text: str,
    elf_path: Path,
    trace_path: Path,
    guest_log: str,
    profraws: Optional[List[Path]],
    metadata_overrides: Dict,
):
    if input_path and input_path.exists():
        shutil.copy2(input_path, tmp / "input.bin")
    (tmp / "pipe.ops").write_text(ops_text)
    shutil.copy2(elf_path, tmp / "pipe-linux-oracle")
    shutil.copy2(trace_path, tmp / "linux.trace")
    (tmp / "guest.log").write_text(guest_log)
    if profraws:
        profraw_dir = tmp / "profraws"
        profraw_dir.mkdir(exist_ok=True)
        for p in profraws:
            if p.exists():
                shutil.copy2(p, profraw_dir / p.name)
    meta_overrides = dict(metadata_overrides)
    meta_overrides.setdefault("input_path", tmp / "input.bin" if (tmp / "input.bin").exists() else None)
    meta_overrides.setdefault("elf_path", tmp / "pipe-linux-oracle")
    meta_overrides.setdefault("ops_path", tmp / "pipe.ops")
    meta_overrides.setdefault("trace_path", tmp / "linux.trace")
    meta_overrides.setdefault("guest_log_path", tmp / "guest.log")
    if profraws:
        meta_overrides.setdefault("profraw_paths", list((tmp / "profraws").iterdir()))
    meta = build_metadata(**meta_overrides)
    save_metadata(tmp, meta)


def validate_failure(dir_path: Path) -> Dict:
    required = ["pipe.ops", "linux.trace", "pipe-linux-oracle", "guest.log", METADATA_NAME]
    for name in required:
        assert (dir_path / name).is_file(), f"missing {name} in {dir_path}"
    meta = load_metadata(dir_path)
    assert meta.get("schema_version") is not None
    for key in ["input", "elf", "ops", "trace", "guest_log"]:
        sha_key = f"{key}_sha256"
        if sha_key in meta:
            file_key = key if key != "guest_log" else "guest_log"
            path = dir_path / {
                "input": "input.bin",
                "elf": "pipe-linux-oracle",
                "ops": "pipe.ops",
                "trace": "linux.trace",
                "guest_log": "guest.log",
            }[key]
            if path.exists():
                actual = sha256_file(path)
                assert actual == meta[sha_key], f"{sha_key} mismatch for {path}"
    import platform
    import struct
    with open(dir_path / "pipe-linux-oracle", "rb") as f:
        header = f.read(20)
        assert header[:4] == b"\x7fELF", "not an ELF"
        ei_class = header[4]
        assert ei_class == 2, "not 64-bit ELF"
        ei_data = header[5]
        if ei_data == 1:
            machine = struct.unpack("<H", header[18:20])[0]
        else:
            machine = struct.unpack(">H", header[18:20])[0]
        assert machine == 62, "not x86_64 ELF"
    return meta
