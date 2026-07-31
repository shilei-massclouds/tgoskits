#!/usr/bin/env python3
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from common import (
    CORPUS_DIR,
    FAILURES_DIR,
    build_metadata,
    save_metadata,
    sha256_bytes,
)
from generator import (
    GENERATOR_VERSION,
    MAX_INPUT_BYTES,
    expand_input,
    ops_to_text,
)
from runner import coverage_object, run_guest_compare


DEFAULT_SEED = 42
DEFAULT_BATCHES = 4
DEFAULT_BATCH_SIZE = 32
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent

INITIAL_SEEDS = [
    # Regression seeds from fixed manual corpus scenarios
    bytes(range(256)),
    bytes(reversed(range(256))),
    b"\x00" * 32,
    b"\xff" * 32,
    b"pipe" * 64,
]


def main():
    parser = argparse.ArgumentParser(
        description="Script-driven pipe differential coverage fuzzing"
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--batches", type=int, default=DEFAULT_BATCHES)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--workspace", type=Path, default=WORKSPACE_ROOT)
    args = parser.parse_args()

    workspace = args.workspace.resolve()
    corpus_dir = workspace / CORPUS_DIR
    corpus_dir.mkdir(parents=True, exist_ok=True)
    failures_dir = workspace / FAILURES_DIR
    failures_dir.mkdir(parents=True, exist_ok=True)

    corpus: Set[bytes] = set(INITIAL_SEEDS)
    covered_regions: Set[str] = set()
    rng = _Rng(args.seed)

    for batch_idx in range(args.batches):
        print(f"=== Batch {batch_idx + 1}/{args.batches} ===", flush=True)
        batch_inputs = _select_batch(rng, corpus, args.batch_size)
        batch_failed = _run_batch(
            workspace, batch_idx, batch_inputs, covered_regions, corpus, failures_dir,
        )
        if batch_failed:
            print(f"Batch {batch_idx + 1} failed, stopping.", flush=True)
            sys.exit(1)
    print("All batches completed.", flush=True)


def _select_batch(rng, corpus: Set[bytes], batch_size: int) -> List[bytes]:
    parents = list(corpus)
    if not parents:
        return [bytes(rng.next() % 256 for _ in range(64)) for _ in range(batch_size)]
    batch = []
    for _ in range(batch_size):
        if rng.next() % 10 < 3:
            seed_bytes = bytes(rng.next() % 256 for _ in range(rng.range(1, 129)))
        else:
            parent = parents[rng.range(0, len(parents))]
            seed_bytes = _mutate(rng, parent)
        batch.append(seed_bytes)
    return batch


def _mutate(rng, data: bytes) -> bytes:
    data = bytearray(data)
    if len(data) == 0:
        return bytes([rng.next() % 256])
    op = rng.range(0, 5)
    if op == 0:
        idx = rng.range(0, len(data))
        data[idx] = (data[idx] + rng.range(1, 256)) % 256
    elif op == 1:
        idx = rng.range(0, len(data))
        data[idx] = rng.next() % 256
    elif op == 2 and len(data) > 1:
        a = rng.range(0, len(data))
        b = rng.range(0, len(data))
        data[a], data[b] = data[b], data[a]
    elif op == 3 and len(data) > 2:
        start = rng.range(0, len(data) - 1)
        end = rng.range(start + 1, len(data))
        data[start:end] = b""
    elif op == 4:
        start = rng.range(0, len(data) + 1)
        data.insert(start, rng.next() % 256)
    return bytes(data[:MAX_INPUT_BYTES])


def _run_batch(
    workspace: Path,
    batch_idx: int,
    inputs: List[bytes],
    covered_regions: Set[str],
    corpus: Set[bytes],
    failures_dir: Path,
) -> bool:
    all_scenarios: List[List[str]] = []
    input_map: Dict[str, bytes] = {}

    for inp in inputs:
        digest = sha256_bytes(inp)
        if digest in input_map:
            continue
        input_map[digest] = inp
        scenarios = expand_input(inp)
        all_scenarios.extend(scenarios)

    ops_text = ops_to_text(all_scenarios)
    ops_digest = hashlib.sha256(ops_text.encode()).hexdigest()

    print(f"  Generated {len(all_scenarios)} scenario groups from {len(inputs)} inputs", flush=True)

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        ops_path = tmp / "pipe.ops"
        ops_path.write_text(ops_text)
        elf_path = _find_or_build_host_oracle(workspace)
        if elf_path is None:
            print("ERROR: cannot build pipe-linux-oracle ELF", flush=True)
            return True

        trace_path = tmp / "linux.trace"
        record_ok = _record_host(elf_path, ops_path, trace_path)
        if not record_ok:
            print("ERROR: host record failed", flush=True)
            return True

        artifact_elf = tmp / "pipe-linux-oracle"
        shutil.copy2(elf_path, artifact_elf)
        guest_log, profraws, passed = _run_guest_compare(workspace, tmp)

        if not passed:
            failure_id = f"batch{batch_idx}_mismatch_{ops_digest[:12]}"
            failure_path = failures_dir / failure_id
            _save_batch_failure(
                failure_path, input_map, ops_text,
                artifact_elf, trace_path, guest_log, profraws,
                batch_idx, "mismatch",
            )
            print(
                f"  MISMATCH saved to {failure_path.relative_to(workspace)}",
                flush=True,
            )
            return True

        try:
            if not profraws:
                raise RuntimeError("QEMU passed without producing the expected Starry profraw")
            new_regions = _extract_new_regions(
                profraws, coverage_object(workspace), covered_regions
            )
        except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
            guest_log += f"\nCoverage analysis failed: {error}\n"
            failure_id = f"batch{batch_idx}_coverage_{ops_digest[:12]}"
            failure_path = failures_dir / failure_id
            _save_batch_failure(
                failure_path,
                input_map,
                ops_text,
                artifact_elf,
                trace_path,
                guest_log,
                profraws,
                batch_idx,
                "coverage",
            )
            print(
                f"  COVERAGE FAILURE saved to {failure_path.relative_to(workspace)}",
                flush=True,
            )
            return True

        if new_regions:
            for inp_digest, inp_bytes in input_map.items():
                if inp_bytes not in corpus:
                    corpus.add(inp_bytes)
                    print(f"  New corpus entry: {inp_digest[:12]}...", flush=True)

        print(
            f"  Coverage saved: {len(profraws)} profraw(s), "
            f"{len(new_regions)} new pipe regions",
            flush=True,
        )

    return False


def _find_or_build_host_oracle(workspace: Path) -> Optional[Path]:
    source_dir = workspace / "test-suit/starryos/qemu/pipe-linux-oracle/c"
    build_dir = workspace / "target/pipe-oracle-host"
    elf_path = build_dir / "pipe-linux-oracle"
    if elf_path.is_file():
        return elf_path

    build_env = os.environ.copy()
    build_env.pop("STARRY_PIPE_ORACLE_ARTIFACT_DIR", None)
    try:
        subprocess.run(
            ["cmake", "-S", str(source_dir), "-B", str(build_dir)],
            cwd=str(workspace),
            env=build_env,
            check=True,
        )
        subprocess.run(
            ["cmake", "--build", str(build_dir), "--target", "pipe-linux-oracle"],
            cwd=str(workspace),
            env=build_env,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return elf_path if elf_path.is_file() else None


def _record_host(elf: Path, ops: Path, trace: Path) -> bool:
    result = subprocess.run(
        [str(elf), "--record", str(ops), str(trace)],
        capture_output=True, text=True, timeout=30,
    )
    return result.returncode == 0


def _run_guest_compare(
    workspace: Path, artifact_dir: Path
) -> Tuple[str, List[Path], bool]:
    return run_guest_compare(workspace, artifact_dir)


def _extract_new_regions(
    profraws: List[Path], elf: Path, covered_regions: Set[str],
) -> Set[str]:
    if not profraws:
        return set()
    from coverage import merge_profraws, pipe_region_set
    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        profdata = tmp / "merged.profdata"
        merge_profraws(profraws, profdata)
        regions = pipe_region_set(profdata, elf)
        new_regions = regions - covered_regions
        covered_regions.update(new_regions)
        return new_regions


def _save_batch_failure(
    dest: Path,
    input_map: Dict[str, bytes],
    ops_text: str,
    elf: Path,
    trace: Path,
    guest_log: str,
    profraws: List[Path],
    batch_idx: int,
    category: str,
):
    from common import atomic_save
    atomic_save(dest, lambda tmp: _write_failure_parts(
        tmp, input_map, ops_text, elf, trace, guest_log, profraws, batch_idx, category,
    ))


def _write_failure_parts(
    tmp: Path,
    input_map: Dict[str, bytes],
    ops_text: str,
    elf_path: Path,
    trace_path: Path,
    guest_log: str,
    profraws: List[Path],
    batch_idx: int,
    category: str,
):
    if len(input_map) == 1:
        key = next(iter(input_map.keys()))
        (tmp / "input.bin").write_bytes(input_map[key])
    else:
        inp_dir = tmp / "inputs"
        inp_dir.mkdir()
        for digest, data in input_map.items():
            (inp_dir / f"{digest[:16]}.bin").write_bytes(data)
    (tmp / "pipe.ops").write_text(ops_text)
    shutil.copy2(elf_path, tmp / "pipe-linux-oracle")
    shutil.copy2(trace_path, tmp / "linux.trace")
    (tmp / "guest.log").write_text(guest_log)
    profraw_dir = tmp / "profraws"
    profraw_dir.mkdir()
    for p in profraws:
        if p.exists():
            shutil.copy2(p, profraw_dir / p.name)
    meta = build_metadata(
        seed=None,
        batch_index=batch_idx,
        generator_version=GENERATOR_VERSION,
        input_path=None,
        elf_path=tmp / "pipe-linux-oracle",
        ops_path=tmp / "pipe.ops",
        trace_path=tmp / "linux.trace",
        guest_log_path=tmp / "guest.log",
        profraw_paths=list(profraw_dir.iterdir()) if profraw_dir.exists() else None,
        command=" ".join(sys.argv),
        result_category=category,
    )
    save_metadata(tmp, meta)


class _Rng:
    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next(self) -> int:
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        return self.state

    def range(self, lo: int, hi: int) -> int:
        if lo >= hi:
            return lo
        return lo + (self.next() % (hi - lo))


if __name__ == "__main__":
    main()
