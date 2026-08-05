#!/usr/bin/env python3
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from artifact import validate_failure
from corpus_errors import CorpusValidationError
from common import build_metadata, save_metadata
from guest_result import GuestExecutionResult, normalize_guest_execution
from linux_oracle.failure import load_failure
from linux_oracle.persistence import PersistentStateError
from linux_oracle.qemu import run_guest_compare as run_common_guest_compare
from models import spec_for_common_failure
from runner import run_guest_compare


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent


def main():
    parser = argparse.ArgumentParser(
        description="Replay a pipe oracle failure artifact"
    )
    parser.add_argument("failure_path", type=Path,
                        help="Path to the failure directory")
    parser.add_argument("--refresh-host", action="store_true",
                        help="Re-record the host trace without overwriting original evidence")
    parser.add_argument("--workspace", type=Path, default=WORKSPACE_ROOT)
    args = parser.parse_args()

    failure_dir = args.failure_path.resolve()
    if not failure_dir.is_dir():
        print(f"Error: {failure_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    try:
        raw_metadata = json.loads((failure_dir / "metadata.json").read_text())
        if isinstance(raw_metadata, dict) and "adapter_id" in raw_metadata:
            _replay_common(
                failure_dir,
                args.workspace.resolve(),
                args.refresh_host,
            )
            return
        meta = validate_failure(failure_dir)
    except (
        AssertionError,
        FileNotFoundError,
        json.JSONDecodeError,
        CorpusValidationError,
        OSError,
        PersistentStateError,
        RuntimeError,
        ValueError,
    ) as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Replaying failure: {failure_dir.name}")
    print(f"  Schema version: {meta.get('schema_version')}")
    print(f"  Category: {meta.get('guest_result_category', 'unknown')}")
    print(f"  Git commit: {meta.get('git_commit', 'unknown')}")

    if args.refresh_host:
        _refresh_host(failure_dir, meta)
    else:
        _replay_guest(failure_dir, meta)


def _replay_common(
    failure_dir: Path,
    workspace: Path,
    refresh_host: bool,
) -> None:
    spec = spec_for_common_failure(failure_dir)
    artifact = load_failure(spec, failure_dir)
    artifact_dir = artifact.path
    temporary = None
    try:
        if refresh_host:
            temporary = tempfile.TemporaryDirectory()
            artifact_dir = Path(temporary.name)
            shutil.copy2(
                artifact.host_elf_path,
                artifact_dir / spec.artifacts.host_executable_filename,
            )
            shutil.copy2(
                artifact.scenario_path,
                artifact_dir / spec.artifacts.scenario_filename,
            )
            recorded = spec.host_record(
                artifact_dir / spec.artifacts.host_executable_filename,
                artifact_dir / spec.artifacts.scenario_filename,
                artifact_dir / spec.artifacts.trace_filename,
            )
            if not recorded.passed:
                raise RuntimeError(recorded.log)
        result = run_common_guest_compare(
            spec,
            workspace,
            artifact_dir,
            pinned_starry_elf=artifact.starry_elf_path,
        )
        print(result.log)
        if not result.passed:
            raise RuntimeError(f"{spec.adapter_id} replay failed")
    finally:
        if temporary is not None:
            temporary.cleanup()


def _replay_guest(failure_dir: Path, meta: Dict):
    elf = failure_dir / "pipe-linux-oracle"
    ops = failure_dir / "pipe.ops"
    trace = failure_dir / "linux.trace"

    run_dir = failure_dir / "replay-runs"
    run_dir.mkdir(parents=True, exist_ok=True)
    run_id = _next_run_id(run_dir)
    run_path = run_dir / run_id
    run_path.mkdir()

    pinned_starry_elf = (
        failure_dir / "starryos"
        if meta.get("schema_version") == 2
        else None
    )
    result = normalize_guest_execution(
        _run_guest_compare(WORKSPACE_ROOT, failure_dir, pinned_starry_elf)
    )
    guest_log = result.log
    profraws = list(result.profraw_paths)
    (run_path / "guest.log").write_text(guest_log)
    for p in profraws:
        shutil.copy2(p, run_path / p.name)

    replay_meta = build_metadata(
        seed=meta.get("fuzz_seed"),
        batch_index=meta.get("batch_index", -1),
        generator_version=meta.get("generator_version", "unknown"),
        input_path=failure_dir / "input.bin" if (failure_dir / "input.bin").exists() else None,
        elf_path=elf,
        ops_path=ops,
        trace_path=trace,
        guest_log_path=run_path / "guest.log",
        profraw_paths=list(run_path.glob("*.profraw")),
        command=" ".join(sys.argv),
        result_category=result.category.value,
    )
    save_metadata(run_path, replay_meta)

    if result.passed:
        print(f"  REPLAY PASSED: saved to {run_path}")
    else:
        print(f"  REPLAY FAILED: saved to {run_path}")
        sys.exit(1)


def _run_guest_compare(
    workspace: Path,
    artifact_dir: Path,
    pinned_starry_elf: Path | None = None,
) -> GuestExecutionResult:
    return run_guest_compare(workspace, artifact_dir, pinned_starry_elf)


def _refresh_host(failure_dir: Path, meta: Dict):
    elf = failure_dir / "pipe-linux-oracle"
    ops = failure_dir / "pipe.ops"

    refresh_dir = failure_dir / "refresh-runs"
    refresh_dir.mkdir(parents=True, exist_ok=True)
    run_id = _next_run_id(refresh_dir)
    run_path = refresh_dir / run_id
    run_path.mkdir()

    new_trace = run_path / "linux.trace"
    result = subprocess.run(
        [str(elf), "--record", str(ops), str(new_trace)],
        capture_output=True, text=True, timeout=30,
    )

    host_log = result.stdout + "\n" + result.stderr
    (run_path / "host.log").write_text(host_log)

    if result.returncode != 0:
        print(f"  HOST RECORD FAILED: saved to {run_path}", file=sys.stderr)
        sys.exit(1)

    refresh_meta = build_metadata(
        seed=meta.get("fuzz_seed"),
        batch_index=meta.get("batch_index", -1),
        generator_version=meta.get("generator_version", "unknown"),
        input_path=failure_dir / "input.bin" if (failure_dir / "input.bin").exists() else None,
        elf_path=elf,
        ops_path=ops,
        trace_path=new_trace,
        guest_log_path=run_path / "host.log",
        profraw_paths=None,
        command=" ".join(sys.argv),
        result_category="refresh-host",
    )
    save_metadata(run_path, refresh_meta)

    old_meta_path = failure_dir / "metadata.json"
    old_meta = json.loads(old_meta_path.read_text())
    print(f"  Old host: {old_meta.get('host_uname', {}).get('release', 'unknown')}")
    print(f"  New host: {refresh_meta.get('host_uname', {}).get('release', 'unknown')}")
    print(f"  Old trace SHA-256: {old_meta.get('trace_sha256', 'unknown')}")
    print(f"  New trace SHA-256: {refresh_meta.get('trace_sha256', 'unknown')}")
    print(f"  Refresh saved to {run_path}")


def _next_run_id(run_dir: Path) -> str:
    existing = [d for d in run_dir.iterdir() if d.is_dir()]
    n = len(existing) + 1
    return f"run-{n:04d}"


if __name__ == "__main__":
    main()
