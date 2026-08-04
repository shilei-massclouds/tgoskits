#!/usr/bin/env python3
"""Replay one strict saved eventfd failure artifact."""

import argparse
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence

from artifact import load_failure
from host_runtime import record_host
from runner import run_guest_compare
from store import PersistentStateError


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("failure", type=Path)
    parser.add_argument("--refresh-host", action="store_true")
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)
    try:
        artifact = load_failure(args.failure)
        artifact_dir = artifact.path
        temporary = None
        if args.refresh_host:
            temporary = tempfile.TemporaryDirectory()
            artifact_dir = Path(temporary.name)
            shutil.copy2(artifact.host_elf_path, artifact_dir / "eventfd-linux-oracle")
            shutil.copy2(artifact.ops_path, artifact_dir / "eventfd.ops")
            recorded = record_host(
                artifact_dir / "eventfd-linux-oracle",
                artifact_dir / "eventfd.ops",
                artifact_dir / "linux.trace",
            )
            if not recorded.passed:
                print(recorded.log, file=sys.stderr)
                return 1
        result = run_guest_compare(
            args.workspace.resolve(), artifact_dir, artifact.starry_elf_path
        )
        print(result.log)
        if temporary is not None:
            temporary.cleanup()
        return 0 if result.passed else 1
    except (OSError, PersistentStateError, ValueError) as error:
        print(f"eventfd replay failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
