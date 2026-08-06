#!/usr/bin/env python3
"""Replay one strict saved eventfd failure artifact."""

import argparse
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence

from linux_oracle.failure import load_failure
from linux_oracle.batch import merge_persistent_outcomes
from linux_oracle.persistence import PersistentStateError
from linux_oracle.qemu import run_guest_compare
from models import spec_for_failure


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("failure", type=Path)
    parser.add_argument("--refresh-host", action="store_true")
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)
    try:
        spec = spec_for_failure(args.failure)
        artifact = load_failure(spec, args.failure)
        artifact_dir = artifact.path
        temporary = None
        if args.refresh_host:
            temporary = tempfile.TemporaryDirectory()
            artifact_dir = Path(temporary.name)
            shutil.copy2(
                artifact.host_elf_path,
                artifact_dir / spec.artifacts.host_executable_filename,
            )
            shutil.copy2(
                artifact.ops_path,
                artifact_dir / spec.artifacts.scenario_filename,
            )
            recorded = spec.host_record(
                artifact_dir / spec.artifacts.host_executable_filename,
                artifact_dir / spec.artifacts.scenario_filename,
                artifact_dir / spec.artifacts.trace_filename,
            )
            if not recorded.passed:
                print(recorded.log, file=sys.stderr)
                return 1
            encoded = (
                artifact_dir / spec.artifacts.scenario_filename
            ).read_bytes()
            if spec.outcomes is not None:
                merge_persistent_outcomes(
                    spec,
                    args.workspace.resolve(),
                    spec.codec.parse(encoded),
                    encoded,
                    artifact_dir / spec.artifacts.trace_filename,
                )
        result = run_guest_compare(
            spec,
            args.workspace.resolve(),
            artifact_dir,
            pinned_starry_elf=artifact.starry_elf_path,
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
