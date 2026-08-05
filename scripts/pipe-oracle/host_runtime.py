"""Build and invoke the host Linux pipe oracle."""

import os
import subprocess
from pathlib import Path
from typing import Optional

from linux_oracle.batch import HostRecordResult


def find_or_build_host_oracle(workspace: Path) -> Optional[Path]:
    source_dir = workspace / "test-suit/starryos/qemu/pipe-linux-oracle/c"
    build_dir = workspace / "target/pipe-oracle-host"
    elf_path = build_dir / "pipe-linux-oracle"

    build_environment = os.environ.copy()
    build_environment.pop("STARRY_PIPE_ORACLE_ARTIFACT_DIR", None)
    try:
        subprocess.run(
            ["cmake", "-S", str(source_dir), "-B", str(build_dir)],
            cwd=str(workspace),
            env=build_environment,
            check=True,
        )
        subprocess.run(
            ["cmake", "--build", str(build_dir), "--target", "pipe-linux-oracle"],
            cwd=str(workspace),
            env=build_environment,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return elf_path if elf_path.is_file() else None


def record_host(elf: Path, ops: Path, trace: Path) -> HostRecordResult:
    environment = os.environ.copy()
    environment.pop("STARRY_PIPE_CONCURRENT_START_BIAS", None)
    return _record_host(elf, ops, trace, environment)


def record_host_scheduled(
    elf: Path, ops: Path, trace: Path, run_index: int
) -> HostRecordResult:
    environment = os.environ.copy()
    environment["STARRY_PIPE_CONCURRENT_START_BIAS"] = str(run_index % 2 + 1)
    return _record_host(elf, ops, trace, environment)


def _record_host(
    elf: Path, ops: Path, trace: Path, environment: dict[str, str]
) -> HostRecordResult:
    try:
        result = subprocess.run(
            [str(elf), "--record", str(ops), str(trace)],
            capture_output=True,
            env=environment,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return HostRecordResult(False, False, str(error))
    log = result.stdout + "\n" + result.stderr
    return HostRecordResult(
        result.returncode == 0,
        result.returncode != 0 and _is_host_parser_rejection(result.stderr),
        log,
    )


def _is_host_parser_rejection(stderr: str) -> bool:
    parser_messages = (
        "corpus line is too long",
        "invalid corpus version",
        "invalid scenario",
        "invalid operation",
        "operation appears before first scenario",
        "operation corpus is incomplete",
    )
    return any(message in stderr for message in parser_messages)


__all__ = ["find_or_build_host_oracle", "record_host", "record_host_scheduled"]
