"""Build and invoke the host Linux eventfd oracle."""

import os
import subprocess
from pathlib import Path
from typing import Optional

from linux_oracle.batch import HostRecordResult


def find_or_build_host_oracle(workspace: Path) -> Optional[Path]:
    source = workspace / "test-suit/starryos/qemu/eventfd-linux-oracle/c"
    build = workspace / "target/eventfd-oracle-host"
    elf = build / "eventfd-linux-oracle"
    environment = os.environ.copy()
    environment.pop("STARRY_EVENTFD_ORACLE_ARTIFACT_DIR", None)
    try:
        subprocess.run(
            ["cmake", "-S", str(source), "-B", str(build)],
            cwd=workspace,
            env=environment,
            check=True,
        )
        subprocess.run(
            ["cmake", "--build", str(build), "--target", "eventfd-linux-oracle"],
            cwd=workspace,
            env=environment,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return elf if elf.is_file() else None


def record_host(elf: Path, ops: Path, trace: Path) -> HostRecordResult:
    environment = os.environ.copy()
    environment.pop("STARRY_EVENTFD_CONCURRENT_START_BIAS", None)
    environment.pop("STARRY_EVENTFD_CONCURRENT_COMPLETION_SCHEDULE", None)
    return _record_host(elf, ops, trace, environment)


def record_host_scheduled(
    elf: Path, ops: Path, trace: Path, run_index: int
) -> HostRecordResult:
    environment = os.environ.copy()
    environment["STARRY_EVENTFD_CONCURRENT_START_BIAS"] = str(
        run_index % 2 + 1
    )
    environment["STARRY_EVENTFD_CONCURRENT_COMPLETION_SCHEDULE"] = str(
        run_index % 4
    )
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
        result.returncode != 0 and _is_parser_rejection(result.stderr),
        log,
    )


def _is_parser_rejection(stderr: str) -> bool:
    messages = (
        "corpus line is too long",
        "invalid corpus version",
        "invalid scenario",
        "invalid operation",
        "operation appears before first scenario",
        "operation corpus is incomplete",
    )
    return any(message in stderr for message in messages)


__all__ = [
    "HostRecordResult",
    "find_or_build_host_oracle",
    "record_host",
    "record_host_scheduled",
]
