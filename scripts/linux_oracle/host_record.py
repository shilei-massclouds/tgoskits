"""Stable repeated host recording for controlled blocking adapters."""

import shutil
import tempfile
from pathlib import Path
from typing import Callable

from .batch import HostRecordResult


HostRecorder = Callable[[Path, Path, Path], HostRecordResult]


def record_stable_host(
    record_once: HostRecorder,
    elf: Path,
    scenario_path: Path,
    trace_path: Path,
    *,
    temporary_prefix: str,
) -> HostRecordResult:
    """Accept exactly three successful byte-identical host recordings."""
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=temporary_prefix, dir=trace_path.parent
    ) as temporary_directory:
        temporary = Path(temporary_directory)
        recorded_traces = []
        logs = []
        for index in range(3):
            candidate_trace = temporary / f"linux-{index}.trace"
            result = record_once(elf, scenario_path, candidate_trace)
            logs.append(result.log)
            if not result.passed:
                return HostRecordResult(
                    False, result.parser_rejection, "\n".join(logs)
                )
            recorded_traces.append(candidate_trace.read_bytes())
        if len(set(recorded_traces)) != 1:
            return HostRecordResult(
                False,
                False,
                "blocking host trace is not byte-stable across three recordings",
            )
        shutil.copy2(temporary / "linux-0.trace", trace_path)
    return HostRecordResult(True, False, "\n".join(logs))


__all__ = ["HostRecorder", "record_stable_host"]
