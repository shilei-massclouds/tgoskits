"""Stable and converged host recording for controlled adapters."""

import shutil
import tempfile
from pathlib import Path
from typing import Callable, Iterable, Optional

from .batch import HostRecordResult
from .outcomes import (
    AllowedOutcomeError,
    AllowedOutcomeRecorder,
    ScenarioRun,
    fnv1a64,
)


HostRecorder = Callable[[Path, Path, Path], HostRecordResult]
IndexedHostRecorder = Callable[[Path, Path, Path, int], HostRecordResult]
RunTraceDecoder = Callable[[Path], Iterable[ScenarioRun]]
ProgressReporter = Callable[[int, int], None]


def record_converged_host(
    record_once: HostRecorder,
    decode_run_trace: RunTraceDecoder,
    elf: Path,
    scenario_path: Path,
    trace_path: Path,
    *,
    magic: bytes,
    version: int,
    temporary_prefix: str,
    deterministic: Iterable[int] = (),
    indexed_record_once: Optional[IndexedHostRecorder] = None,
    progress: Optional[ProgressReporter] = None,
) -> HostRecordResult:
    """Record 32 host runs and atomically persist one converged allowed set."""
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    recorder = AllowedOutcomeRecorder(deterministic=deterministic)
    logs = []
    try:
        with tempfile.TemporaryDirectory(
            prefix=temporary_prefix, dir=trace_path.parent
        ) as temporary_directory:
            temporary = Path(temporary_directory)
            for index in range(recorder.expected_runs):
                raw_trace = temporary / f"linux-{index:02d}.trace"
                result = (
                    indexed_record_once(elf, scenario_path, raw_trace, index)
                    if indexed_record_once is not None
                    else record_once(elf, scenario_path, raw_trace)
                )
                logs.append(result.log)
                if not result.passed:
                    return HostRecordResult(
                        False, result.parser_rejection, "\n".join(logs)
                    )
                recorder.add_run(tuple(decode_run_trace(raw_trace)))
                if progress is not None:
                    progress(index + 1, recorder.expected_runs)
            allowed = recorder.finish(
                version=version,
                corpus_digest=fnv1a64(scenario_path.read_bytes()),
            )
            staged = temporary / "allowed.trace"
            staged.write_bytes(allowed.to_bytes(magic))
            shutil.copy2(staged, trace_path)
    except (AllowedOutcomeError, OSError) as error:
        return HostRecordResult(False, False, f"host-unstable: {error}")
    return HostRecordResult(True, False, "\n".join(logs))


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


__all__ = [
    "HostRecorder",
    "IndexedHostRecorder",
    "ProgressReporter",
    "RunTraceDecoder",
    "record_converged_host",
    "record_stable_host",
]
