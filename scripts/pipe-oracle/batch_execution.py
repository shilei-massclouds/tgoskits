"""Shared deterministic host-record and Starry-compare batch execution."""

import hashlib
import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Optional, Tuple

from guest_result import GuestExecutionResult, normalize_guest_execution
from scenario import (
    ScenarioDocument,
    combine_documents,
    parse_document,
    serialize_document,
)


@dataclass(frozen=True)
class HostRecordResult:
    passed: bool
    parser_rejection: bool
    log: str


@dataclass(frozen=True)
class BatchInput:
    digest: str
    encoded: bytes


@dataclass(frozen=True)
class PreparedBatch:
    inputs: Tuple[BatchInput, ...]
    document: ScenarioDocument
    ops_text: str
    ops_digest: str
    scenario_count: int


@dataclass(frozen=True)
class BatchExecution:
    prepared: PreparedBatch
    artifact_dir: Path
    ops_path: Path
    trace_path: Path
    host_oracle_path: Path
    host_record: HostRecordResult
    guest_result: Optional[GuestExecutionResult]


def prepare_batch(inputs: Tuple[BatchInput, ...]) -> PreparedBatch:
    """Validate and combine canonical inputs in digest order."""
    if not inputs:
        raise ValueError("batch execution requires at least one input")
    ordered = tuple(sorted(inputs, key=lambda item: item.digest))
    if tuple(item.digest for item in ordered) != tuple(
        sorted({item.digest for item in ordered})
    ):
        raise ValueError("batch inputs must have unique canonical digests")
    documents = []
    for item in ordered:
        if hashlib.sha256(item.encoded).hexdigest() != item.digest:
            raise ValueError(f"batch input digest mismatch: {item.digest}")
        document = parse_document(item.encoded)
        if serialize_document(document).encode("utf-8") != item.encoded:
            raise ValueError(f"batch input is not canonical: {item.digest}")
        documents.append(document)
    document = combine_documents(documents)
    ops_text = serialize_document(document)
    return PreparedBatch(
        ordered,
        document,
        ops_text,
        hashlib.sha256(ops_text.encode("utf-8")).hexdigest(),
        sum(len(item.scenarios) for item in documents),
    )


@contextmanager
def execute_batch(
    workspace: Path,
    inputs: Tuple[BatchInput, ...],
    host_oracle: Path,
    record_host: Callable[[Path, Path, Path], HostRecordResult],
    run_guest_compare: Callable[[Path, Path, Optional[Path]], object],
    *,
    pinned_starry_elf: Optional[Path] = None,
) -> Iterator[BatchExecution]:
    """Record one combined host trace, then compare it in one Starry QEMU run."""
    prepared = prepare_batch(inputs)
    if host_oracle.is_symlink() or not host_oracle.is_file():
        raise FileNotFoundError(f"host oracle is not a regular file: {host_oracle}")
    with tempfile.TemporaryDirectory() as temporary_directory:
        artifact_dir = Path(temporary_directory)
        ops_path = artifact_dir / "pipe.ops"
        trace_path = artifact_dir / "linux.trace"
        artifact_oracle = artifact_dir / "pipe-linux-oracle"
        ops_path.write_text(prepared.ops_text, encoding="utf-8")
        host_record = record_host(host_oracle, ops_path, trace_path)
        if host_record.passed and not trace_path.is_file():
            host_record = HostRecordResult(
                False,
                False,
                host_record.log + "\nHost record reported success without a trace.\n",
            )
        guest_result = None
        if host_record.passed:
            shutil.copy2(host_oracle, artifact_oracle)
            guest_result = normalize_guest_execution(
                run_guest_compare(workspace, artifact_dir, pinned_starry_elf)
            )
        yield BatchExecution(
            prepared,
            artifact_dir,
            ops_path,
            trace_path,
            artifact_oracle,
            host_record,
            guest_result,
        )


__all__ = [
    "BatchExecution",
    "BatchInput",
    "HostRecordResult",
    "PreparedBatch",
    "execute_batch",
    "prepare_batch",
]
