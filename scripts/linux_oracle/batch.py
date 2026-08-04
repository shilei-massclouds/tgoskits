"""Deterministic host-record and guest-compare batch execution."""

import hashlib
import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Optional, Tuple

from .spec import AdapterSpec


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
    document: object
    encoded: bytes
    scenario_digest: str
    scenario_count: int

    @property
    def ops_text(self) -> str:
        return self.encoded.decode("utf-8")

    @property
    def ops_digest(self) -> str:
        return self.scenario_digest


@dataclass(frozen=True)
class BatchExecution:
    prepared: PreparedBatch
    artifact_dir: Path
    scenario_path: Path
    trace_path: Path
    host_oracle_path: Path
    host_record: object
    guest_result: Optional[object]

    @property
    def ops_path(self) -> Path:
        return self.scenario_path


def prepare_batch(spec: AdapterSpec, inputs: Tuple[BatchInput, ...]) -> PreparedBatch:
    if not inputs:
        raise ValueError("batch execution requires at least one input")
    ordered = tuple(sorted(inputs, key=lambda item: item.digest))
    if len({item.digest for item in ordered}) != len(ordered):
        raise ValueError("batch inputs must have unique canonical digests")
    documents = []
    for item in ordered:
        if hashlib.sha256(item.encoded).hexdigest() != item.digest:
            raise ValueError(f"batch input digest mismatch: {item.digest}")
        document = spec.codec.parse(item.encoded)
        spec.codec.validate_entry(document)
        if spec.codec.serialize(document) != item.encoded:
            raise ValueError(f"batch input is not canonical: {item.digest}")
        documents.append(document)
    combined = spec.codec.combine(documents)
    encoded = spec.codec.serialize(combined)
    return PreparedBatch(
        ordered,
        combined,
        encoded,
        hashlib.sha256(encoded).hexdigest(),
        sum(spec.codec.scenario_count(document) for document in documents),
    )


@contextmanager
def execute_batch(
    spec: AdapterSpec,
    workspace: Path,
    inputs: Tuple[BatchInput, ...],
    host_oracle: Path,
    record_host: Optional[Callable[[Path, Path, Path], object]] = None,
    run_guest: Optional[Callable[[Path, Path, Optional[Path]], object]] = None,
    *,
    pinned_starry_elf: Optional[Path] = None,
) -> Iterator[BatchExecution]:
    prepared = prepare_batch(spec, inputs)
    if host_oracle.is_symlink() or not host_oracle.is_file():
        raise FileNotFoundError(f"host oracle is not a regular file: {host_oracle}")
    with tempfile.TemporaryDirectory() as temporary_directory:
        artifact_dir = Path(temporary_directory)
        scenario_path = artifact_dir / spec.artifacts.scenario_filename
        trace_path = artifact_dir / spec.artifacts.trace_filename
        artifact_oracle = artifact_dir / spec.artifacts.host_executable_filename
        scenario_path.write_bytes(prepared.encoded)
        host_record_call = record_host or spec.host_record
        host_record = host_record_call(host_oracle, scenario_path, trace_path)
        if host_record.passed and not trace_path.is_file():
            host_record = HostRecordResult(
                False,
                False,
                host_record.log + "\nHost record reported success without a trace.\n",
            )
        guest_result = None
        if host_record.passed:
            shutil.copy2(host_oracle, artifact_oracle)
            if run_guest is None:
                from .qemu import run_guest_compare

                raw_guest_result = run_guest_compare(
                    spec,
                    workspace,
                    artifact_dir,
                    pinned_starry_elf=pinned_starry_elf,
                )
            else:
                raw_guest_result = run_guest(
                    workspace, artifact_dir, pinned_starry_elf
                )
            guest_result = spec.normalize_guest(raw_guest_result)
        yield BatchExecution(
            prepared,
            artifact_dir,
            scenario_path,
            trace_path,
            artifact_oracle,
            host_record,
            guest_result,
        )
