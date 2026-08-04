"""Compatibility entry points for common eventfd batch execution."""

import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Optional, Tuple

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from adapter import SPEC
from linux_oracle.batch import (
    BatchExecution,
    BatchInput,
    HostRecordResult,
    PreparedBatch,
)
from linux_oracle.batch import execute_batch as _execute_batch
from linux_oracle.batch import prepare_batch as _prepare_batch


def prepare_batch(inputs: Tuple[BatchInput, ...]) -> PreparedBatch:
    return _prepare_batch(SPEC, inputs)


@contextmanager
def execute_batch(
    workspace: Path,
    inputs: Tuple[BatchInput, ...],
    host_oracle: Path,
    record_host: Callable[[Path, Path, Path], object],
    run_guest_compare: Callable[[Path, Path, Optional[Path]], object],
    *,
    pinned_starry_elf: Optional[Path] = None,
) -> Iterator[BatchExecution]:
    with _execute_batch(
        SPEC,
        workspace,
        inputs,
        host_oracle,
        record_host,
        run_guest_compare,
        pinned_starry_elf=pinned_starry_elf,
    ) as execution:
        yield execution


__all__ = [
    "BatchExecution",
    "BatchInput",
    "HostRecordResult",
    "PreparedBatch",
    "execute_batch",
    "prepare_batch",
]
