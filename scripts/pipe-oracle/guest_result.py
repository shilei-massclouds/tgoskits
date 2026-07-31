"""Typed classification and semantic-difference parsing for guest replays."""

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Optional, Tuple


class GuestResultCategory(str, Enum):
    PASSED = "passed"
    SEMANTIC_MISMATCH = "semantic-mismatch"
    ORACLE_FAILURE = "oracle-failure"
    KERNEL_PANIC = "kernel-panic"
    LOCKDEP_FAILURE = "lockdep-failure"
    TIMEOUT = "timeout"
    INFRASTRUCTURE_FAILURE = "infrastructure-failure"


@dataclass(frozen=True)
class OperationDifference:
    scenario_index: int
    operation_index: int
    operation_text: str
    operation_kind: int
    difference_fields: Tuple[str, ...]
    expected_result: int
    expected_errno: int
    expected_value: int
    expected_data_len: int
    actual_result: int
    actual_errno: int
    actual_value: int
    actual_data_len: int


@dataclass(frozen=True)
class GuestExecutionResult:
    category: GuestResultCategory
    log: str
    profraw_paths: Tuple[Path, ...]
    returncode: Optional[int]
    difference: Optional[OperationDifference] = None

    @property
    def passed(self) -> bool:
        return self.category == GuestResultCategory.PASSED

    def __iter__(self):
        """Keep legacy tuple unpacking readable while callers migrate to categories."""
        yield self.log
        yield list(self.profraw_paths)
        yield self.passed


DIFFERENCE_BITS = {
    1 << 3: "result",
    1 << 4: "errno",
    1 << 5: "value",
    1 << 6: "data_len",
    1 << 7: "data",
}
IDENTITY_DIFFERENCE_MASK = (1 << 0) | (1 << 1) | (1 << 2)
KNOWN_DIFFERENCE_MASK = IDENTITY_DIFFERENCE_MASK | sum(DIFFERENCE_BITS)

_DIFFERENCE_RE = re.compile(
    r"STARRY_PIPE_LINUX_ORACLE_FAILED: host=[^\r\n]*?\s+line=(?P<line>[0-9]+)\s+"
    r"scenario=(?P<scenario>[0-9]+)\s+operation=(?P<operation>[0-9]+)\s+"
    r'text="(?P<text>[^"]*)"(?:\s+difference_mask=0x(?P<mask>[0-9a-fA-F]+))?\s+'
    r"expected=\{kind=(?P<expected_kind>[0-9]+),result=(?P<expected_result>-?[0-9]+),"
    r"errno=(?P<expected_errno>-?[0-9]+),value=(?P<expected_value>-?[0-9]+),"
    r"data_len=(?P<expected_data_len>[0-9]+)\}\s+"
    r"actual=\{kind=(?P<actual_kind>[0-9]+),result=(?P<actual_result>-?[0-9]+),"
    r"errno=(?P<actual_errno>-?[0-9]+),value=(?P<actual_value>-?[0-9]+),"
    r"data_len=(?P<actual_data_len>[0-9]+)\}",
)

_PANIC_RE = re.compile(r"(?i)\bpanic(?:ked)?\b")
_LOCKDEP_RE = re.compile(r"(?m)^lockdep fatal violation\s*$", re.IGNORECASE)
_ORACLE_FAILURE_MARKER = "STARRY_PIPE_LINUX_ORACLE_FAILED:"


def classify_guest_execution(
    log: str,
    returncode: Optional[int],
    profraw_paths: Iterable[Path] = (),
    *,
    timed_out: bool = False,
) -> GuestExecutionResult:
    paths = tuple(profraw_paths)
    if timed_out:
        return GuestExecutionResult(
            GuestResultCategory.TIMEOUT,
            log,
            paths,
            returncode,
        )
    if _LOCKDEP_RE.search(log):
        return GuestExecutionResult(
            GuestResultCategory.LOCKDEP_FAILURE,
            log,
            paths,
            returncode,
        )
    if _PANIC_RE.search(log):
        return GuestExecutionResult(
            GuestResultCategory.KERNEL_PANIC,
            log,
            paths,
            returncode,
        )

    difference = parse_operation_difference(log)
    if difference is not None:
        return GuestExecutionResult(
            GuestResultCategory.SEMANTIC_MISMATCH,
            log,
            paths,
            returncode,
            difference,
        )
    if _ORACLE_FAILURE_MARKER in log:
        return GuestExecutionResult(
            GuestResultCategory.ORACLE_FAILURE,
            log,
            paths,
            returncode,
        )
    if returncode == 0:
        return GuestExecutionResult(
            GuestResultCategory.PASSED,
            log,
            paths,
            returncode,
        )
    return GuestExecutionResult(
        GuestResultCategory.INFRASTRUCTURE_FAILURE,
        log,
        paths,
        returncode,
    )


def normalize_guest_execution(value: Any) -> GuestExecutionResult:
    """Accept old test doubles without weakening the production runner contract."""
    if isinstance(value, GuestExecutionResult):
        return value
    if (
        isinstance(value, tuple)
        and len(value) == 3
        and isinstance(value[0], str)
        and isinstance(value[2], bool)
    ):
        log, profraw_paths, passed = value
        return GuestExecutionResult(
            GuestResultCategory.PASSED
            if passed
            else GuestResultCategory.SEMANTIC_MISMATCH,
            log,
            tuple(profraw_paths),
            0 if passed else 1,
        )
    raise TypeError("guest execution must be a GuestExecutionResult")


def parse_operation_difference(log: str) -> Optional[OperationDifference]:
    matches = tuple(_DIFFERENCE_RE.finditer(log))
    if len(matches) != 1:
        return None
    fields = matches[0].groupdict()
    expected_kind = int(fields["expected_kind"])
    actual_kind = int(fields["actual_kind"])
    if expected_kind != actual_kind:
        return None

    scalar_pairs = {
        "result": (int(fields["expected_result"]), int(fields["actual_result"])),
        "errno": (int(fields["expected_errno"]), int(fields["actual_errno"])),
        "value": (int(fields["expected_value"]), int(fields["actual_value"])),
        "data_len": (
            int(fields["expected_data_len"]),
            int(fields["actual_data_len"]),
        ),
    }
    if fields["mask"] is None:
        difference_fields = tuple(
            name for name, values in scalar_pairs.items() if values[0] != values[1]
        )
        if not difference_fields:
            difference_fields = ("data",)
    else:
        mask = int(fields["mask"], 16)
        if mask == 0 or mask & ~KNOWN_DIFFERENCE_MASK or mask & IDENTITY_DIFFERENCE_MASK:
            return None
        difference_fields = tuple(
            name for bit, name in DIFFERENCE_BITS.items() if mask & bit
        )
        visible_fields = {
            name for name, values in scalar_pairs.items() if values[0] != values[1]
        }
        if visible_fields != set(difference_fields) - {"data"}:
            return None

    return OperationDifference(
        scenario_index=int(fields["scenario"]),
        operation_index=int(fields["operation"]),
        operation_text=fields["text"],
        operation_kind=actual_kind,
        difference_fields=difference_fields,
        expected_result=scalar_pairs["result"][0],
        expected_errno=scalar_pairs["errno"][0],
        expected_value=scalar_pairs["value"][0],
        expected_data_len=scalar_pairs["data_len"][0],
        actual_result=scalar_pairs["result"][1],
        actual_errno=scalar_pairs["errno"][1],
        actual_value=scalar_pairs["value"][1],
        actual_data_len=scalar_pairs["data_len"][1],
    )


__all__ = [
    "GuestExecutionResult",
    "GuestResultCategory",
    "OperationDifference",
    "classify_guest_execution",
    "normalize_guest_execution",
    "parse_operation_difference",
]
