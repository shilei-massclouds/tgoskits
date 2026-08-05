"""Typed classification and semantic-difference parsing for guest replays."""

import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Optional, Tuple, Union


class GuestResultCategory(str, Enum):
    PASSED = "passed"
    SEMANTIC_MISMATCH = "semantic-mismatch"
    ORACLE_FAILURE = "oracle-failure"
    KERNEL_PANIC = "kernel-panic"
    LOCKDEP_FAILURE = "lockdep-failure"
    SYSCALL_TIMEOUT = "syscall-timeout"
    SCHEDULE_TIMEOUT = "schedule-timeout"
    HARNESS_ERROR = "harness-error"
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
class ConcurrentScenarioDifference:
    scenario_index: int
    alternative_index: int
    byte_offset: int
    expected_length: int
    actual_length: int
    expected_byte: int
    actual_byte: int
    allowed_set_digest: str
    actual_digest: str
    actual_vector: str


@dataclass(frozen=True)
class GuestExecutionResult:
    category: GuestResultCategory
    log: str
    profraw_paths: Tuple[Path, ...]
    returncode: Optional[int]
    difference: Optional[Union[OperationDifference, ConcurrentScenarioDifference]] = None

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
_CONCURRENT_DIFFERENCE_RE = re.compile(
    r"STARRY_PIPE_CONCURRENT_MISMATCH:\s+scenario=(?P<scenario>[0-9]+)\s+"
    r"alternative=(?P<alternative>[0-9]+)\s+byte_offset=(?P<byte_offset>[0-9]+)\s+"
    r"expected_length=(?P<expected_length>[0-9]+)\s+"
    r"actual_length=(?P<actual_length>[0-9]+)\s+"
    r"expected_byte=(?P<expected_byte>[0-9]+)\s+"
    r"actual_byte=(?P<actual_byte>[0-9]+)\s+"
    r"set_digest=(?P<set_digest>[0-9a-f]{64})\s+"
    r"actual_digest=(?P<actual_digest>[0-9a-f]{64})\s+"
    r"actual_vector=(?P<actual_vector>[0-9a-f]+)"
)

_PANIC_RE = re.compile(r"(?i)\bpanic(?:ked)?\b")
_LOCKDEP_RE = re.compile(r"(?m)^lockdep fatal violation\s*$", re.IGNORECASE)
_ORACLE_FAILURE_MARKER = "STARRY_PIPE_LINUX_ORACLE_FAILED:"
_CONCURRENT_MISMATCH_MARKER = "STARRY_PIPE_CONCURRENT_MISMATCH:"
_SYSCALL_TIMEOUT_MARKER = "STARRY_PIPE_LINUX_ORACLE_SYSCALL_TIMEOUT:"
_SCHEDULE_TIMEOUT_MARKER = "STARRY_PIPE_LINUX_ORACLE_SCHEDULE_TIMEOUT:"
_HARNESS_ERROR_MARKER = "STARRY_PIPE_LINUX_ORACLE_HARNESS_ERROR:"


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

    if _SYSCALL_TIMEOUT_MARKER in log:
        return GuestExecutionResult(
            GuestResultCategory.SYSCALL_TIMEOUT,
            log,
            paths,
            returncode,
        )
    if _SCHEDULE_TIMEOUT_MARKER in log:
        return GuestExecutionResult(
            GuestResultCategory.SCHEDULE_TIMEOUT,
            log,
            paths,
            returncode,
        )
    if _HARNESS_ERROR_MARKER in log:
        return GuestExecutionResult(
            GuestResultCategory.HARNESS_ERROR,
            log,
            paths,
            returncode,
        )

    concurrent_difference = parse_concurrent_difference(log)
    if concurrent_difference is not None:
        return GuestExecutionResult(
            GuestResultCategory.SEMANTIC_MISMATCH,
            log,
            paths,
            returncode,
            concurrent_difference,
        )
    if _CONCURRENT_MISMATCH_MARKER in log:
        return GuestExecutionResult(
            GuestResultCategory.ORACLE_FAILURE,
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


def parse_concurrent_difference(
    log: str,
) -> Optional[ConcurrentScenarioDifference]:
    matches = tuple(_CONCURRENT_DIFFERENCE_RE.finditer(log))
    if len(matches) != 1:
        return None
    fields = matches[0].groupdict()
    expected_length = int(fields["expected_length"])
    actual_length = int(fields["actual_length"])
    byte_offset = int(fields["byte_offset"])
    expected_byte = int(fields["expected_byte"])
    actual_byte = int(fields["actual_byte"])
    actual_vector = fields["actual_vector"]
    if (
        expected_length <= 0
        or actual_length <= 0
        or expected_length % 112 != 0
        or actual_length % 112 != 0
        or len(actual_vector) != actual_length * 2
        or byte_offset > min(expected_length, actual_length)
        or expected_byte > 255
        or actual_byte > 255
        or hashlib.sha256(bytes.fromhex(actual_vector)).hexdigest()
        != fields["actual_digest"]
    ):
        return None
    return ConcurrentScenarioDifference(
        int(fields["scenario"]),
        int(fields["alternative"]),
        byte_offset,
        expected_length,
        actual_length,
        expected_byte,
        actual_byte,
        fields["set_digest"],
        fields["actual_digest"],
        actual_vector,
    )


__all__ = [
    "ConcurrentScenarioDifference",
    "GuestExecutionResult",
    "GuestResultCategory",
    "OperationDifference",
    "classify_guest_execution",
    "normalize_guest_execution",
    "parse_concurrent_difference",
    "parse_operation_difference",
]
