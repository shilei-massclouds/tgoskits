"""Stable eventfd mismatch fingerprints anchored to original operations."""

from dataclasses import dataclass
from typing import Optional, Tuple

from guest_result import OperationDifference
from reducer import OperationOrigin


_KINDS = {
    "eventfd": 1,
    "eventfd2": 2,
    "read": 3,
    "write": 4,
    "dup": 5,
    "dup2": 6,
    "dup3": 7,
    "close": 8,
    "get-status-flags": 9,
    "set-status-flags": 10,
    "get-fd-flags": 11,
    "set-fd-flags": 12,
    "poll-many": 13,
    "start-read": 14,
    "start-write": 15,
    "assert-pending": 16,
    "join": 17,
    "start-poll": 18,
    "assert-all-pending": 19,
    "join-set": 20,
}
_FIELD_ORDER = ("result", "errno", "value", "data_len", "data")


@dataclass(frozen=True)
class MismatchFingerprint:
    operation_origin: OperationOrigin
    operation_kind: str
    difference_fields: Tuple[str, ...]
    expected_result_class: str
    actual_result_class: str
    expected_errno: Optional[int]
    actual_errno: Optional[int]

    @classmethod
    def from_difference(
        cls, difference: OperationDifference, origin: OperationOrigin
    ) -> "MismatchFingerprint":
        operation_kind = difference.operation_text.split(maxsplit=1)[0]
        if _KINDS.get(operation_kind) != difference.operation_kind:
            raise ValueError("mismatch operation kind is inconsistent")
        expected_class = _result_class(difference.expected_result)
        actual_class = _result_class(difference.actual_result)
        fields = tuple(difference.difference_fields)
        if fields != tuple(field for field in _FIELD_ORDER if field in fields):
            raise ValueError("mismatch difference fields are not canonical")
        return cls(
            origin,
            operation_kind,
            fields,
            expected_class,
            actual_class,
            difference.expected_errno if expected_class == "error" else None,
            difference.actual_errno if actual_class == "error" else None,
        )


def _result_class(result: int) -> str:
    if result < 0:
        return "error"
    if result == 0:
        return "zero"
    return "positive"


__all__ = ["MismatchFingerprint"]
