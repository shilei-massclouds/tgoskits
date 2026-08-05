"""Stable semantic-mismatch fingerprints anchored to original operations."""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from guest_result import OperationDifference
from reducer import OperationOrigin, ReductionInput


_OPERATION_KINDS = {
    "pipe2": 1,
    "read": 2,
    "read-null": 3,
    "write": 4,
    "write-null": 5,
    "dup": 6,
    "close": 7,
    "poll": 8,
    "set-size": 9,
    "get-size": 10,
    "fionread": 11,
    "get-status-flags": 12,
    "set-status-flags": 13,
    "get-fd-flags": 14,
    "set-fd-flags": 15,
    "dup2": 16,
    "dup3": 17,
    "readv": 18,
    "writev": 19,
    "poll-many": 20,
    "start-read": 21,
    "start-write": 22,
    "assert-pending": 23,
    "join": 24,
    "start-poll": 25,
}
_DIFFERENCE_FIELDS = ("result", "errno", "value", "data_len", "data")
_RESULT_CLASSES = {"error", "zero", "positive"}


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
        cls,
        difference: Optional[OperationDifference],
        operation_origin: OperationOrigin,
    ) -> "MismatchFingerprint":
        if difference is None:
            raise ValueError("semantic mismatch lacks a structured difference")
        operation_kind = difference.operation_text.split(maxsplit=1)[0]
        if _OPERATION_KINDS.get(operation_kind) != difference.operation_kind:
            raise ValueError("mismatch operation kind is inconsistent")
        expected_class = _result_class(difference.expected_result)
        actual_class = _result_class(difference.actual_result)
        fingerprint = cls(
            operation_origin,
            operation_kind,
            tuple(difference.difference_fields),
            expected_class,
            actual_class,
            difference.expected_errno if expected_class == "error" else None,
            difference.actual_errno if actual_class == "error" else None,
        )
        fingerprint._validate()
        return fingerprint

    @classmethod
    def for_reduction_input(
        cls,
        difference: Optional[OperationDifference],
        reduction_input: ReductionInput,
    ) -> "MismatchFingerprint":
        if difference is None:
            raise ValueError("semantic mismatch lacks a structured difference")
        origin = operation_origin_for_difference(reduction_input, difference)
        return cls.from_difference(difference, origin)

    @classmethod
    def from_metadata(cls, metadata: Any) -> "MismatchFingerprint":
        expected_keys = {
            "operation_origin",
            "operation_kind",
            "difference_fields",
            "expected_result_class",
            "actual_result_class",
            "expected_errno",
            "actual_errno",
        }
        if not isinstance(metadata, dict) or set(metadata) != expected_keys:
            raise ValueError("mismatch fingerprint keys are invalid")
        origin = metadata["operation_origin"]
        if (
            not isinstance(origin, dict)
            or set(origin) != {"scenario_index", "operation_index"}
            or not _is_nonnegative_integer(origin["scenario_index"])
            or not _is_nonnegative_integer(origin["operation_index"])
        ):
            raise ValueError("mismatch operation origin is invalid")
        fields = metadata["difference_fields"]
        fingerprint = cls(
            OperationOrigin(origin["scenario_index"], origin["operation_index"]),
            metadata["operation_kind"],
            tuple(fields) if isinstance(fields, list) else (),
            metadata["expected_result_class"],
            metadata["actual_result_class"],
            metadata["expected_errno"],
            metadata["actual_errno"],
        )
        fingerprint._validate()
        return fingerprint

    def as_metadata(self) -> Dict[str, Any]:
        self._validate()
        return {
            "operation_origin": {
                "scenario_index": self.operation_origin.scenario_index,
                "operation_index": self.operation_origin.operation_index,
            },
            "operation_kind": self.operation_kind,
            "difference_fields": list(self.difference_fields),
            "expected_result_class": self.expected_result_class,
            "actual_result_class": self.actual_result_class,
            "expected_errno": self.expected_errno,
            "actual_errno": self.actual_errno,
        }

    def _validate(self) -> None:
        if self.operation_kind not in _OPERATION_KINDS:
            raise ValueError("mismatch operation kind is invalid")
        expected_fields = tuple(
            field for field in _DIFFERENCE_FIELDS if field in self.difference_fields
        )
        if (
            not self.difference_fields
            or self.difference_fields != expected_fields
            or len(set(self.difference_fields)) != len(self.difference_fields)
        ):
            raise ValueError("mismatch difference fields are invalid")
        for result_class, error in (
            (self.expected_result_class, self.expected_errno),
            (self.actual_result_class, self.actual_errno),
        ):
            if result_class not in _RESULT_CLASSES:
                raise ValueError("mismatch result class is invalid")
            if result_class == "error":
                if not _is_nonnegative_integer(error) or error == 0:
                    raise ValueError("failing result requires an exact errno")
            elif error is not None:
                raise ValueError("successful result cannot retain an errno")


def operation_origin_for_difference(
    reduction_input: ReductionInput,
    difference: OperationDifference,
) -> OperationOrigin:
    if difference.scenario_index >= len(reduction_input.origins):
        raise ValueError("mismatch scenario is absent from the reduction candidate")
    flattened = tuple(
        origin for scenario_origins in reduction_input.origins for origin in scenario_origins
    )
    if difference.operation_index >= len(flattened):
        raise ValueError("mismatch operation is absent from the reduction candidate")
    scenario_origins = reduction_input.origins[difference.scenario_index]
    origin = flattened[difference.operation_index]
    if origin not in scenario_origins:
        raise ValueError("mismatch scenario and operation indices disagree")
    return origin


def _result_class(result: int) -> str:
    if result < 0:
        return "error"
    if result == 0:
        return "zero"
    return "positive"


def _is_nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


__all__ = [
    "MismatchFingerprint",
    "OperationOrigin",
    "operation_origin_for_difference",
]
