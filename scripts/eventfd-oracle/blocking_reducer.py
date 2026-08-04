"""Deterministic reduction that preserves controlled blocking lifecycles."""

from dataclasses import dataclass, replace
from typing import Iterator, Optional, Tuple

from blocking_scenario import (
    AssertPending,
    EventFd,
    EventFd2,
    Join,
    Scenario,
    ScenarioCodecError,
    ScenarioDocument,
    StartRead,
    StartWrite,
    Write,
    canonical_digest,
    serialize_document,
    validate_entry_limits,
)


@dataclass(frozen=True, order=True)
class OperationOrigin:
    scenario_index: int
    operation_index: int


@dataclass(frozen=True)
class OriginOperation:
    operation: object
    origin: OperationOrigin


@dataclass(frozen=True)
class OriginScenario:
    operations: Tuple[OriginOperation, ...]


@dataclass(frozen=True)
class OriginDocument:
    scenarios: Tuple[OriginScenario, ...]

    def plain(self) -> ScenarioDocument:
        return ScenarioDocument(
            (
                Scenario(item.operation for item in scenario.operations)
                for scenario in self.scenarios
            ),
            version=2,
        )


@dataclass(frozen=True)
class ReductionCandidate:
    document: OriginDocument
    transform: str
    digest: str
    complexity: Tuple[int, int, int, bytes]


def with_origins(document: ScenarioDocument) -> OriginDocument:
    return OriginDocument(
        tuple(
            OriginScenario(
                tuple(
                    OriginOperation(
                        operation, OperationOrigin(scenario_index, operation_index)
                    )
                    for operation_index, operation in enumerate(scenario.operations)
                )
            )
            for scenario_index, scenario in enumerate(document.scenarios)
        )
    )


def complexity_key(document: OriginDocument) -> Tuple[int, int, int, bytes]:
    plain = document.plain()
    encoded = serialize_document(plain).encode("utf-8")
    operation_count = sum(len(scenario.operations) for scenario in document.scenarios)
    parameter_weight = sum(
        _operation_weight(item.operation)
        for scenario in document.scenarios
        for item in scenario.operations
    )
    return (len(document.scenarios), operation_count, parameter_weight, encoded)


def reduction_candidates(
    document: OriginDocument,
    *,
    required_origin: Optional[OperationOrigin] = None,
) -> Iterator[ReductionCandidate]:
    """Yield unique strictly smaller documents accepted by the v2 validator."""
    current = complexity_key(document)
    seen = set()
    raw_candidates = _scenario_deletions(document)
    raw_candidates.extend(_operation_deletions(document))
    raw_candidates.extend(_parameter_reductions(document))
    for candidate, transform in raw_candidates:
        if required_origin is not None and not contains_origin(candidate, required_origin):
            continue
        try:
            validate_entry_limits(candidate.plain())
            candidate_key = complexity_key(candidate)
            digest = canonical_digest(candidate.plain())
        except ScenarioCodecError:
            continue
        if candidate_key >= current or digest in seen:
            continue
        seen.add(digest)
        yield ReductionCandidate(candidate, transform, digest, candidate_key)


def contains_origin(document: OriginDocument, origin: OperationOrigin) -> bool:
    return any(
        item.origin == origin
        for scenario in document.scenarios
        for item in scenario.operations
    )


def locate_origin(
    document: OriginDocument, origin: OperationOrigin
) -> Optional[Tuple[int, int]]:
    for scenario_index, scenario in enumerate(document.scenarios):
        for operation_index, item in enumerate(scenario.operations):
            if item.origin == origin:
                return scenario_index, operation_index
    return None


def _scenario_deletions(document: OriginDocument):
    candidates = []
    if len(document.scenarios) <= 1:
        return candidates
    for index in reversed(range(len(document.scenarios))):
        candidates.append(
            (
                OriginDocument(
                    document.scenarios[:index] + document.scenarios[index + 1 :]
                ),
                f"delete-scenario:{index}",
            )
        )
    return candidates


def _operation_deletions(document: OriginDocument):
    candidates = []
    for scenario_index, scenario in enumerate(document.scenarios):
        if len(scenario.operations) <= 1:
            continue
        for operation_index in reversed(range(len(scenario.operations))):
            operations = (
                scenario.operations[:operation_index]
                + scenario.operations[operation_index + 1 :]
            )
            scenarios = list(document.scenarios)
            scenarios[scenario_index] = OriginScenario(operations)
            candidates.append(
                (
                    OriginDocument(tuple(scenarios)),
                    f"delete-operation:{scenario_index}:{operation_index}",
                )
            )
    return candidates


def _parameter_reductions(document: OriginDocument):
    candidates = []
    for scenario_index, scenario in enumerate(document.scenarios):
        for operation_index, item in enumerate(scenario.operations):
            for replacement, label in _simpler_operations(item.operation):
                operations = list(scenario.operations)
                operations[operation_index] = replace(item, operation=replacement)
                scenarios = list(document.scenarios)
                scenarios[scenario_index] = OriginScenario(tuple(operations))
                candidates.append(
                    (
                        OriginDocument(tuple(scenarios)),
                        f"simplify:{scenario_index}:{operation_index}:{label}",
                    )
                )
    return candidates


def _simpler_operations(operation):
    replacements = []
    if isinstance(operation, (EventFd, EventFd2)):
        for value in (0, 1):
            if value < operation.initval:
                replacements.append((replace(operation, initval=value), f"initval={value}"))
    elif isinstance(operation, (Write, StartWrite)):
        for value in (0, 1, 2):
            if value < operation.value:
                replacements.append((replace(operation, value=value), f"value={value}"))
    elif isinstance(operation, (StartRead, AssertPending, Join)):
        pass
    return replacements


def _operation_weight(operation) -> int:
    return sum(
        int(value)
        for value in vars(operation).values()
        if isinstance(value, int) and value >= 0
    )


__all__ = [
    "OperationOrigin",
    "OriginDocument",
    "OriginOperation",
    "OriginScenario",
    "ReductionCandidate",
    "complexity_key",
    "contains_origin",
    "locate_origin",
    "reduction_candidates",
    "with_origins",
]
