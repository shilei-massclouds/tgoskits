"""Resource-aware reduction for complete concurrent eventfd stories."""

from dataclasses import dataclass
from typing import Iterator, Optional, Tuple

from concurrent_scenario import (
    Scenario,
    ScenarioCodecError,
    ScenarioDocument,
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
            (Scenario(item.operation for item in scenario.operations) for scenario in self.scenarios),
            version=4,
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
                    OriginOperation(operation, OperationOrigin(scenario_index, operation_index))
                    for operation_index, operation in enumerate(scenario.operations)
                )
            )
            for scenario_index, scenario in enumerate(document.scenarios)
        )
    )


def complexity_key(document: OriginDocument) -> Tuple[int, int, int, bytes]:
    encoded = serialize_document(document.plain()).encode("utf-8")
    operations = sum(len(scenario.operations) for scenario in document.scenarios)
    weight = sum(
        int(value)
        for scenario in document.scenarios
        for item in scenario.operations
        for value in vars(item.operation).values()
        if isinstance(value, int) and value >= 0
    )
    return len(document.scenarios), operations, weight, encoded


def reduction_candidates(
    document: OriginDocument,
    *,
    required_origin: Optional[OperationOrigin] = None,
) -> Iterator[ReductionCandidate]:
    if len(document.scenarios) <= 1:
        return
    current = complexity_key(document)
    for index in reversed(range(len(document.scenarios))):
        candidate = OriginDocument(document.scenarios[:index] + document.scenarios[index + 1 :])
        if required_origin is not None and not contains_origin(candidate, required_origin):
            continue
        try:
            validate_entry_limits(candidate.plain())
            candidate_complexity = complexity_key(candidate)
            digest = canonical_digest(candidate.plain())
        except ScenarioCodecError:
            continue
        if candidate_complexity < current:
            yield ReductionCandidate(candidate, f"delete-scenario:{index}", digest, candidate_complexity)


def contains_origin(document: OriginDocument, origin: OperationOrigin) -> bool:
    return any(
        item.origin == origin
        for scenario in document.scenarios
        for item in scenario.operations
    )


__all__ = [
    "OperationOrigin",
    "OriginDocument",
    "OriginOperation",
    "OriginScenario",
    "ReductionCandidate",
    "complexity_key",
    "contains_origin",
    "reduction_candidates",
    "with_origins",
]
