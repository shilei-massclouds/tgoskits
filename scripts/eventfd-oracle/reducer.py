"""Deterministic resource-aware eventfd scenario reduction."""

from dataclasses import dataclass, replace
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from scenario import (
    MAX_U64,
    Close,
    Dup,
    Dup2,
    Dup3,
    EventFd,
    EventFd2,
    PollMany,
    Read,
    Scenario,
    ScenarioCodecError,
    ScenarioDocument,
    SetFdFlags,
    SetStatusFlags,
    Write,
    canonical_digest,
    serialize_document,
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
            Scenario(item.operation for item in scenario.operations)
            for scenario in self.scenarios
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
    plain = document.plain()
    encoded = serialize_document(plain).encode("utf-8")
    operations = sum(len(scenario.operations) for scenario in document.scenarios)
    parameter_weight = sum(
        _operation_weight(item.operation)
        for scenario in document.scenarios
        for item in scenario.operations
    )
    return (len(document.scenarios), operations, parameter_weight, encoded)


def reduction_candidates(
    document: OriginDocument,
    *,
    required_origin: Optional[OperationOrigin] = None,
) -> Iterator[ReductionCandidate]:
    """Yield unique, canonical, strictly lower candidates in deterministic order."""
    current_key = complexity_key(document)
    seen = set()
    raw_candidates = []
    raw_candidates.extend(_scenario_deletions(document))
    raw_candidates.extend(_operation_deletions(document))
    raw_candidates.extend(_parameter_reductions(document))
    for candidate, transform in raw_candidates:
        if required_origin is not None and not contains_origin(candidate, required_origin):
            continue
        try:
            candidate_key = complexity_key(candidate)
            digest = canonical_digest(candidate.plain())
        except ScenarioCodecError:
            continue
        if candidate_key >= current_key or digest in seen:
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
        scenarios = document.scenarios[:index] + document.scenarios[index + 1 :]
        candidates.append((OriginDocument(scenarios), f"delete-scenario:{index}"))
    return candidates


def _operation_deletions(document: OriginDocument):
    candidates = []
    for scenario_index, scenario in enumerate(document.scenarios):
        if len(scenario.operations) <= 1:
            continue
        count = len(scenario.operations)
        block = max(1, count // 2)
        sizes = []
        while block >= 1:
            if block not in sizes:
                sizes.append(block)
            block //= 2
        for size in sizes:
            for start in range(count - size, -1, -size):
                stop = min(count, start + size)
                remaining = scenario.operations[:start] + scenario.operations[stop:]
                if not remaining:
                    continue
                scenarios = list(document.scenarios)
                scenarios[scenario_index] = OriginScenario(remaining)
                candidates.append(
                    (
                        OriginDocument(tuple(scenarios)),
                        f"delete-operations:{scenario_index}:{start}:{stop}",
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
        if isinstance(operation, EventFd2):
            for flags in (0, 1, 2048):
                if flags != operation.flags:
                    replacements.append((replace(operation, flags=flags), f"flags={flags}"))
    elif isinstance(operation, Read):
        for length in (0, 7, 8):
            if length < operation.length:
                replacements.append((replace(operation, length=length), f"length={length}"))
        if int(operation.pointer_mode) != 0:
            replacements.append((replace(operation, pointer_mode=type(operation.pointer_mode)(0)), "valid-pointer"))
    elif isinstance(operation, Write):
        for length in (0, 7, 8):
            if length < operation.length:
                replacements.append((replace(operation, length=length), f"length={length}"))
        for value in (0, 1, MAX_U64 - 1):
            if value < operation.value:
                replacements.append((replace(operation, value=value), f"value={value}"))
        if int(operation.pointer_mode) != 0:
            replacements.append((replace(operation, pointer_mode=type(operation.pointer_mode)(0)), "valid-pointer"))
    elif isinstance(operation, Dup3):
        if operation.flags != 0:
            replacements.append((replace(operation, flags=0), "flags=0"))
    elif isinstance(operation, (SetStatusFlags, SetFdFlags)):
        if operation.flags != 0:
            replacements.append((replace(operation, flags=0), "flags=0"))
    elif isinstance(operation, PollMany):
        for count in range(len(operation.entries)):
            replacements.append((PollMany(operation.entries[:count]), f"entries={count}"))
        for index, entry in enumerate(operation.entries):
            if entry.events != 0:
                entries = list(operation.entries)
                entries[index] = replace(entry, events=0)
                replacements.append((PollMany(entries), f"events[{index}]=0"))
    elif isinstance(operation, (Dup, Dup2, Close)):
        pass
    return replacements


def _operation_weight(operation) -> int:
    if isinstance(operation, (EventFd, EventFd2)):
        return operation.initval + getattr(operation, "flags", 0)
    if isinstance(operation, Read):
        return operation.length + int(operation.pointer_mode)
    if isinstance(operation, Write):
        return operation.length + int(operation.pointer_mode) + operation.value
    if isinstance(operation, PollMany):
        return len(operation.entries) + sum(entry.events for entry in operation.entries)
    return sum(
        value
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
