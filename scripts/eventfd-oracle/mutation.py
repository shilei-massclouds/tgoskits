"""Structured eventfd mutation with deterministic nonblocking repair."""

from dataclasses import dataclass, replace
from enum import Enum
from typing import Iterable, List, Optional, Tuple

import generator
from scenario import (
    DUP3_FLAG_VALUES,
    EFD_FLAG_VALUES,
    FD_FLAG_VALUES,
    MAX_LOGICAL_SLOTS,
    MAX_OPS_PER_SCENARIO,
    MAX_POLL_FDS,
    MAX_U32,
    MAX_U64,
    O_NONBLOCK,
    STATUS_FLAG_VALUES,
    Close,
    Dup,
    Dup2,
    Dup3,
    EventFd,
    EventFd2,
    PointerMode,
    PollFdEntry,
    PollFdMode,
    PollMany,
    Read,
    ResourceState,
    Scenario,
    ScenarioCodecError,
    ScenarioDocument,
    SetFdFlags,
    SetStatusFlags,
    Write,
    canonical_digest,
    serialize_document,
    validate_entry_limits,
)


MUTATION_KINDS = (
    "operation-delete",
    "operation-insert",
    "operation-replace",
    "adjacent-swap",
    "fragment-duplicate",
    "donor-splice",
    "parameter",
)


class CandidateClassification(Enum):
    EXECUTABLE = "executable"
    MALFORMED = "malformed"


@dataclass(frozen=True)
class MutationProvenance:
    source: str
    parent_digest: Optional[str]
    donor_digest: Optional[str]
    mutation_type: Optional[str]


@dataclass(frozen=True)
class MutationCandidate:
    document: Optional[ScenarioDocument]
    encoded: bytes
    digest: str
    classification: CandidateClassification
    provenance: MutationProvenance
    rejection: Optional[str] = None


def candidate_from_document(document: ScenarioDocument, source: str) -> MutationCandidate:
    try:
        validate_entry_limits(document)
        encoded = serialize_document(document).encode("utf-8")
    except ScenarioCodecError as error:
        return MutationCandidate(
            None,
            b"",
            "",
            CandidateClassification.MALFORMED,
            MutationProvenance(source, None, None, None),
            error.category,
        )
    return MutationCandidate(
        document,
        encoded,
        canonical_digest(document),
        CandidateClassification.EXECUTABLE,
        MutationProvenance(source, None, None, None),
    )


def mutate_document(
    rng: generator.CampaignRng,
    parent: ScenarioDocument,
    donor: Optional[ScenarioDocument] = None,
    *,
    requested_kind: Optional[str] = None,
) -> MutationCandidate:
    """Apply one named structural mutation and return a canonical candidate."""
    kind = requested_kind or rng.choice(MUTATION_KINDS)
    if kind not in MUTATION_KINDS:
        raise ValueError(f"unknown mutation kind: {kind}")
    parent_digest = canonical_digest(parent)
    donor_digest = canonical_digest(donor) if donor is not None else None
    provenance = MutationProvenance("mutation", parent_digest, donor_digest, kind)

    for _ in range(64):
        raw = _apply_mutation(rng, parent, donor, kind)
        try:
            repaired = repair_document(raw)
            validate_entry_limits(repaired)
            encoded = serialize_document(repaired).encode("utf-8")
        except ScenarioCodecError:
            continue
        digest = canonical_digest(repaired)
        if digest != parent_digest:
            return MutationCandidate(
                repaired,
                encoded,
                digest,
                CandidateClassification.EXECUTABLE,
                provenance,
            )
    return MutationCandidate(
        None,
        b"",
        "",
        CandidateClassification.MALFORMED,
        provenance,
        "mutation-exhausted",
    )


def repair_document(document: ScenarioDocument) -> ScenarioDocument:
    """Repair resource collisions and insert only explicit nonblocking setup."""
    repaired_scenarios = []
    for scenario in document.scenarios:
        state = ResourceState()
        repaired_operations = []
        for operation in scenario.operations:
            try:
                state.apply(operation)
            except ScenarioCodecError as error:
                if error.category == "blocking-operation" and hasattr(operation, "slot"):
                    slot = operation.slot
                    if state.descriptor(slot) is not None:
                        setup = SetStatusFlags(slot, O_NONBLOCK)
                        state.apply(setup)
                        repaired_operations.append(setup)
                        state.apply(operation)
                    else:
                        continue
                else:
                    continue
            repaired_operations.append(operation)
            if len(repaired_operations) >= MAX_OPS_PER_SCENARIO:
                break
        if repaired_operations:
            repaired_scenarios.append(Scenario(repaired_operations))
    if not repaired_scenarios:
        raise ScenarioCodecError("mutation", "repair removed every operation")
    return ScenarioDocument(repaired_scenarios)


def _apply_mutation(
    rng: generator.CampaignRng,
    parent: ScenarioDocument,
    donor: Optional[ScenarioDocument],
    kind: str,
) -> ScenarioDocument:
    scenarios = [list(scenario.operations) for scenario in parent.scenarios]
    scenario_index = rng.range(0, len(scenarios))
    operations = scenarios[scenario_index]
    if kind == "operation-delete" and len(operations) > 1:
        del operations[rng.range(0, len(operations))]
    elif kind == "operation-insert":
        index = rng.range(0, len(operations) + 1)
        state = _state_before(operations, index)
        operations.insert(index, generator._candidate_operation(rng, state))
    elif kind == "operation-replace":
        index = rng.range(0, len(operations))
        operations[index] = generator._candidate_operation(rng, _state_before(operations, index))
    elif kind == "adjacent-swap" and len(operations) > 1:
        index = rng.range(0, len(operations) - 1)
        operations[index], operations[index + 1] = operations[index + 1], operations[index]
    elif kind == "fragment-duplicate":
        start = rng.range(0, len(operations))
        stop = rng.range(start + 1, min(len(operations), start + 4) + 1)
        destination = rng.range(0, len(operations) + 1)
        operations[destination:destination] = operations[start:stop]
    elif kind == "donor-splice" and donor is not None:
        donor_scenario = rng.choice(donor.scenarios)
        donor_ops = list(donor_scenario.operations)
        start = rng.range(0, len(donor_ops))
        stop = rng.range(start + 1, min(len(donor_ops), start + 4) + 1)
        destination = rng.range(0, len(operations) + 1)
        operations[destination:destination] = donor_ops[start:stop]
    else:
        index = rng.range(0, len(operations))
        operations[index] = _mutate_parameter(rng, operations[index])
    return ScenarioDocument(Scenario(items) for items in scenarios if items)


def _state_before(operations: Iterable, stop: int) -> ResourceState:
    state = ResourceState()
    for operation in list(operations)[:stop]:
        try:
            state.apply(operation)
        except ScenarioCodecError:
            continue
    return state


def _mutate_parameter(rng: generator.CampaignRng, operation):
    if isinstance(operation, EventFd):
        return replace(
            operation,
            slot=rng.range(0, MAX_LOGICAL_SLOTS),
            initval=rng.choice((0, 1, 7, MAX_U32)),
        )
    if isinstance(operation, EventFd2):
        return replace(
            operation,
            slot=rng.range(0, MAX_LOGICAL_SLOTS),
            initval=rng.choice((0, 1, 7, MAX_U32)),
            flags=rng.choice(EFD_FLAG_VALUES),
        )
    if isinstance(operation, Read):
        return replace(
            operation,
            slot=rng.range(0, MAX_LOGICAL_SLOTS),
            length=rng.choice((0, 4, 7, 8, 9, 16)),
            pointer_mode=rng.choice(tuple(PointerMode)),
        )
    if isinstance(operation, Write):
        return replace(
            operation,
            slot=rng.range(0, MAX_LOGICAL_SLOTS),
            length=rng.choice((0, 4, 7, 8, 9, 16)),
            pointer_mode=rng.choice(tuple(PointerMode)),
            value=rng.choice((0, 1, 7, MAX_U64 - 1, MAX_U64)),
        )
    if isinstance(operation, (Dup, Dup2)):
        return replace(
            operation,
            source_slot=rng.range(0, MAX_LOGICAL_SLOTS),
            destination_slot=rng.range(0, MAX_LOGICAL_SLOTS),
        )
    if isinstance(operation, Dup3):
        return replace(
            operation,
            source_slot=rng.range(0, MAX_LOGICAL_SLOTS),
            destination_slot=rng.range(0, MAX_LOGICAL_SLOTS),
            flags=rng.choice(DUP3_FLAG_VALUES),
        )
    if isinstance(operation, Close):
        return replace(operation, slot=rng.range(0, MAX_LOGICAL_SLOTS))
    if isinstance(operation, SetStatusFlags):
        return replace(
            operation,
            slot=rng.range(0, MAX_LOGICAL_SLOTS),
            flags=rng.choice(STATUS_FLAG_VALUES),
        )
    if isinstance(operation, SetFdFlags):
        return replace(
            operation,
            slot=rng.range(0, MAX_LOGICAL_SLOTS),
            flags=rng.choice(FD_FLAG_VALUES),
        )
    if isinstance(operation, PollMany):
        entries = list(operation.entries)
        if entries and rng.range(0, 2) == 0:
            del entries[rng.range(0, len(entries))]
        elif len(entries) < MAX_POLL_FDS:
            entries.append(
                PollFdEntry(
                    rng.choice(tuple(PollFdMode)),
                    rng.range(0, MAX_LOGICAL_SLOTS),
                    rng.choice((0, 1, 4, 5, 32767)),
                )
            )
        return PollMany(entries)
    if hasattr(operation, "slot"):
        return replace(operation, slot=rng.range(0, MAX_LOGICAL_SLOTS))
    return operation


__all__ = [
    "CandidateClassification",
    "MUTATION_KINDS",
    "MutationCandidate",
    "MutationProvenance",
    "candidate_from_document",
    "mutate_document",
    "repair_document",
]
