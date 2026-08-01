"""Structured pipe scenario mutations and dependency repair."""

import hashlib
from dataclasses import dataclass, replace
from enum import Enum
from typing import Optional, Tuple

import generator
from corpus import CorpusProvenance
from scenario import (
    Close,
    Dup,
    Dup2,
    Dup3,
    Fionread,
    GetFdFlags,
    GetSize,
    GetStatusFlags,
    IOVCNT_VALUES,
    IovBaseMode,
    IovMode,
    MAX_IO_BYTES,
    MAX_LOGICAL_SLOTS,
    MAX_OPS_PER_SCENARIO,
    MAX_PIPE_SIZE,
    MAX_POLL_MASK,
    O_CLOEXEC,
    O_NONBLOCK,
    PIPE2_ALLOWED_FLAGS,
    Pipe2,
    Poll,
    Read,
    ReadNull,
    Readv,
    ReadvSegment,
    Scenario,
    ScenarioCodecError,
    ScenarioDocument,
    SetFdFlags,
    ScenarioEntryLimitError,
    SetSize,
    SetStatusFlags,
    Write,
    WriteNull,
    Writev,
    WritevSegment,
    parse_document,
    serialize_document,
    serialize_unchecked_document,
    validate_entry_limits,
)


MUTATION_KINDS = (
    "insert-operation",
    "delete-operation",
    "replace-operation",
    "swap-adjacent",
    "duplicate-fragment",
    "delete-fragment",
    "donor-splice",
    "mutate-parameter",
)

LENGTH_BOUNDARIES = (0, 1, 2, 4095, 4096, 4097, 8191, 8192, 8193)
PIPE_SIZE_BOUNDARIES = (
    0,
    1,
    2,
    4095,
    4096,
    4097,
    8191,
    8192,
    8193,
    MAX_PIPE_SIZE,
    MAX_PIPE_SIZE + 1,
)
POLL_MASK_BOUNDARIES = (
    0,
    1,
    4,
    5,
    4095,
    4096,
    4097,
    8191,
    8192,
    8193,
    0x4000,
    MAX_POLL_MASK,
    MAX_POLL_MASK + 1,
)
BYTE_BOUNDARIES = (0, 1, 0x61, 0xFE, 0xFF, 0x100)
SLOT_BOUNDARIES = (0, 1, MAX_LOGICAL_SLOTS - 1, MAX_LOGICAL_SLOTS)
FLAG_BOUNDARIES = (
    0,
    1,
    O_NONBLOCK,
    O_CLOEXEC,
    PIPE2_ALLOWED_FLAGS,
    0x40000000,
)

FREE = 0
READER = 1
WRITER = 2


class CandidateClassification(str, Enum):
    EXECUTABLE = "executable"
    MALFORMED = "malformed"


@dataclass(frozen=True)
class MutationCandidate:
    encoded: bytes
    kind: str
    classification: CandidateClassification
    document: Optional[ScenarioDocument]
    error_category: Optional[str]
    provenance: CorpusProvenance

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.encoded).hexdigest()


class MutationUnavailable(RuntimeError):
    pass


def candidate_from_document(document: ScenarioDocument, kind: str) -> MutationCandidate:
    return _classify_candidate(document, kind, CorpusProvenance.generated())


def mutate_document(
    rng,
    parent: ScenarioDocument,
    donor: Optional[ScenarioDocument] = None,
    requested_kind: Optional[str] = None,
) -> MutationCandidate:
    """Return a changed structured candidate or report a forced-kind limitation."""

    parent_encoded = serialize_document(parent).encode("utf-8")
    parent_digest = hashlib.sha256(parent_encoded).hexdigest()
    donor_digest = (
        hashlib.sha256(serialize_document(donor).encode("utf-8")).hexdigest()
        if donor is not None
        else None
    )
    attempts = 64 if requested_kind is None else 32
    for _ in range(attempts):
        kind = requested_kind or MUTATION_KINDS[rng.range(0, len(MUTATION_KINDS))]
        mutated = _apply_mutation_kind(rng, parent, donor, kind)
        if mutated is None:
            continue
        candidate = _classify_candidate(
            mutated,
            kind,
            CorpusProvenance.mutated(parent_digest, donor_digest, kind),
        )
        if candidate.encoded == parent_encoded:
            continue
        if (
            candidate.classification == CandidateClassification.EXECUTABLE
            and candidate.digest == parent_digest
        ):
            continue
        return candidate
    if requested_kind is not None:
        raise MutationUnavailable(f"{requested_kind} cannot change this parent")
    return _fallback_insert_candidate(
        rng,
        parent,
        parent_encoded,
        parent_digest,
        donor_digest,
    )


def repair_dependencies(document: ScenarioDocument) -> ScenarioDocument:
    """Remap logical slots and synthesize pipe2 operations needed by structural edits."""

    return ScenarioDocument(_repair_scenario(scenario) for scenario in document.scenarios)


def _apply_mutation_kind(rng, parent, donor, kind):
    if kind == "insert-operation":
        return repair_dependencies(_insert_operation(rng, parent))
    if kind == "delete-operation":
        deleted = _delete_operation(rng, parent)
        return repair_dependencies(deleted) if deleted is not None else None
    if kind == "replace-operation":
        return repair_dependencies(_replace_operation(rng, parent))
    if kind == "swap-adjacent":
        swapped = _swap_adjacent(rng, parent)
        return repair_dependencies(swapped) if swapped is not None else None
    if kind == "duplicate-fragment":
        return repair_dependencies(_duplicate_fragment(rng, parent))
    if kind == "delete-fragment":
        deleted = _delete_fragment(rng, parent)
        return repair_dependencies(deleted) if deleted is not None else None
    if kind == "donor-splice":
        spliced = _donor_splice(rng, parent, donor)
        return repair_dependencies(spliced) if spliced is not None else None
    if kind == "mutate-parameter":
        return _mutate_parameter(rng, repair_dependencies(parent))
    raise ValueError(f"unknown mutation kind: {kind}")


def _insert_operation(rng, parent):
    scenarios = list(parent.scenarios)
    scenario_index = rng.range(0, len(scenarios))
    operations = list(scenarios[scenario_index].operations)
    template = _random_template_operation(rng)
    operations.insert(rng.range(0, len(operations) + 1), template)
    scenarios[scenario_index] = Scenario(operations)
    return ScenarioDocument(scenarios)


def _delete_operation(rng, parent):
    choices = [
        index
        for index, scenario in enumerate(parent.scenarios)
        if scenario.operations
    ]
    if not choices:
        return None
    scenarios = list(parent.scenarios)
    scenario_index = choices[rng.range(0, len(choices))]
    operations = list(scenarios[scenario_index].operations)
    del operations[rng.range(0, len(operations))]
    scenarios[scenario_index] = Scenario(operations)
    return ScenarioDocument(scenarios)


def _replace_operation(rng, parent):
    scenarios = list(parent.scenarios)
    scenario_index = rng.range(0, len(scenarios))
    operations = list(scenarios[scenario_index].operations)
    if not operations:
        operations.append(_random_template_operation(rng))
    else:
        operations[rng.range(0, len(operations))] = _random_template_operation(rng)
    scenarios[scenario_index] = Scenario(operations)
    return ScenarioDocument(scenarios)


def _swap_adjacent(rng, parent):
    choices = []
    for scenario_index, scenario in enumerate(parent.scenarios):
        for operation_index in range(len(scenario.operations) - 1):
            if scenario.operations[operation_index] != scenario.operations[operation_index + 1]:
                choices.append((scenario_index, operation_index))
    if not choices:
        return None
    scenario_index, operation_index = choices[rng.range(0, len(choices))]
    scenarios = list(parent.scenarios)
    operations = list(scenarios[scenario_index].operations)
    operations[operation_index], operations[operation_index + 1] = (
        operations[operation_index + 1],
        operations[operation_index],
    )
    scenarios[scenario_index] = Scenario(operations)
    return ScenarioDocument(scenarios)


def _duplicate_fragment(rng, parent):
    scenarios = list(parent.scenarios)
    scenario_index = rng.range(0, len(scenarios))
    operations = list(scenarios[scenario_index].operations)
    if not operations:
        operations.append(_random_template_operation(rng))
    start, end = _random_fragment(rng, len(operations))
    insertion = rng.range(0, len(operations) + 1)
    operations[insertion:insertion] = operations[start:end]
    scenarios[scenario_index] = Scenario(operations)
    return ScenarioDocument(scenarios)


def _delete_fragment(rng, parent):
    choices = [
        index
        for index, scenario in enumerate(parent.scenarios)
        if scenario.operations
    ]
    if not choices:
        return None
    scenarios = list(parent.scenarios)
    scenario_index = choices[rng.range(0, len(choices))]
    operations = list(scenarios[scenario_index].operations)
    start, end = _random_fragment(rng, len(operations))
    del operations[start:end]
    scenarios[scenario_index] = Scenario(operations)
    return ScenarioDocument(scenarios)


def _donor_splice(rng, parent, donor):
    if donor is None or not donor.scenarios:
        return None
    donor_scenarios = [scenario for scenario in donor.scenarios if scenario.operations]
    if not donor_scenarios:
        return None
    source = donor_scenarios[rng.range(0, len(donor_scenarios))]
    start, end = _random_fragment(rng, len(source.operations))
    fragment = source.operations[start:end]
    scenarios = list(parent.scenarios)
    scenario_index = rng.range(0, len(scenarios))
    operations = list(scenarios[scenario_index].operations)
    insertion = rng.range(0, len(operations) + 1)
    operations[insertion:insertion] = fragment
    scenarios[scenario_index] = Scenario(operations)
    return ScenarioDocument(scenarios)


def _mutate_parameter(rng, parent):
    locations = _parameter_locations(parent)
    families = [family for family, family_locations in locations.items() if family_locations]
    if not families:
        return None
    family = families[rng.range(0, len(families))]
    location = _choose(rng, locations[family])
    scenario_index, operation_index = location[:2]
    segment_index = location[2] if len(location) == 3 else None
    scenarios = list(parent.scenarios)
    operations = list(scenarios[scenario_index].operations)
    operation = operations[operation_index]
    operations[operation_index] = _mutate_operation_parameter(
        rng,
        operation,
        family,
        segment_index,
    )
    scenarios[scenario_index] = Scenario(operations)
    return ScenarioDocument(scenarios)


def _parameter_locations(document):
    locations = {
        "slot": [],
        "length": [],
        "byte": [],
        "iov-mode": [],
        "iov-count": [],
        "segment-length": [],
        "base-mode": [],
        "pipe-size": [],
        "poll-mask": [],
        "flags": [],
    }
    for scenario_index, scenario in enumerate(document.scenarios):
        for operation_index, operation in enumerate(scenario.operations):
            locations["slot"].append((scenario_index, operation_index))
            if isinstance(operation, (Read, Write)):
                locations["length"].append((scenario_index, operation_index))
            if isinstance(operation, Write):
                locations["byte"].append((scenario_index, operation_index))
            if isinstance(operation, (Readv, Writev)):
                locations["iov-mode"].append((scenario_index, operation_index))
                locations["iov-count"].append((scenario_index, operation_index))
                for segment_index, _segment in enumerate(operation.segments):
                    location = (scenario_index, operation_index, segment_index)
                    locations["segment-length"].append(location)
                    locations["base-mode"].append(location)
                    if isinstance(operation, Writev):
                        locations["byte"].append(location)
            if isinstance(operation, SetSize):
                locations["pipe-size"].append((scenario_index, operation_index))
            if isinstance(operation, Poll):
                locations["poll-mask"].append((scenario_index, operation_index))
            if isinstance(
                operation,
                (Pipe2, SetStatusFlags, SetFdFlags, Dup3),
            ):
                locations["flags"].append((scenario_index, operation_index))
    return locations


def _mutate_operation_parameter(rng, operation, family, segment_index=None):
    if family == "slot":
        return _replace_one_slot(rng, operation)
    if family == "length":
        value = _mutated_number(
            rng,
            operation.length,
            LENGTH_BOUNDARIES,
            0,
            MAX_IO_BYTES,
        )
        return replace(operation, length=value)
    if family == "byte":
        if isinstance(operation, Writev):
            return _mutate_vector_segment_number(
                rng,
                operation,
                segment_index,
                "byte",
                BYTE_BOUNDARIES,
                0,
                255,
            )
        value = _mutated_number(rng, operation.byte, BYTE_BOUNDARIES, 0, 255)
        return replace(operation, byte=value)
    if family == "iov-mode":
        return _mutate_iov_mode(operation)
    if family == "iov-count":
        return _mutate_iov_count(rng, operation)
    if family == "segment-length":
        other_length = sum(
            segment.length
            for index, segment in enumerate(operation.segments)
            if index != segment_index
        )
        return _mutate_vector_segment_number(
            rng,
            operation,
            segment_index,
            "length",
            LENGTH_BOUNDARIES,
            0,
            MAX_IO_BYTES - other_length,
        )
    if family == "base-mode":
        segments = list(operation.segments)
        segment = segments[segment_index]
        segments[segment_index] = replace(
            segment,
            base_mode=(
                IovBaseMode.INVALID
                if segment.base_mode == IovBaseMode.VALID
                else IovBaseMode.VALID
            ),
        )
        return replace(operation, segments=tuple(segments))
    if family == "pipe-size":
        value = _mutated_number(
            rng,
            operation.size,
            PIPE_SIZE_BOUNDARIES,
            0,
            MAX_PIPE_SIZE,
        )
        return replace(operation, size=value)
    if family == "flags":
        value = _mutated_number(
            rng,
            operation.flags,
            FLAG_BOUNDARIES,
            0,
            2147483647,
        )
        return replace(operation, flags=value)
    value = _mutated_number(
        rng,
        operation.events,
        POLL_MASK_BOUNDARIES,
        0,
        MAX_POLL_MASK,
    )
    return replace(operation, events=value)


def _mutate_iov_mode(operation):
    if operation.iov_mode == IovMode.VALID:
        return replace(operation, iov_mode=IovMode.INVALID, segments=())
    segments = _zero_vector_segments(operation, operation.iovcnt)
    return replace(operation, iov_mode=IovMode.VALID, segments=segments)


def _mutate_iov_count(rng, operation):
    choices = [value for value in IOVCNT_VALUES if value != operation.iovcnt]
    iovcnt = _choose(rng, choices)
    segments = (
        _resize_vector_segments(operation, iovcnt)
        if operation.iov_mode == IovMode.VALID
        else ()
    )
    return replace(operation, iovcnt=iovcnt, segments=segments)


def _resize_vector_segments(operation, count):
    if count < 0 or count > 4:
        return ()
    segments = list(operation.segments[:count])
    segments.extend(_zero_vector_segments(operation, count - len(segments)))
    return tuple(segments)


def _zero_vector_segments(operation, count):
    if count < 0 or count > 4:
        return ()
    if isinstance(operation, Writev):
        return tuple(
            WritevSegment(IovBaseMode.VALID, 0, 0) for _ in range(count)
        )
    return tuple(ReadvSegment(IovBaseMode.VALID, 0) for _ in range(count))


def _mutate_vector_segment_number(
    rng,
    operation,
    segment_index,
    field,
    boundaries,
    legal_minimum,
    legal_maximum,
):
    segments = list(operation.segments)
    segment = segments[segment_index]
    value = _mutated_number(
        rng,
        getattr(segment, field),
        boundaries,
        legal_minimum,
        legal_maximum,
    )
    segments[segment_index] = replace(segment, **{field: value})
    return replace(operation, segments=tuple(segments))


def _replace_one_slot(rng, operation):
    fields = []
    if isinstance(operation, Pipe2):
        fields = ["read_slot", "write_slot"]
    elif isinstance(operation, (Dup, Dup2, Dup3)):
        fields = ["source_slot", "destination_slot"]
    else:
        fields = ["slot"]
    field = fields[rng.range(0, len(fields))]
    current = getattr(operation, field)
    value = _mutated_number(
        rng,
        current,
        SLOT_BOUNDARIES,
        0,
        MAX_LOGICAL_SLOTS - 1,
    )
    return replace(operation, **{field: value})


def _mutated_number(rng, current, boundaries, legal_minimum, legal_maximum):
    if rng.range(0, 4) < 3:
        choices = [
            value
            for value in boundaries
            if legal_minimum <= value <= legal_maximum and value != current
        ]
        if not choices:
            return current
        return _choose(rng, choices)
    if legal_minimum == legal_maximum:
        return legal_minimum
    value = rng.range(legal_minimum, legal_maximum + 1)
    if value == current:
        value = legal_minimum if current != legal_minimum else legal_maximum
    return value


def _repair_scenario(scenario: Scenario) -> Scenario:
    repaired = []
    slots = [FREE] * MAX_LOGICAL_SLOTS
    logical_mapping = {}
    for operation in scenario.operations:
        if len(repaired) >= MAX_OPS_PER_SCENARIO:
            break
        if isinstance(operation, Pipe2):
            free_slots = _free_slots(slots)
            if len(free_slots) < 2:
                continue
            read_slot, write_slot = free_slots[:2]
            repaired_flags = operation.flags
            repaired.append(Pipe2(read_slot, write_slot, repaired_flags))
            if repaired_flags & ~PIPE2_ALLOWED_FLAGS == 0:
                slots[read_slot] = READER
                slots[write_slot] = WRITER
                logical_mapping[operation.read_slot] = read_slot
                logical_mapping[operation.write_slot] = write_slot
            continue
        if isinstance(operation, Dup):
            source = _resolve_endpoint(
                operation.source_slot,
                (READER, WRITER),
                logical_mapping,
                slots,
                repaired,
            )
            if source is None:
                continue
            free_slots = _free_slots(slots)
            if not free_slots:
                continue
            destination = free_slots[0]
            repaired.append(Dup(source, destination))
            slots[destination] = slots[source]
            logical_mapping[operation.destination_slot] = destination
            continue
        if isinstance(operation, (Dup2, Dup3)):
            source = _resolve_endpoint(
                operation.source_slot,
                (READER, WRITER),
                logical_mapping,
                slots,
                repaired,
            )
            if source is None:
                continue
            destination = logical_mapping.get(
                operation.destination_slot,
                operation.destination_slot,
            )
            rewritten = replace(
                operation,
                source_slot=source,
                destination_slot=destination,
            )
            repaired.append(rewritten)
            if source != destination and (
                isinstance(operation, Dup2)
                or operation.flags & ~O_CLOEXEC == 0
            ):
                slots[destination] = slots[source]
                logical_mapping[operation.destination_slot] = destination
            continue

        required_states = _required_states(operation)
        slot = _resolve_endpoint(
            operation.slot,
            required_states,
            logical_mapping,
            slots,
            repaired,
        )
        if slot is None or len(repaired) >= MAX_OPS_PER_SCENARIO:
            continue
        repaired_operation = replace(operation, slot=slot)
        if _positive_io_length(repaired_operation) > 0:
            repaired.append(SetStatusFlags(slot, O_NONBLOCK))
            if len(repaired) >= MAX_OPS_PER_SCENARIO:
                break
        repaired.append(repaired_operation)
        if isinstance(operation, Close):
            slots[slot] = FREE
    if not repaired:
        repaired.append(Pipe2(0, 1))
    return Scenario(repaired[:MAX_OPS_PER_SCENARIO])


def _resolve_endpoint(
    logical_slot,
    required_states,
    logical_mapping,
    slots,
    repaired,
):
    mapped = logical_mapping.get(logical_slot)
    if mapped is not None and slots[mapped] in required_states:
        return mapped
    existing = [index for index, state in enumerate(slots) if state in required_states]
    if existing:
        logical_mapping[logical_slot] = existing[0]
        return existing[0]
    if len(repaired) + 2 > MAX_OPS_PER_SCENARIO:
        return None
    free_slots = _free_slots(slots)
    if len(free_slots) < 2:
        return None
    read_slot, write_slot = free_slots[:2]
    repaired.append(Pipe2(read_slot, write_slot, PIPE2_ALLOWED_FLAGS))
    slots[read_slot] = READER
    slots[write_slot] = WRITER
    resolved = read_slot if READER in required_states else write_slot
    logical_mapping[logical_slot] = resolved
    return resolved


def _required_states(operation):
    if isinstance(operation, (Read, ReadNull, Readv)):
        return (READER,)
    if isinstance(operation, (Write, WriteNull, Writev)):
        return (WRITER,)
    return (READER, WRITER)


def _positive_io_length(operation):
    if isinstance(operation, (Read, Write)):
        return operation.length
    if (
        isinstance(operation, (Readv, Writev))
        and operation.iov_mode == IovMode.VALID
        and 0 < operation.iovcnt <= 4
    ):
        return sum(segment.length for segment in operation.segments)
    return 0


def _random_template_operation(rng):
    document = generator.generate_document(rng)
    scenario = _choose(rng, document.scenarios)
    return _choose(rng, scenario.operations)


def _random_fragment(rng, length: int) -> Tuple[int, int]:
    start = rng.range(0, length)
    end = rng.range(start + 1, length + 1)
    return start, end


def _classify_candidate(document, kind, provenance):
    encoded = serialize_unchecked_document(document).encode("utf-8")
    try:
        parsed = parse_document(encoded)
        validate_entry_limits(parsed)
    except ScenarioCodecError as error:
        return MutationCandidate(
            encoded,
            kind,
            CandidateClassification.MALFORMED,
            None,
            f"codec:{error.category.value}",
            provenance,
        )
    except ScenarioEntryLimitError as error:
        return MutationCandidate(
            encoded,
            kind,
            CandidateClassification.MALFORMED,
            None,
            f"limit:{error.category.value}",
            provenance,
        )
    canonical = serialize_document(parsed).encode("utf-8")
    return MutationCandidate(
        canonical,
        kind,
        CandidateClassification.EXECUTABLE,
        parsed,
        None,
        provenance,
    )


def _fallback_insert_candidate(
    rng,
    parent,
    parent_encoded,
    parent_digest,
    donor_digest,
):
    for _ in range(64):
        candidate = _classify_candidate(
            repair_dependencies(_insert_operation(rng, parent)),
            "insert-operation",
            CorpusProvenance.mutated(
                parent_digest,
                donor_digest,
                "insert-operation",
            ),
        )
        if candidate.encoded != parent_encoded:
            return candidate
    raise MutationUnavailable("no structured mutation changed the parent")


def _free_slots(slots):
    return [index for index, state in enumerate(slots) if state == FREE]


def _choose(rng, values):
    return values[rng.range(0, len(values))]


__all__ = [
    "BYTE_BOUNDARIES",
    "CandidateClassification",
    "FLAG_BOUNDARIES",
    "LENGTH_BOUNDARIES",
    "MUTATION_KINDS",
    "MutationCandidate",
    "MutationUnavailable",
    "PIPE_SIZE_BOUNDARIES",
    "POLL_MASK_BOUNDARIES",
    "SLOT_BOUNDARIES",
    "candidate_from_document",
    "mutate_document",
    "repair_dependencies",
]
