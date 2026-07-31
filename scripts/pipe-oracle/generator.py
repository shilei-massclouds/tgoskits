"""Deterministic legacy migration and version-2 structured generation."""

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Dict, List

from scenario import (
    Close,
    Dup,
    Dup2,
    Dup3,
    DUP3_ALLOWED_FLAGS,
    DUP3_FLAG_VALUES,
    FD_CLOEXEC,
    Fionread,
    GetFdFlags,
    GetSize,
    GetStatusFlags,
    LEGACY_CORPUS_VERSION,
    MAX_ENTRY_BYTES,
    MAX_IO_BYTES,
    MAX_LOGICAL_SLOTS,
    MAX_OPS_PER_SCENARIO,
    MAX_PIPE_SIZE,
    MAX_POLL_MASK,
    O_CLOEXEC,
    O_NONBLOCK,
    PIPE2_ALLOWED_FLAGS,
    PIPE2_FLAG_VALUES,
    Pipe2,
    Poll,
    Read,
    ReadNull,
    Scenario,
    ScenarioDocument,
    SetFdFlags,
    SetSize,
    SetStatusFlags,
    Write,
    WriteNull,
    canonical_digest,
    serialize_document,
    validate_entry_limits,
)


GENERATOR_VERSION = "3"
PREVIOUS_GENERATOR_VERSION = "2"
LEGACY_GENERATOR_VERSION = "1"
SUPPORTED_CORPUS_GENERATOR_VERSIONS = (
    PREVIOUS_GENERATOR_VERSION,
    GENERATOR_VERSION,
)

MAX_INPUT_BYTES = MAX_ENTRY_BYTES

FREE = 0
READER = 1
WRITER = 2
CLOSED = 3

_CAMPAIGN_RNG_DOMAIN = b"starry-pipe-oracle-campaign-rng-v2\x00"
_UINT64_RANGE = 1 << 64

_GENERATION_LENGTH_BOUNDARIES = (0, 1, 2, 4095, 4096, 4097, 8191, 8192)
_GENERATION_PIPE_SIZE_BOUNDARIES = (
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
)
_GENERATION_POLL_BOUNDARIES = (
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
)
_PIPE2_FLAG_BOUNDARIES = PIPE2_FLAG_VALUES
_STATUS_FLAG_BOUNDARIES = (0, O_NONBLOCK, O_CLOEXEC, PIPE2_ALLOWED_FLAGS)
_FD_FLAG_BOUNDARIES = (0, FD_CLOEXEC, 2, 3)
_DUP3_FLAG_BOUNDARIES = DUP3_FLAG_VALUES


@dataclass
class _GenerationState:
    slots: List[int] = field(default_factory=lambda: [FREE] * MAX_LOGICAL_SLOTS)
    descriptions: List[int] = field(
        default_factory=lambda: [-1] * MAX_LOGICAL_SLOTS
    )
    close_on_exec: List[bool] = field(
        default_factory=lambda: [False] * MAX_LOGICAL_SLOTS
    )
    nonblocking: Dict[int, bool] = field(default_factory=dict)
    next_description: int = 0

    def open_endpoint(
        self,
        slot: int,
        endpoint: int,
        flags: int,
    ) -> None:
        description = self.next_description
        self.next_description += 1
        self.slots[slot] = endpoint
        self.descriptions[slot] = description
        self.close_on_exec[slot] = bool(flags & O_CLOEXEC)
        self.nonblocking[description] = bool(flags & O_NONBLOCK)

    def duplicate(self, source: int, destination: int, close_on_exec: bool) -> None:
        self.slots[destination] = self.slots[source]
        self.descriptions[destination] = self.descriptions[source]
        self.close_on_exec[destination] = close_on_exec

    def close(self, slot: int) -> None:
        self.slots[slot] = CLOSED
        self.descriptions[slot] = -1
        self.close_on_exec[slot] = False

    def is_nonblocking(self, slot: int) -> bool:
        description = self.descriptions[slot]
        return description >= 0 and self.nonblocking[description]


class CampaignRng:
    """Versioned SHA-256 counter stream with unbiased bounded selection."""

    def __init__(self, seed: int):
        self.seed = seed & 0xFFFFFFFFFFFFFFFF
        self.counter = 0

    def next(self) -> int:
        payload = self.seed.to_bytes(8, "little") + self.counter.to_bytes(8, "little")
        self.counter += 1
        digest = hashlib.sha256(_CAMPAIGN_RNG_DOMAIN + payload).digest()
        return int.from_bytes(digest[:8], "little")

    def range(self, lower: int, upper: int) -> int:
        if lower >= upper:
            return lower
        width = upper - lower
        rejection_limit = _UINT64_RANGE - (_UINT64_RANGE % width)
        while True:
            value = self.next()
            if value < rejection_limit:
                return lower + value % width


class LegacyLcgRng:
    """Version-1 LCG retained only for seed migration and offline comparison."""

    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next(self) -> int:
        self.state = (
            self.state * 6364136223846793005 + 1442695040888963407
        ) & 0xFFFFFFFFFFFFFFFF
        return self.state

    def range(self, lower: int, upper: int) -> int:
        if lower >= upper:
            return lower
        return lower + self.next() % (upper - lower)


def generate_document(rng) -> ScenarioDocument:
    """Generate one bounded version-3 corpus entry directly as scenario IR."""

    scenario_count = rng.range(1, 5)
    scenarios = []
    for _ in range(scenario_count):
        operation_count = rng.range(1, MAX_OPS_PER_SCENARIO + 1)
        scenarios.append(_generate_structured_scenario(rng, operation_count))
    document = ScenarioDocument(scenarios)
    validate_entry_limits(document)
    return document


def legacy_document_from_input(data: bytes) -> ScenarioDocument:
    """Decode version-1 raw bytes byte-for-byte for migration and golden tests."""

    if not data:
        rng = LegacyLcgRng(0)
        operation_count = max(1, rng.range(1, 6))
        return ScenarioDocument(
            [_generate_legacy_scenario(rng, operation_count)],
            version=LEGACY_CORPUS_VERSION,
        )
    if len(data) > MAX_INPUT_BYTES:
        data = data[:MAX_INPUT_BYTES]
    rng = LegacyLcgRng(_bytes_to_seed(data))
    scenario_count = max(1, rng.range(1, 5))
    scenarios = []
    for _ in range(scenario_count):
        operation_count = max(1, rng.range(1, MAX_OPS_PER_SCENARIO + 1))
        scenarios.append(_generate_legacy_scenario(rng, operation_count))
    return ScenarioDocument(scenarios, version=LEGACY_CORPUS_VERSION)


def expand_input(data: bytes) -> ScenarioDocument:
    """Compatibility name for the version-1 raw-input migration decoder."""

    return legacy_document_from_input(data)


def canonicalize_input(data: bytes):
    document = legacy_document_from_input(data)
    return serialize_document(document), canonical_digest(document)


def ops_to_text(document: ScenarioDocument) -> str:
    return serialize_document(document)


def _generate_structured_scenario(rng, operation_count: int) -> Scenario:
    operations = []
    state = _GenerationState()
    for _ in range(operation_count):
        families = _structured_operation_families(state)
        family = families[rng.range(0, len(families))]
        operations.append(_emit_structured_operation(rng, family, state))
    return Scenario(operations)


def _structured_operation_families(state: _GenerationState):
    open_slots = _slots_with_states(state.slots, READER, WRITER)
    available_slots = _slots_with_states(state.slots, FREE, CLOSED)
    if not open_slots:
        return ("pipe2",)

    families = [
        "read",
        "read-null",
        "write",
        "write-null",
        "close",
        "poll",
        "set-size",
        "get-size",
        "fionread",
        "get-status-flags",
        "set-status-flags",
        "get-fd-flags",
        "set-fd-flags",
        "dup2",
        "dup3",
        "resource-error",
    ]
    if len(available_slots) >= 2:
        families.append("pipe2")
    if available_slots:
        families.append("dup")
    return tuple(families)


def _emit_structured_operation(rng, family: str, state: _GenerationState):
    readers = _slots_with_states(state.slots, READER)
    writers = _slots_with_states(state.slots, WRITER)
    open_slots = readers + writers
    available_slots = _slots_with_states(state.slots, FREE, CLOSED)

    if family == "pipe2":
        read_slot = _take_random(rng, available_slots)
        write_slot = _take_random(rng, available_slots)
        flags = _choose(rng, _PIPE2_FLAG_BOUNDARIES)
        if flags & ~PIPE2_ALLOWED_FLAGS == 0:
            state.open_endpoint(read_slot, READER, flags)
            state.open_endpoint(write_slot, WRITER, flags)
        return Pipe2(read_slot, write_slot, flags)
    if family == "read":
        slot = _choose(rng, readers or open_slots)
        return Read(slot, _safe_generation_length(rng, state, slot))
    if family == "read-null":
        return ReadNull(_choose(rng, readers or open_slots))
    if family == "write":
        slot = _choose(rng, writers or open_slots)
        return Write(
            slot,
            _safe_generation_length(rng, state, slot),
            rng.range(0, 256),
        )
    if family == "write-null":
        return WriteNull(_choose(rng, writers or open_slots))
    if family == "dup":
        source = _choose(rng, open_slots)
        destination = _choose(rng, available_slots)
        state.duplicate(source, destination, False)
        return Dup(source, destination)
    if family == "close":
        slot = _choose(rng, open_slots)
        state.close(slot)
        return Close(slot)
    if family == "poll":
        return Poll(_choose(rng, open_slots), _generation_poll_mask(rng))
    if family == "set-size":
        return SetSize(_choose(rng, open_slots), _generation_pipe_size(rng))
    if family == "get-size":
        return GetSize(_choose(rng, open_slots))
    if family == "fionread":
        return Fionread(_choose(rng, open_slots))
    if family == "get-status-flags":
        return GetStatusFlags(_choose_any_slot(rng, open_slots, available_slots))
    if family == "set-status-flags":
        slot = _choose_any_slot(rng, open_slots, available_slots)
        flags = _choose(rng, _STATUS_FLAG_BOUNDARIES)
        if state.slots[slot] in (READER, WRITER):
            state.nonblocking[state.descriptions[slot]] = bool(flags & O_NONBLOCK)
        return SetStatusFlags(slot, flags)
    if family == "get-fd-flags":
        return GetFdFlags(_choose_any_slot(rng, open_slots, available_slots))
    if family == "set-fd-flags":
        slot = _choose_any_slot(rng, open_slots, available_slots)
        flags = _choose(rng, _FD_FLAG_BOUNDARIES)
        if state.slots[slot] in (READER, WRITER):
            state.close_on_exec[slot] = bool(flags & FD_CLOEXEC)
        return SetFdFlags(slot, flags)
    if family == "dup2":
        source = _choose_any_slot(rng, open_slots, available_slots)
        destination = rng.range(0, MAX_LOGICAL_SLOTS)
        if state.slots[source] in (READER, WRITER) and source != destination:
            state.duplicate(source, destination, False)
        return Dup2(source, destination)
    if family == "dup3":
        source = _choose_any_slot(rng, open_slots, available_slots)
        destination = rng.range(0, MAX_LOGICAL_SLOTS)
        flags = _choose(rng, _DUP3_FLAG_BOUNDARIES)
        if (
            state.slots[source] in (READER, WRITER)
            and source != destination
            and flags & ~DUP3_ALLOWED_FLAGS == 0
        ):
            state.duplicate(source, destination, bool(flags & O_CLOEXEC))
        return Dup3(source, destination, flags)
    return _emit_resource_error(rng, state)


def _emit_resource_error(rng, state: _GenerationState):
    readers = _slots_with_states(state.slots, READER)
    writers = _slots_with_states(state.slots, WRITER)
    free_slots = _slots_with_states(state.slots, FREE)
    closed_slots = _slots_with_states(state.slots, CLOSED)
    choices = []
    if free_slots:
        choices.append(("free", free_slots))
    if closed_slots:
        choices.extend((("closed", closed_slots), ("duplicate-close", closed_slots)))
    if readers:
        choices.append(("wrong-write", readers))
    if writers:
        choices.append(("wrong-read", writers))
    category, candidates = choices[rng.range(0, len(choices))]
    slot = _choose(rng, candidates)
    if category == "duplicate-close":
        return Close(slot)
    if category == "wrong-write":
        if rng.range(0, 2) == 0:
            return Write(
                slot,
                _safe_generation_length(rng, state, slot),
                rng.range(0, 256),
            )
        return WriteNull(slot)
    if category == "wrong-read":
        if rng.range(0, 2) == 0:
            return Read(slot, _safe_generation_length(rng, state, slot))
        return ReadNull(slot)

    operation_kind = rng.range(0, 7)
    if operation_kind == 0:
        return Read(slot, _generation_length(rng))
    if operation_kind == 1:
        return Write(slot, _generation_length(rng), rng.range(0, 256))
    if operation_kind == 2:
        return Close(slot)
    if operation_kind == 3:
        return Poll(slot, _generation_poll_mask(rng))
    if operation_kind == 4:
        return GetSize(slot)
    if operation_kind == 5:
        return Fionread(slot)
    return ReadNull(slot) if rng.range(0, 2) == 0 else WriteNull(slot)


def _generation_length(rng) -> int:
    if rng.range(0, 2) == 0:
        return _choose(rng, _GENERATION_LENGTH_BOUNDARIES)
    return rng.range(0, MAX_IO_BYTES + 1)


def _safe_generation_length(rng, state: _GenerationState, slot: int) -> int:
    if state.slots[slot] in (READER, WRITER) and not state.is_nonblocking(slot):
        return 0
    return _generation_length(rng)


def _choose_any_slot(rng, open_slots, available_slots) -> int:
    if available_slots and rng.range(0, 4) == 0:
        return _choose(rng, available_slots)
    return _choose(rng, open_slots)


def _generation_pipe_size(rng) -> int:
    if rng.range(0, 2) == 0:
        return _choose(rng, _GENERATION_PIPE_SIZE_BOUNDARIES)
    return rng.range(0, MAX_PIPE_SIZE + 1)


def _generation_poll_mask(rng) -> int:
    if rng.range(0, 2) == 0:
        return _choose(rng, _GENERATION_POLL_BOUNDARIES)
    return rng.range(0, MAX_POLL_MASK + 1)


def _generate_legacy_scenario(rng: LegacyLcgRng, operation_count: int) -> Scenario:
    operations = []
    slots = [FREE] * MAX_LOGICAL_SLOTS
    for _ in range(operation_count):
        available_operations = _legacy_available_operations(slots)
        operation_kind = available_operations[rng.range(0, len(available_operations))]
        operations.append(_emit_legacy_operation(rng, operation_kind, slots))
    return Scenario(operations)


def _legacy_available_operations(slots: List[int]):
    has_reader = READER in slots
    has_writer = WRITER in slots
    has_any = has_reader or has_writer
    free_slots = slots.count(FREE)
    operations = []
    if free_slots >= 2:
        operations.append("pipe2")
    if has_reader:
        operations.extend(("read", "close", "poll", "fionread"))
    if has_writer:
        operations.extend(("write", "close", "poll", "set-size", "get-size"))
    if has_any and free_slots >= 1:
        operations.append("dup")
    return operations


def _emit_legacy_operation(rng: LegacyLcgRng, operation_kind: str, slots: List[int]):
    if operation_kind == "pipe2":
        free_slots = _slots_with_states(slots, FREE)
        read_slot = _take_random(rng, free_slots)
        write_slot = _choose(rng, free_slots)
        slots[read_slot] = READER
        slots[write_slot] = WRITER
        return Pipe2(read_slot, write_slot)
    if operation_kind == "read":
        return Read(_choose(rng, _slots_with_states(slots, READER)), rng.range(0, 8193))
    if operation_kind == "write":
        return Write(
            _choose(rng, _slots_with_states(slots, WRITER)),
            rng.range(0, 8193),
            rng.range(0, 256),
        )
    if operation_kind == "dup":
        source = _choose(rng, _slots_with_states(slots, READER, WRITER))
        destination = _choose(rng, _slots_with_states(slots, FREE))
        slots[destination] = slots[source]
        return Dup(source, destination)
    if operation_kind == "close":
        slot = _choose(rng, _slots_with_states(slots, READER, WRITER))
        slots[slot] = FREE
        return Close(slot)
    if operation_kind == "poll":
        slot = _choose(rng, _slots_with_states(slots, READER, WRITER))
        return Poll(slot, 1 if slots[slot] == READER else 4)
    if operation_kind == "set-size":
        slot = _choose(rng, _slots_with_states(slots, WRITER))
        return SetSize(slot, rng.range(1, 1048577))
    if operation_kind == "get-size":
        return GetSize(_choose(rng, _slots_with_states(slots, WRITER)))
    return Fionread(_choose(rng, _slots_with_states(slots, READER)))


def _bytes_to_seed(data: bytes) -> int:
    if len(data) >= 8:
        return struct.unpack("<Q", data[:8])[0]
    padded = data + b"\x00" * (8 - len(data))
    return struct.unpack("<Q", padded)[0]


def _slots_with_states(slots: List[int], *states: int):
    return [index for index, state in enumerate(slots) if state in states]


def _choose(rng, values):
    return values[rng.range(0, len(values))]


def _take_random(rng, values: List[int]) -> int:
    return values.pop(rng.range(0, len(values)))


_Rng = LegacyLcgRng
