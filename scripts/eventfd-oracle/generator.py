"""Deterministic resource-aware eventfd scenario generation."""

import hashlib
from dataclasses import dataclass
from typing import Iterable, List, Sequence

from scenario import (
    DUP3_FLAG_VALUES,
    EFD_FLAG_VALUES,
    FD_FLAG_VALUES,
    MAX_LOGICAL_SLOTS,
    MAX_POLL_FDS,
    MAX_U32,
    MAX_U64,
    O_NONBLOCK,
    POLL_LITERAL_FDS,
    STATUS_FLAG_VALUES,
    Close,
    Dup,
    Dup2,
    Dup3,
    EventFd,
    EventFd2,
    GetFdFlags,
    GetStatusFlags,
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


GENERATOR_VERSION = "eventfd-generator-v1"
_RNG_DOMAIN = b"starry-eventfd-oracle-rng-v1\x00"


class CampaignRng:
    """Versioned SHA-256 counter stream with unbiased bounded selection."""

    def __init__(self, seed: int):
        if seed < 0:
            raise ValueError("seed must be nonnegative")
        self._seed = seed.to_bytes(max(1, (seed.bit_length() + 7) // 8), "little")
        self._counter = 0

    def next(self) -> int:
        counter = self._counter.to_bytes(16, "little")
        self._counter += 1
        return int.from_bytes(hashlib.sha256(_RNG_DOMAIN + self._seed + counter).digest()[:8], "little")

    def range(self, start: int, stop: int) -> int:
        if stop <= start:
            raise ValueError("empty random range")
        width = stop - start
        limit = (1 << 64) - ((1 << 64) % width)
        while True:
            value = self.next()
            if value < limit:
                return start + value % width

    def choice(self, values: Sequence):
        if not values:
            raise ValueError("cannot choose from an empty sequence")
        return values[self.range(0, len(values))]


@dataclass(frozen=True)
class GeneratedInput:
    document: ScenarioDocument
    encoded: bytes
    digest: str


def generate_document(rng: CampaignRng) -> ScenarioDocument:
    """Generate one canonical executable document without predicting syscall results."""
    scenario_count = rng.range(1, 3)
    scenarios = [_generate_scenario(rng) for _ in range(scenario_count)]
    document = ScenarioDocument(scenarios)
    validate_entry_limits(document)
    return document


def generate_input(rng: CampaignRng) -> GeneratedInput:
    document = generate_document(rng)
    encoded = serialize_document(document).encode("utf-8")
    return GeneratedInput(document, encoded, canonical_digest(document))


def canonicalize_seed(seed: int) -> GeneratedInput:
    return generate_input(CampaignRng(seed))


def _generate_scenario(rng: CampaignRng) -> Scenario:
    state = ResourceState()
    operations: List = []
    first_slot = rng.range(0, MAX_LOGICAL_SLOTS)
    first_flags = rng.choice((O_NONBLOCK, O_NONBLOCK | 1, O_NONBLOCK | 524288))
    first = EventFd2(first_slot, rng.choice((0, 1, 2, 7, MAX_U32)), first_flags)
    state.apply(first)
    operations.append(first)

    target_count = rng.range(8, 25)
    attempts = 0
    while len(operations) < target_count and attempts < target_count * 16:
        attempts += 1
        candidate = _candidate_operation(rng, state)
        try:
            state.apply(candidate)
        except ScenarioCodecError:
            continue
        operations.append(candidate)
    return Scenario(operations)


def _candidate_operation(rng: CampaignRng, state: ResourceState):
    live = sorted(state.descriptors)
    empty = [slot for slot in range(MAX_LOGICAL_SLOTS) if slot not in state.descriptors]
    kind = rng.range(0, 100)

    if kind < 12 and empty:
        slot = rng.choice(empty)
        flags = rng.choice(EFD_FLAG_VALUES)
        if rng.range(0, 4) == 0:
            return EventFd(slot, rng.choice((0, 1, 7, MAX_U32)))
        return EventFd2(slot, rng.choice((0, 1, 2, 7, MAX_U32)), flags)
    if kind < 28:
        return Read(
            _possibly_dead_slot(rng, live),
            rng.choice((0, 1, 4, 7, 8, 9, 16)),
            rng.choice(tuple(PointerMode)),
        )
    if kind < 44:
        return Write(
            _possibly_dead_slot(rng, live),
            rng.choice((0, 1, 4, 7, 8, 9, 16)),
            rng.choice(tuple(PointerMode)),
            rng.choice((0, 1, 2, 7, MAX_U64 - 2, MAX_U64 - 1, MAX_U64)),
        )
    if kind < 51 and empty:
        return Dup(_possibly_dead_slot(rng, live), rng.choice(empty))
    if kind < 58:
        return Dup2(
            _possibly_dead_slot(rng, live), rng.range(0, MAX_LOGICAL_SLOTS)
        )
    if kind < 65:
        return Dup3(
            _possibly_dead_slot(rng, live),
            rng.range(0, MAX_LOGICAL_SLOTS),
            rng.choice(DUP3_FLAG_VALUES),
        )
    if kind < 72:
        return Close(_possibly_dead_slot(rng, live))
    if kind < 78:
        return GetStatusFlags(_possibly_dead_slot(rng, live))
    if kind < 84:
        return SetStatusFlags(
            _possibly_dead_slot(rng, live), rng.choice(STATUS_FLAG_VALUES)
        )
    if kind < 89:
        return GetFdFlags(_possibly_dead_slot(rng, live))
    if kind < 94:
        return SetFdFlags(
            _possibly_dead_slot(rng, live), rng.choice(FD_FLAG_VALUES)
        )
    return _poll_operation(rng)


def _poll_operation(rng: CampaignRng) -> PollMany:
    entries = []
    for _ in range(rng.range(0, MAX_POLL_FDS + 1)):
        mode = rng.choice(tuple(PollFdMode))
        fd_arg = (
            rng.range(0, MAX_LOGICAL_SLOTS)
            if mode is PollFdMode.SLOT
            else rng.choice(POLL_LITERAL_FDS)
        )
        entries.append(
            PollFdEntry(mode, fd_arg, rng.choice((0, 1, 4, 5, 8, 32767)))
        )
    return PollMany(entries)


def _possibly_dead_slot(rng: CampaignRng, live: Iterable[int]) -> int:
    live_slots = tuple(live)
    if live_slots and rng.range(0, 4) != 0:
        return rng.choice(live_slots)
    return rng.range(0, MAX_LOGICAL_SLOTS)


__all__ = [
    "CampaignRng",
    "GENERATOR_VERSION",
    "GeneratedInput",
    "canonicalize_seed",
    "generate_document",
    "generate_input",
]
