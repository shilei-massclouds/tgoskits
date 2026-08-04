"""Deterministic generation of complete controlled eventfd lifecycles."""

from dataclasses import dataclass
from typing import List, Optional

from generator import CampaignRng
from blocking_scenario import (
    EFD_SEMAPHORE,
    MAX_COUNTER,
    O_NONBLOCK,
    AssertPending,
    Dup,
    EventFd2,
    Join,
    PointerMode,
    Read,
    Scenario,
    ScenarioDocument,
    SetStatusFlags,
    StartRead,
    StartWrite,
    Write,
    canonical_digest,
    serialize_document,
    validate_entry_limits,
)


GENERATOR_VERSION = "eventfd-blocking-generator-v1"
STORY_COUNT = 7
_FULL_COUNTER_INCREMENT = MAX_COUNTER - ((1 << 32) - 1)


@dataclass(frozen=True)
class GeneratedInput:
    document: ScenarioDocument
    encoded: bytes
    digest: str


def generate_document(rng: CampaignRng) -> ScenarioDocument:
    scenarios = [
        generate_scenario(rng) for _ in range(rng.range(1, 3))
    ]
    document = ScenarioDocument(scenarios, version=2)
    validate_entry_limits(document)
    return document


def generate_scenario(rng: CampaignRng, story: Optional[int] = None) -> Scenario:
    story_index = rng.range(0, STORY_COUNT) if story is None else story
    if story_index < 0 or story_index >= STORY_COUNT:
        raise ValueError(f"unknown blocking story: {story_index}")
    first_slot = rng.range(0, 16)
    second_slot = _different_slot(rng, first_slot)
    if story_index == 0:
        return _read_story(rng, first_slot, second_slot, semaphore=False, alias=False)
    if story_index == 1:
        return _read_story(rng, first_slot, second_slot, semaphore=True, alias=True)
    if story_index == 2:
        return _write_story(first_slot, second_slot, semaphore=False, alias=False)
    if story_index == 3:
        return _write_story(first_slot, second_slot, semaphore=True, alias=True)
    if story_index == 4:
        return _phased_write_story(first_slot)
    if story_index == 5:
        return _zero_write_story(rng, first_slot)
    return _shared_nonblocking_story(rng, first_slot, second_slot)


def generate_input(rng: CampaignRng) -> GeneratedInput:
    document = generate_document(rng)
    encoded = serialize_document(document).encode("utf-8")
    return GeneratedInput(document, encoded, canonical_digest(document))


def canonicalize_seed(seed: int) -> GeneratedInput:
    return generate_input(CampaignRng(seed))


def _read_story(
    rng: CampaignRng,
    first_slot: int,
    second_slot: int,
    *,
    semaphore: bool,
    alias: bool,
) -> Scenario:
    flags = EFD_SEMAPHORE if semaphore else 0
    operations: List[object] = [EventFd2(first_slot, 0, flags)]
    start_slot = first_slot
    trigger_slot = first_slot
    if alias:
        operations.append(Dup(first_slot, second_slot))
        start_slot = second_slot
        trigger_slot = first_slot
    operations.extend(
        (
            StartRead(1, start_slot),
            AssertPending(1),
            Write(trigger_slot, 8, PointerMode.VALID, rng.choice((1, 2, 7))),
            Join(1),
        )
    )
    return Scenario(operations)


def _write_story(
    first_slot: int,
    second_slot: int,
    *,
    semaphore: bool,
    alias: bool,
) -> Scenario:
    flags = EFD_SEMAPHORE if semaphore else 0
    operations: List[object] = [
        EventFd2(first_slot, (1 << 32) - 1, flags),
        Write(first_slot, 8, PointerMode.VALID, _FULL_COUNTER_INCREMENT),
    ]
    start_slot = first_slot
    trigger_slot = first_slot
    if alias:
        operations.append(Dup(first_slot, second_slot))
        start_slot = second_slot
    operations.extend(
        (
            StartWrite(1, start_slot, 1),
            AssertPending(1),
            Read(trigger_slot, 8, PointerMode.VALID),
            Join(1),
        )
    )
    return Scenario(operations)


def _phased_write_story(slot: int) -> Scenario:
    return Scenario(
        (
            EventFd2(slot, (1 << 32) - 1, EFD_SEMAPHORE),
            Write(slot, 8, PointerMode.VALID, _FULL_COUNTER_INCREMENT),
            StartWrite(1, slot, 2),
            AssertPending(1),
            Read(slot, 8, PointerMode.VALID),
            AssertPending(1),
            Read(slot, 8, PointerMode.VALID),
            Join(1),
        )
    )


def _zero_write_story(rng: CampaignRng, slot: int) -> Scenario:
    return Scenario(
        (
            EventFd2(slot, 0, 0),
            StartRead(1, slot),
            AssertPending(1),
            Write(slot, 8, PointerMode.VALID, 0),
            AssertPending(1),
            Write(slot, 8, PointerMode.VALID, rng.choice((1, 2, 7))),
            Join(1),
        )
    )


def _shared_nonblocking_story(
    rng: CampaignRng, first_slot: int, second_slot: int
) -> Scenario:
    return Scenario(
        (
            EventFd2(first_slot, 0, O_NONBLOCK),
            Dup(first_slot, second_slot),
            SetStatusFlags(second_slot, 0),
            StartRead(1, first_slot),
            AssertPending(1),
            Write(second_slot, 8, PointerMode.VALID, rng.choice((1, 2, 7))),
            Join(1),
        )
    )


def _different_slot(rng: CampaignRng, first_slot: int) -> int:
    candidate = rng.range(0, 15)
    return candidate if candidate < first_slot else candidate + 1


__all__ = [
    "CampaignRng",
    "GENERATOR_VERSION",
    "GeneratedInput",
    "canonicalize_seed",
    "generate_document",
    "generate_input",
    "generate_scenario",
]
