"""Deterministic generation of controlled eventfd poll lifecycles."""

from dataclasses import dataclass
from typing import List, Optional

from generator import CampaignRng
from poll_scenario import (
    CORPUS_VERSION,
    EFD_SEMAPHORE,
    MAX_COUNTER,
    O_NONBLOCK,
    POLLIN,
    POLLOUT,
    AssertPending,
    Dup,
    EventFd2,
    Join,
    PointerMode,
    Read,
    Scenario,
    ScenarioDocument,
    StartPoll,
    Write,
    canonical_digest,
    serialize_document,
    validate_entry_limits,
)


GENERATOR_VERSION = "eventfd-blocking-generator-v2"
STORY_COUNT = 7
_FULL_COUNTER_INCREMENT = MAX_COUNTER - ((1 << 32) - 1)


@dataclass(frozen=True)
class GeneratedInput:
    document: ScenarioDocument
    encoded: bytes
    digest: str


def generate_document(rng: CampaignRng) -> ScenarioDocument:
    scenarios = [generate_scenario(rng) for _ in range(rng.range(1, 3))]
    document = ScenarioDocument(scenarios, version=CORPUS_VERSION)
    validate_entry_limits(document)
    return document


def generate_scenario(rng: CampaignRng, story: Optional[int] = None) -> Scenario:
    story_index = rng.range(0, STORY_COUNT) if story is None else story
    if story_index < 0 or story_index >= STORY_COUNT:
        raise ValueError(f"unknown blocking poll story: {story_index}")
    first_slot = rng.range(0, 16)
    second_slot = _different_slot(rng, first_slot)
    if story_index == 0:
        return _pollin_story(
            rng, first_slot, second_slot, flags=0, alias=False, zero_first=False
        )
    if story_index == 1:
        return _pollin_story(
            rng,
            first_slot,
            second_slot,
            flags=EFD_SEMAPHORE,
            alias=True,
            zero_first=False,
        )
    if story_index == 2:
        return _pollin_story(
            rng,
            first_slot,
            second_slot,
            flags=O_NONBLOCK,
            alias=True,
            zero_first=False,
        )
    if story_index == 3:
        return _pollin_story(
            rng, first_slot, second_slot, flags=0, alias=False, zero_first=True
        )
    if story_index == 4:
        return _pollout_story(first_slot, second_slot, flags=0, alias=False)
    if story_index == 5:
        return _pollout_story(
            first_slot,
            second_slot,
            flags=EFD_SEMAPHORE,
            alias=True,
        )
    return _pollout_story(
        first_slot,
        second_slot,
        flags=EFD_SEMAPHORE | O_NONBLOCK,
        alias=True,
    )


def generate_input(rng: CampaignRng) -> GeneratedInput:
    document = generate_document(rng)
    encoded = serialize_document(document).encode("utf-8")
    return GeneratedInput(document, encoded, canonical_digest(document))


def canonicalize_seed(seed: int) -> GeneratedInput:
    return generate_input(CampaignRng(seed))


def _pollin_story(
    rng: CampaignRng,
    first_slot: int,
    second_slot: int,
    *,
    flags: int,
    alias: bool,
    zero_first: bool,
) -> Scenario:
    operations: List[object] = [EventFd2(first_slot, 0, flags)]
    start_slot = first_slot
    trigger_slot = first_slot
    if alias:
        operations.append(Dup(first_slot, second_slot))
        start_slot = second_slot
    operations.extend((StartPoll(1, start_slot, POLLIN), AssertPending(1)))
    if zero_first:
        operations.extend(
            (Write(trigger_slot, 8, PointerMode.VALID, 0), AssertPending(1))
        )
    operations.extend(
        (
            Write(trigger_slot, 8, PointerMode.VALID, rng.choice((1, 2, 7))),
            Join(1),
        )
    )
    return Scenario(operations)


def _pollout_story(
    first_slot: int,
    second_slot: int,
    *,
    flags: int,
    alias: bool,
) -> Scenario:
    operations: List[object] = [
        EventFd2(first_slot, (1 << 32) - 1, flags),
        Write(first_slot, 8, PointerMode.VALID, _FULL_COUNTER_INCREMENT),
    ]
    start_slot = first_slot
    if alias:
        operations.append(Dup(first_slot, second_slot))
        start_slot = second_slot
    operations.extend(
        (
            StartPoll(1, start_slot, POLLOUT),
            AssertPending(1),
            Read(first_slot, 8, PointerMode.VALID),
            Join(1),
        )
    )
    return Scenario(operations)


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
