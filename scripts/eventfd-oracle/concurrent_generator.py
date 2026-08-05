"""Deterministic complete-story generator for eventfd concurrent v1."""

from dataclasses import dataclass
from typing import Optional

from concurrent_scenario import (
    AssertAllPending,
    Dup,
    EFD_SEMAPHORE,
    EventFd,
    EventFd2,
    JoinSet,
    MAX_COUNTER,
    O_NONBLOCK,
    POLLIN,
    POLLOUT,
    PointerMode,
    Read,
    Scenario,
    ScenarioDocument,
    SetStatusFlags,
    StartPoll,
    StartRead,
    StartWrite,
    Write,
    canonical_digest,
    serialize_document,
    validate_entry_limits,
)
from poll_generator import CampaignRng


GENERATOR_VERSION = "eventfd-concurrent-generator-v1"
STORY_COUNT = 6
_FULL_COUNTER_INCREMENT = MAX_COUNTER - ((1 << 32) - 1)


@dataclass(frozen=True)
class GeneratedInput:
    document: ScenarioDocument
    encoded: bytes
    digest: str


def generate_scenario(rng: CampaignRng, story: Optional[int] = None) -> Scenario:
    story_index = rng.range(0, STORY_COUNT) if story is None else story
    if story_index < 0 or story_index >= STORY_COUNT:
        raise ValueError(f"unknown concurrent eventfd story: {story_index}")
    first = rng.range(0, 16)
    second = _different_slot(rng, first)
    actors = (1, 2) if rng.range(0, 2) == 0 else (2, 1)
    if story_index == 0:
        return Scenario(
            (
                EventFd2(first, 0, EFD_SEMAPHORE),
                Dup(first, second),
                StartRead(actors[0], first, 8),
                StartRead(actors[1], second, 8),
                AssertAllPending(),
                Write(first, 8, PointerMode.VALID, 2),
                JoinSet((1, 2)),
            )
        )
    if story_index == 1:
        return _poll_story(first, POLLIN)
    if story_index == 2:
        return _ordinary_read_story(first, second, actors, flags=0)
    if story_index == 3:
        return _ordinary_read_story(first, second, actors, flags=O_NONBLOCK)
    if story_index == 4:
        return Scenario(
            (
                EventFd(first, (1 << 32) - 1),
                Write(first, 8, PointerMode.VALID, _FULL_COUNTER_INCREMENT),
                StartWrite(actors[0], first, MAX_COUNTER),
                StartWrite(actors[1], first, MAX_COUNTER),
                AssertAllPending(),
                Read(first, 8, PointerMode.VALID),
                Read(first, 8, PointerMode.VALID),
                JoinSet((1, 2)),
            )
        )
    return _poll_story(first, POLLOUT)


def generate_document(rng: CampaignRng) -> ScenarioDocument:
    document = ScenarioDocument(
        (generate_scenario(rng) for _ in range(rng.range(1, 3))), version=4
    )
    validate_entry_limits(document)
    return document


def generate_input(rng: CampaignRng) -> GeneratedInput:
    document = generate_document(rng)
    encoded = serialize_document(document).encode("utf-8")
    return GeneratedInput(document, encoded, canonical_digest(document))


def canonicalize_seed(seed: int) -> GeneratedInput:
    return generate_input(CampaignRng(seed))


def _ordinary_read_story(first, second, actors, *, flags):
    setup = [EventFd2(first, 0, flags), Dup(first, second)]
    if flags & O_NONBLOCK:
        setup.append(SetStatusFlags(first, 0))
    return Scenario(
        tuple(setup)
        + (
            StartRead(actors[0], first, 8),
            StartRead(actors[1], second, 8),
            AssertAllPending(),
            Write(first, 8, PointerMode.VALID, 1),
            Write(first, 8, PointerMode.VALID, 1),
            JoinSet((1, 2)),
        )
    )


def _poll_story(slot, events):
    setup = [EventFd(slot, 0)]
    if events == POLLOUT:
        setup = [
            EventFd(slot, (1 << 32) - 1),
            Write(slot, 8, PointerMode.VALID, _FULL_COUNTER_INCREMENT),
        ]
    trigger = (
        Write(slot, 8, PointerMode.VALID, 1)
        if events == POLLIN
        else Read(slot, 8, PointerMode.VALID)
    )
    return Scenario(
        tuple(setup)
        + (
            StartPoll(1, slot, events, -1),
            StartPoll(2, slot, events, -1),
            AssertAllPending(),
            trigger,
            JoinSet((1, 2)),
        )
    )


def _different_slot(rng: CampaignRng, first: int) -> int:
    candidate = rng.range(0, 15)
    return candidate if candidate < first else candidate + 1


__all__ = [
    "CampaignRng",
    "GENERATOR_VERSION",
    "GeneratedInput",
    "STORY_COUNT",
    "canonicalize_seed",
    "generate_document",
    "generate_input",
    "generate_scenario",
]
