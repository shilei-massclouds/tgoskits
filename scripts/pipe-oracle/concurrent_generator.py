"""Deterministic complete-story generator for pipe concurrent v1."""

from dataclasses import dataclass
from typing import Optional

from concurrent_scenario import (
    AssertAllPending,
    Close,
    Dup,
    JoinSet,
    O_NONBLOCK,
    POLLIN,
    POLLOUT,
    Pipe2,
    Read,
    Scenario,
    ScenarioDocument,
    SetSize,
    SetStatusFlags,
    StartPoll,
    StartRead,
    StartWrite,
    Write,
    canonical_digest,
    serialize_document,
    validate_entry_limits,
)
from generator import CampaignRng


GENERATOR_VERSION = "pipe-concurrent-generator-v1"
STORY_COUNT = 6


@dataclass(frozen=True)
class GeneratedInput:
    document: ScenarioDocument
    encoded: bytes
    digest: str


def generate_scenario(rng: CampaignRng, story: Optional[int] = None) -> Scenario:
    story_index = rng.range(0, STORY_COUNT) if story is None else story
    if story_index < 0 or story_index >= STORY_COUNT:
        raise ValueError(f"unknown concurrent pipe story: {story_index}")
    read_slot, write_slot, alias = _distinct_slots(rng, 3)
    actors = (1, 2) if rng.range(0, 2) == 0 else (2, 1)
    if story_index in (0, 1):
        flags = O_NONBLOCK if story_index == 1 else 0
        setup = [Pipe2(read_slot, write_slot, flags)]
        second_read = read_slot
        if story_index == 1:
            setup.extend((Dup(read_slot, alias), SetStatusFlags(alias, 0)))
            second_read = alias
        return Scenario(
            tuple(setup)
            + (
                StartRead(actors[0], read_slot, 1),
                StartRead(actors[1], second_read, 1),
                AssertAllPending(),
                Write(write_slot, 1, _choose(rng, (65, 85, 170))),
                Write(write_slot, 1, _choose(rng, (66, 86, 171))),
                JoinSet((1, 2)),
            )
        )
    if story_index == 2:
        return Scenario(
            (
                Pipe2(read_slot, write_slot, 0),
                SetSize(write_slot, 4096),
                Write(write_slot, 4096, 17),
                StartWrite(actors[0], write_slot, 4096),
                StartWrite(actors[1], write_slot, 4096),
                AssertAllPending(),
                Read(read_slot, 4096),
                Read(read_slot, 4096),
                JoinSet((1, 2)),
            )
        )
    if story_index == 3:
        return Scenario(
            (
                Pipe2(read_slot, write_slot, 0),
                StartPoll(1, read_slot, POLLIN, -1),
                StartPoll(2, read_slot, POLLIN, -1),
                AssertAllPending(),
                Write(write_slot, 1, _choose(rng, (1, 65, 255))),
                JoinSet((1, 2)),
            )
        )
    if story_index == 4:
        return Scenario(
            (
                Pipe2(read_slot, write_slot, 0),
                SetSize(write_slot, 4096),
                Write(write_slot, 4096, 85),
                StartPoll(1, write_slot, POLLOUT, -1),
                StartPoll(2, write_slot, POLLOUT, -1),
                AssertAllPending(),
                Read(read_slot, 1),
                AssertAllPending(),
                Read(read_slot, 4095),
                JoinSet((1, 2)),
            )
        )
    return Scenario(
        (
            Pipe2(read_slot, write_slot, 0),
            StartPoll(1, read_slot, POLLIN, -1),
            StartPoll(2, read_slot, POLLIN, -1),
            AssertAllPending(),
            Close(write_slot),
            JoinSet((1, 2)),
        )
    )


def generate_document(rng: CampaignRng) -> ScenarioDocument:
    document = ScenarioDocument(
        (generate_scenario(rng) for _ in range(rng.range(1, 3))), version=7
    )
    validate_entry_limits(document)
    return document


def generate_input(rng: CampaignRng) -> GeneratedInput:
    document = generate_document(rng)
    encoded = serialize_document(document).encode("utf-8")
    return GeneratedInput(document, encoded, canonical_digest(document))


def canonicalize_seed(seed: int) -> GeneratedInput:
    return generate_input(CampaignRng(seed))


def _distinct_slots(rng: CampaignRng, count: int) -> tuple[int, ...]:
    available = list(range(16))
    for index in range(count):
        selected = rng.range(index, len(available))
        available[index], available[selected] = available[selected], available[index]
    return tuple(available[:count])


def _choose(rng: CampaignRng, values: tuple[int, ...]) -> int:
    return values[rng.range(0, len(values))]


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
