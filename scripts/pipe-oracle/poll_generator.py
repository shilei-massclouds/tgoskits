"""Deterministic generation of complete controlled pipe poll lifecycles."""

from dataclasses import dataclass
from typing import Optional

from generator import CampaignRng
from poll_scenario import (
    CORPUS_VERSION,
    O_NONBLOCK,
    POLLIN,
    POLLOUT,
    AssertPending,
    Close,
    Dup,
    Join,
    Pipe2,
    Read,
    Scenario,
    ScenarioDocument,
    SetSize,
    StartPoll,
    Write,
    canonical_digest,
    serialize_document,
    validate_entry_limits,
)


GENERATOR_VERSION = "pipe-blocking-generator-v2"
STORY_COUNT = 7


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
        raise ValueError(f"unknown blocking pipe poll story: {story_index}")
    read_slot, write_slot, read_alias, write_alias = _distinct_slots(rng, 4)
    if story_index == 0:
        return _pollin_story(
            rng,
            read_slot,
            write_slot,
            read_alias,
            write_alias,
            alias=False,
            flags=0,
        )
    if story_index == 1:
        return _pollin_story(
            rng,
            read_slot,
            write_slot,
            read_alias,
            write_alias,
            alias=True,
            flags=0,
        )
    if story_index == 2:
        return _pollin_story(
            rng,
            read_slot,
            write_slot,
            read_alias,
            write_alias,
            alias=True,
            flags=O_NONBLOCK,
        )
    if story_index == 3:
        return _zero_write_story(rng, read_slot, write_slot)
    if story_index == 4:
        return _pollhup_story(read_slot, write_slot)
    if story_index == 5:
        return _pollout_story(
            rng,
            read_slot,
            write_slot,
            read_alias,
            write_alias,
            alias=True,
            flags=O_NONBLOCK,
            phased=False,
        )
    return _pollout_story(
        rng,
        read_slot,
        write_slot,
        read_alias,
        write_alias,
        alias=False,
        flags=0,
        phased=True,
    )


def generate_input(rng: CampaignRng) -> GeneratedInput:
    document = generate_document(rng)
    encoded = serialize_document(document).encode("utf-8")
    return GeneratedInput(document, encoded, canonical_digest(document))


def canonicalize_seed(seed: int) -> GeneratedInput:
    return generate_input(CampaignRng(seed))


def _pollin_story(
    rng: CampaignRng,
    read_slot: int,
    write_slot: int,
    read_alias: int,
    write_alias: int,
    *,
    alias: bool,
    flags: int,
) -> Scenario:
    length = _choose(rng, (1, 2, 16))
    operations = [Pipe2(read_slot, write_slot, flags)]
    start_slot = read_slot
    trigger_slot = write_slot
    if alias:
        operations.extend((Dup(read_slot, read_alias), Dup(write_slot, write_alias)))
        start_slot = read_alias
        trigger_slot = write_alias
    operations.extend(
        (
            StartPoll(1, start_slot, POLLIN),
            AssertPending(1),
            Write(trigger_slot, length, _choose(rng, (1, 65, 255))),
            Join(1),
        )
    )
    return Scenario(operations)


def _zero_write_story(
    rng: CampaignRng, read_slot: int, write_slot: int
) -> Scenario:
    return Scenario(
        (
            Pipe2(read_slot, write_slot, 0),
            StartPoll(1, read_slot, POLLIN),
            AssertPending(1),
            Write(write_slot, 0, _choose(rng, (0, 67, 255))),
            AssertPending(1),
            Write(write_slot, 1, _choose(rng, (1, 68, 254))),
            Join(1),
        )
    )


def _pollhup_story(read_slot: int, write_slot: int) -> Scenario:
    return Scenario(
        (
            Pipe2(read_slot, write_slot, 0),
            StartPoll(1, read_slot, POLLIN),
            AssertPending(1),
            Close(write_slot),
            Join(1),
        )
    )


def _pollout_story(
    rng: CampaignRng,
    read_slot: int,
    write_slot: int,
    read_alias: int,
    write_alias: int,
    *,
    alias: bool,
    flags: int,
    phased: bool,
) -> Scenario:
    fill_byte = _choose(rng, (17, 85, 170))
    operations = [
        Pipe2(read_slot, write_slot, flags),
        SetSize(write_slot, 4096),
        Write(write_slot, 4096, fill_byte),
    ]
    start_slot = write_slot
    trigger_slot = read_slot
    if alias:
        operations.extend((Dup(read_slot, read_alias), Dup(write_slot, write_alias)))
        start_slot = write_alias
        trigger_slot = read_alias
    operations.extend((StartPoll(1, start_slot, POLLOUT), AssertPending(1)))
    if phased:
        operations.extend(
            (Read(trigger_slot, 1), AssertPending(1), Read(trigger_slot, 4095))
        )
    else:
        operations.append(Read(trigger_slot, 4096))
    operations.append(Join(1))
    return Scenario(operations)


def _distinct_slots(rng: CampaignRng, count: int) -> tuple[int, ...]:
    return _distinct_slots_excluding(rng, (), count)


def _distinct_slots_excluding(
    rng: CampaignRng, excluded: tuple[int, ...], count: int
) -> tuple[int, ...]:
    available = [slot for slot in range(16) if slot not in excluded]
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
    "canonicalize_seed",
    "generate_document",
    "generate_input",
    "generate_scenario",
]
