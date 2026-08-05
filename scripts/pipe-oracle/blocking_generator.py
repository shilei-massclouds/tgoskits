"""Deterministic generation of complete controlled pipe lifecycles."""

from dataclasses import dataclass
from typing import Optional

from generator import CampaignRng
from blocking_scenario import (
    O_NONBLOCK,
    AssertPending,
    Close,
    Dup,
    GetStatusFlags,
    Join,
    Pipe2,
    Read,
    Scenario,
    ScenarioDocument,
    SetSize,
    SetStatusFlags,
    StartRead,
    StartWrite,
    Write,
    canonical_digest,
    serialize_document,
    validate_entry_limits,
)


GENERATOR_VERSION = "pipe-blocking-generator-v1"
STORY_COUNT = 6


@dataclass(frozen=True)
class GeneratedInput:
    document: ScenarioDocument
    encoded: bytes
    digest: str


def generate_document(rng: CampaignRng) -> ScenarioDocument:
    scenarios = [generate_scenario(rng) for _ in range(rng.range(1, 3))]
    document = ScenarioDocument(scenarios, version=5)
    validate_entry_limits(document)
    return document


def generate_scenario(rng: CampaignRng, story: Optional[int] = None) -> Scenario:
    story_index = rng.range(0, STORY_COUNT) if story is None else story
    if story_index < 0 or story_index >= STORY_COUNT:
        raise ValueError(f"unknown blocking pipe story: {story_index}")
    slots = _distinct_slots(rng, 4)
    read_slot, write_slot, read_alias, write_alias = slots
    if story_index == 0:
        return _read_story(rng, read_slot, write_slot)
    if story_index == 1:
        return _alias_story(
            rng, read_slot, write_slot, read_alias, write_alias
        )
    if story_index == 2:
        return _zero_write_story(rng, read_slot, write_slot)
    if story_index == 3:
        return _eof_story(read_slot, write_slot)
    if story_index == 4:
        return _full_write_story(rng, read_slot, write_slot, phased=False)
    return _full_write_story(rng, read_slot, write_slot, phased=True)


def generate_input(rng: CampaignRng) -> GeneratedInput:
    document = generate_document(rng)
    encoded = serialize_document(document).encode("utf-8")
    return GeneratedInput(document, encoded, canonical_digest(document))


def canonicalize_seed(seed: int) -> GeneratedInput:
    return generate_input(CampaignRng(seed))


def _read_story(rng: CampaignRng, read_slot: int, write_slot: int) -> Scenario:
    length = _choose(rng, (1, 2, 16))
    return Scenario(
        (
            Pipe2(read_slot, write_slot, 0),
            StartRead(1, read_slot, length),
            AssertPending(1),
            Write(write_slot, length, _choose(rng, (0, 65, 255))),
            Join(1),
        )
    )


def _alias_story(
    rng: CampaignRng,
    read_slot: int,
    write_slot: int,
    read_alias: int,
    write_alias: int,
) -> Scenario:
    length = _choose(rng, (1, 3, 16))
    return Scenario(
        (
            Pipe2(read_slot, write_slot, O_NONBLOCK),
            Dup(read_slot, read_alias),
            Dup(write_slot, write_alias),
            SetStatusFlags(read_alias, 0),
            SetStatusFlags(write_alias, 0),
            GetStatusFlags(read_slot),
            GetStatusFlags(write_slot),
            StartRead(1, read_alias, length),
            AssertPending(1),
            Write(write_alias, length, _choose(rng, (1, 66, 254))),
            Join(1),
        )
    )


def _zero_write_story(
    rng: CampaignRng, read_slot: int, write_slot: int
) -> Scenario:
    return Scenario(
        (
            Pipe2(read_slot, write_slot, 0),
            StartRead(1, read_slot, 1),
            AssertPending(1),
            Write(write_slot, 0, _choose(rng, (0, 67, 255))),
            AssertPending(1),
            Write(write_slot, 1, _choose(rng, (1, 68, 254))),
            Join(1),
        )
    )


def _eof_story(read_slot: int, write_slot: int) -> Scenario:
    return Scenario(
        (
            Pipe2(read_slot, write_slot, 0),
            StartRead(1, read_slot, 8),
            AssertPending(1),
            Close(write_slot),
            Join(1),
        )
    )


def _full_write_story(
    rng: CampaignRng,
    read_slot: int,
    write_slot: int,
    *,
    phased: bool,
) -> Scenario:
    fill_byte = _choose(rng, (17, 85, 170))
    worker_length = _choose(rng, (1, 16, 4096))
    operations = [
        Pipe2(read_slot, write_slot, 0),
        SetSize(write_slot, 4096),
        Write(write_slot, 4096, fill_byte),
        StartWrite(1, write_slot, worker_length, fill_byte ^ 0xFF),
        AssertPending(1),
    ]
    if phased:
        operations.extend((Read(read_slot, 1), AssertPending(1), Read(read_slot, 4095)))
    else:
        operations.append(Read(read_slot, 4096))
    operations.append(Join(1))
    return Scenario(operations)


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
    "canonicalize_seed",
    "generate_document",
    "generate_input",
    "generate_scenario",
]
