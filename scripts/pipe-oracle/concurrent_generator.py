"""Deterministic complete-story generator for pipe concurrent v1."""

from dataclasses import dataclass
from typing import Optional

from concurrent_scenario import (
    AssertAllPending,
    AssertPending,
    AssertSignalHandled,
    Close,
    Dup,
    EPOLLEXCLUSIVE,
    EPOLLIN,
    EPOLLONESHOT,
    EPOLLET,
    EPOLLOUT,
    EpollCreate,
    EpollCtl,
    EpollCtlAction,
    Join,
    JoinSet,
    O_NONBLOCK,
    POLLIN,
    POLLOUT,
    Pipe2,
    Read,
    SA_RESTART,
    SIGUSR1,
    Scenario,
    ScenarioDocument,
    SendSignal,
    SetSize,
    SetStatusFlags,
    SignalConfig,
    SignalMask,
    StartPoll,
    StartPpoll,
    StartEpollPwait,
    StartEpollPwait2,
    StartEpollWait,
    StartRead,
    StartWrite,
    Write,
    canonical_digest,
    serialize_document,
    validate_entry_limits,
)
from generator import CampaignRng


GENERATOR_VERSION = "pipe-concurrent-generator-v1"
STORY_COUNT = 17


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
    if story_index == 5:
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
    if story_index == 6:
        return _signal_story(rng, actors[0])
    if story_index == 7:
        return _timeout_story(rng, actors[0])
    if story_index == 8:
        return _ppoll_story(rng, actors[0])
    if story_index == 9:
        return _epoll_lt_story(rng, actors)
    if story_index == 10:
        return _epoll_et_story(rng, actors)
    if story_index == 11:
        return _epoll_oneshot_story(rng, actors)
    if story_index == 12:
        return _epoll_exclusive_story(rng, actors)
    if story_index == 13:
        return _epoll_hup_err_story(rng, actors)
    if story_index == 14:
        return _epoll_signal_timeout_story(rng, actors[0])
    if story_index == 15:
        return _epoll_lifetime_story(rng, actors[0])
    return _blocked_close_lifetime_story(rng, actors)


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


def _signal_story(rng: CampaignRng, actor: int) -> Scenario:
    slots = _distinct_slots(rng, 12)
    pairs = tuple((slots[index], slots[index + 1]) for index in range(0, 12, 2))
    return Scenario(
        (
            SignalConfig(SIGUSR1, 0),
            Pipe2(*pairs[0], 0),
            StartRead(actor, pairs[0][0], 1),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 1),
            Join(actor),
            SignalConfig(SIGUSR1, SA_RESTART),
            Pipe2(*pairs[1], 0),
            StartRead(actor, pairs[1][0], 1),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 2),
            AssertPending(actor),
            Write(pairs[1][1], 1, 65),
            Join(actor),
            SignalConfig(SIGUSR1, SA_RESTART),
            Pipe2(*pairs[2], 0),
            StartPoll(actor, pairs[2][0], POLLIN, -1),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 3),
            Join(actor),
            SignalConfig(SIGUSR1, 0),
            Pipe2(*pairs[3], 0),
            SetSize(pairs[3][1], 4096),
            Write(pairs[3][1], 4096, 17),
            StartWrite(actor, pairs[3][1], 4096),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 4),
            Join(actor),
            SignalConfig(SIGUSR1, SA_RESTART),
            Pipe2(*pairs[4], 0),
            SetSize(pairs[4][1], 4096),
            Write(pairs[4][1], 4096, 34),
            StartWrite(actor, pairs[4][1], 4096),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 5),
            AssertPending(actor),
            Read(pairs[4][0], 4096),
            Join(actor),
            SignalConfig(SIGUSR1, SA_RESTART),
            Pipe2(*pairs[5], 0),
            SetSize(pairs[5][1], 4096),
            Write(pairs[5][1], 4096, 51),
            StartWrite(actor, pairs[5][1], 8192),
            AssertPending(actor),
            Read(pairs[5][0], 4096),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 6),
            Join(actor),
        )
    )


def _timeout_story(rng: CampaignRng, actor: int) -> Scenario:
    expired_read, expired_write, ready_read, ready_write = _distinct_slots(rng, 4)
    return Scenario(
        (
            Pipe2(expired_read, expired_write, 0),
            StartPoll(actor, expired_read, POLLIN, 200),
            AssertPending(actor),
            Join(actor),
            Pipe2(ready_read, ready_write, 0),
            StartPoll(actor, ready_read, POLLIN, 1000),
            AssertPending(actor),
            Write(ready_write, 1, 68),
            Join(actor),
        )
    )


def _ppoll_story(rng: CampaignRng, actor: int) -> Scenario:
    slots = _distinct_slots(rng, 8)
    pairs = tuple((slots[index], slots[index + 1]) for index in range(0, 8, 2))
    return Scenario(
        (
            SignalConfig(SIGUSR1, SA_RESTART),
            Pipe2(*pairs[0], 0),
            StartPpoll(actor, pairs[0][0], POLLIN, None, SignalMask.USR1),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 0),
            AssertPending(actor),
            Write(pairs[0][1], 1, 85),
            Join(actor),
            AssertSignalHandled(actor, 1),
            Pipe2(*pairs[1], 0),
            StartPpoll(actor, pairs[1][0], POLLIN, None, SignalMask.EMPTY),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 2),
            Join(actor),
            Pipe2(*pairs[2], 0),
            StartPpoll(
                actor, pairs[2][0], POLLIN, 200_000_000, SignalMask.EMPTY
            ),
            AssertPending(actor),
            Join(actor),
            Pipe2(*pairs[3], 0),
            StartPpoll(
                actor, pairs[3][0], POLLIN, 1_000_000_000, SignalMask.EMPTY
            ),
            AssertPending(actor),
            Write(pairs[3][1], 1, 102),
            Join(actor),
        )
    )


def _epoll_lt_story(rng: CampaignRng, actors: tuple[int, int]) -> Scenario:
    read_slot, write_slot, alias, epoll = _distinct_slots(rng, 4)
    return Scenario(
        (
            Pipe2(read_slot, write_slot, 0),
            Dup(read_slot, alias),
            EpollCreate(epoll, 0),
            EpollCtl(epoll, EpollCtlAction.ADD, read_slot, EPOLLIN, 17),
            EpollCtl(epoll, EpollCtlAction.ADD, alias, EPOLLIN, 34),
            StartEpollWait(actors[0], epoll, 1, -1),
            StartEpollWait(actors[1], epoll, 1, -1),
            AssertAllPending(),
            Write(write_slot, 1, 65),
            JoinSet((1, 2)),
        )
    )


def _epoll_lifetime_story(rng: CampaignRng, actor: int) -> Scenario:
    read_slot, write_slot, alias, epoll = _distinct_slots(rng, 4)
    return Scenario(
        (
            Pipe2(read_slot, write_slot, 0),
            Dup(read_slot, alias),
            EpollCreate(epoll, 0),
            EpollCtl(epoll, EpollCtlAction.ADD, read_slot, EPOLLIN, 221),
            Close(read_slot),
            StartEpollWait(actor, epoll, 1, -1),
            AssertPending(actor),
            Write(write_slot, 1, 111),
            Join(actor),
            Read(alias, 1),
            Close(alias),
            Close(write_slot),
            Pipe2(read_slot, write_slot, 0),
            Write(write_slot, 1, 112),
            StartEpollWait(actor, epoll, 1, 200),
            AssertPending(actor),
            Join(actor),
        )
    )


def _blocked_close_lifetime_story(
    rng: CampaignRng, actors: tuple[int, int]
) -> Scenario:
    slots = _distinct_slots(rng, 6)
    pairs = tuple((slots[index], slots[index + 1]) for index in range(0, 6, 2))
    return Scenario(
        (
            Pipe2(*pairs[0], 0),
            StartRead(actors[0], pairs[0][0], 1),
            AssertPending(actors[0]),
            Close(pairs[0][0]),
            AssertPending(actors[0]),
            Write(pairs[0][1], 1, 113),
            Join(actors[0]),
            Pipe2(*pairs[1], 0),
            SetSize(pairs[1][1], 4096),
            Write(pairs[1][1], 4096, 114),
            StartWrite(actors[0], pairs[1][1], 4096),
            AssertPending(actors[0]),
            Close(pairs[1][1]),
            AssertPending(actors[0]),
            Read(pairs[1][0], 4096),
            Join(actors[0]),
            Pipe2(*pairs[2], 0),
            SetSize(pairs[2][1], 4096),
            Write(pairs[2][1], 4096, 115),
            StartWrite(actors[0], pairs[2][1], 4096),
            StartPoll(actors[1], pairs[2][1], POLLOUT, -1),
            AssertAllPending(),
            Close(pairs[2][0]),
            JoinSet((1, 2)),
        )
    )


def _epoll_et_story(rng: CampaignRng, actors: tuple[int, int]) -> Scenario:
    read_slot, write_slot, epoll = _distinct_slots(rng, 3)
    return Scenario(
        (
            Pipe2(read_slot, write_slot, 0),
            EpollCreate(epoll, 0),
            EpollCtl(epoll, EpollCtlAction.ADD, read_slot, EPOLLIN | EPOLLET, 51),
            StartEpollWait(actors[0], epoll, 1, -1),
            StartEpollWait(actors[1], epoll, 1, -1),
            AssertAllPending(),
            Write(write_slot, 1, 66),
            Read(read_slot, 1),
            Write(write_slot, 1, 67),
            JoinSet((1, 2)),
        )
    )


def _epoll_oneshot_story(rng: CampaignRng, actors: tuple[int, int]) -> Scenario:
    read_slot, write_slot, epoll = _distinct_slots(rng, 3)
    events = EPOLLIN | EPOLLONESHOT
    return Scenario(
        (
            Pipe2(read_slot, write_slot, 0),
            EpollCreate(epoll, 0),
            EpollCtl(epoll, EpollCtlAction.ADD, read_slot, events, 68),
            StartEpollWait(actors[0], epoll, 1, -1),
            StartEpollWait(actors[1], epoll, 1, -1),
            AssertAllPending(),
            Write(write_slot, 1, 68),
            EpollCtl(epoll, EpollCtlAction.MOD, read_slot, events, 85),
            JoinSet((1, 2)),
        )
    )


def _epoll_exclusive_story(rng: CampaignRng, actors: tuple[int, int]) -> Scenario:
    read_slot, write_slot, first_epoll, second_epoll = _distinct_slots(rng, 4)
    events = EPOLLIN | EPOLLEXCLUSIVE
    return Scenario(
        (
            Pipe2(read_slot, write_slot, 0),
            EpollCreate(first_epoll, 0),
            EpollCreate(second_epoll, 0),
            EpollCtl(first_epoll, EpollCtlAction.ADD, read_slot, events, 102),
            EpollCtl(second_epoll, EpollCtlAction.ADD, read_slot, events, 119),
            StartEpollWait(actors[0], first_epoll, 1, -1),
            StartEpollWait(actors[1], second_epoll, 1, -1),
            AssertAllPending(),
            Write(write_slot, 1, 69),
            Read(read_slot, 1),
            Write(write_slot, 1, 70),
            JoinSet((1, 2)),
        )
    )


def _epoll_hup_err_story(rng: CampaignRng, actors: tuple[int, int]) -> Scenario:
    slots = _distinct_slots(rng, 6)
    hup_read, hup_write, hup_epoll, err_read, err_write, err_epoll = slots
    return Scenario(
        (
            Pipe2(hup_read, hup_write, 0),
            EpollCreate(hup_epoll, 0),
            EpollCtl(hup_epoll, EpollCtlAction.ADD, hup_read, EPOLLIN, 136),
            StartEpollWait(actors[0], hup_epoll, 1, -1),
            StartEpollWait(actors[1], hup_epoll, 1, -1),
            AssertAllPending(),
            Close(hup_write),
            JoinSet((1, 2)),
            Pipe2(err_read, err_write, 0),
            SetSize(err_write, 4096),
            Write(err_write, 4096, 85),
            EpollCreate(err_epoll, 0),
            EpollCtl(err_epoll, EpollCtlAction.ADD, err_write, EPOLLOUT, 153),
            StartEpollWait(actors[0], err_epoll, 1, -1),
            StartEpollWait(actors[1], err_epoll, 1, -1),
            AssertAllPending(),
            Close(err_read),
            JoinSet((1, 2)),
        )
    )


def _epoll_signal_timeout_story(rng: CampaignRng, actor: int) -> Scenario:
    read_slot, write_slot, epoll, timeout_epoll = _distinct_slots(rng, 4)
    return Scenario(
        (
            SignalConfig(SIGUSR1, SA_RESTART),
            Pipe2(read_slot, write_slot, 0),
            EpollCreate(epoll, 0),
            EpollCtl(epoll, EpollCtlAction.ADD, read_slot, EPOLLIN | EPOLLET, 170),
            StartEpollPwait(actor, epoll, 4, -1, SignalMask.USR1),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 0),
            AssertPending(actor),
            Write(write_slot, 1, 86),
            Join(actor),
            AssertSignalHandled(actor, 1),
            EpollCreate(timeout_epoll, 0),
            StartEpollPwait2(
                actor, timeout_epoll, 4, 200_000_000, SignalMask.EMPTY
            ),
            AssertPending(actor),
            Join(actor),
        )
    )


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
