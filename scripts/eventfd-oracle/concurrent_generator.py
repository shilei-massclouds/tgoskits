"""Deterministic complete-story generator for eventfd concurrent v1."""

from dataclasses import dataclass
from typing import Optional

from concurrent_scenario import (
    AssertAllPending,
    AssertPending,
    AssertSignalHandled,
    Close,
    Dup,
    EFD_SEMAPHORE,
    EPOLLEXCLUSIVE,
    EPOLLIN,
    EPOLLONESHOT,
    EPOLLET,
    EpollCreate,
    EpollCtl,
    EpollCtlAction,
    EventFd,
    EventFd2,
    Join,
    JoinSet,
    MAX_COUNTER,
    O_NONBLOCK,
    POLLIN,
    POLLOUT,
    PointerMode,
    Read,
    SA_RESTART,
    SIGUSR1,
    Scenario,
    ScenarioDocument,
    SendSignal,
    SetStatusFlags,
    SignalMask,
    SignalConfig,
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
from poll_generator import CampaignRng


GENERATOR_VERSION = "eventfd-concurrent-generator-v1"
STORY_COUNT = 15
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
    if story_index == 5:
        return _poll_story(first, POLLOUT)
    if story_index == 6:
        return _signal_story(rng, actors[0])
    if story_index == 7:
        return _timeout_story(first, second, actors[0])
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
        return _epoll_signal_timeout_story(rng, actors[0])
    return _epoll_lifetime_story(rng, actors[0])


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


def _signal_story(rng: CampaignRng, actor: int) -> Scenario:
    read_interrupt, read_restart, poll_interrupt, write_interrupt, write_restart = (
        _distinct_slots(rng, 5)
    )
    return Scenario(
        (
            SignalConfig(SIGUSR1, 0),
            EventFd(read_interrupt, 0),
            StartRead(actor, read_interrupt, 8),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 1),
            Join(actor),
            SignalConfig(SIGUSR1, SA_RESTART),
            EventFd(read_restart, 0),
            StartRead(actor, read_restart, 8),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 2),
            AssertPending(actor),
            Write(read_restart, 8, PointerMode.VALID, 1),
            Join(actor),
            SignalConfig(SIGUSR1, SA_RESTART),
            EventFd(poll_interrupt, 0),
            StartPoll(actor, poll_interrupt, POLLIN, -1),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 3),
            Join(actor),
            SignalConfig(SIGUSR1, 0),
            EventFd(write_interrupt, (1 << 32) - 1),
            Write(
                write_interrupt,
                8,
                PointerMode.VALID,
                _FULL_COUNTER_INCREMENT,
            ),
            StartWrite(actor, write_interrupt, MAX_COUNTER),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 4),
            Join(actor),
            SignalConfig(SIGUSR1, SA_RESTART),
            EventFd(write_restart, (1 << 32) - 1),
            Write(
                write_restart,
                8,
                PointerMode.VALID,
                _FULL_COUNTER_INCREMENT,
            ),
            StartWrite(actor, write_restart, MAX_COUNTER),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 5),
            AssertPending(actor),
            Read(write_restart, 8, PointerMode.VALID),
            Join(actor),
        )
    )


def _timeout_story(first: int, second: int, actor: int) -> Scenario:
    return Scenario(
        (
            EventFd(first, 0),
            StartPoll(actor, first, POLLIN, 200),
            AssertPending(actor),
            Join(actor),
            EventFd(second, 0),
            StartPoll(actor, second, POLLIN, 1000),
            AssertPending(actor),
            Write(second, 8, PointerMode.VALID, 1),
            Join(actor),
        )
    )


def _ppoll_story(rng: CampaignRng, actor: int) -> Scenario:
    masked, interrupted, expired, ready = _distinct_slots(rng, 4)
    return Scenario(
        (
            SignalConfig(SIGUSR1, SA_RESTART),
            EventFd(masked, 0),
            StartPpoll(actor, masked, POLLIN, None, SignalMask.USR1),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 0),
            AssertPending(actor),
            Write(masked, 8, PointerMode.VALID, 1),
            Join(actor),
            AssertSignalHandled(actor, 1),
            EventFd(interrupted, 0),
            StartPpoll(actor, interrupted, POLLIN, None, SignalMask.EMPTY),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 2),
            Join(actor),
            EventFd(expired, 0),
            StartPpoll(actor, expired, POLLIN, 200_000_000, SignalMask.EMPTY),
            AssertPending(actor),
            Join(actor),
            EventFd(ready, 0),
            StartPpoll(actor, ready, POLLIN, 1_000_000_000, SignalMask.EMPTY),
            AssertPending(actor),
            Write(ready, 8, PointerMode.VALID, 1),
            Join(actor),
        )
    )


def _epoll_lt_story(rng: CampaignRng, actors: tuple[int, int]) -> Scenario:
    event, alias, epoll = _distinct_slots(rng, 3)
    return Scenario(
        (
            EventFd(event, 0),
            Dup(event, alias),
            EpollCreate(epoll, 0),
            EpollCtl(epoll, EpollCtlAction.ADD, event, EPOLLIN, 17),
            EpollCtl(epoll, EpollCtlAction.ADD, alias, EPOLLIN, 34),
            StartEpollWait(actors[0], epoll, 1, -1),
            StartEpollWait(actors[1], epoll, 1, -1),
            AssertAllPending(),
            Write(event, 8, PointerMode.VALID, 1),
            JoinSet((1, 2)),
        )
    )


def _epoll_lifetime_story(rng: CampaignRng, actor: int) -> Scenario:
    event, alias, epoll = _distinct_slots(rng, 3)
    return Scenario(
        (
            EventFd(event, 0),
            Dup(event, alias),
            EpollCreate(epoll, 0),
            EpollCtl(epoll, EpollCtlAction.ADD, event, EPOLLIN, 153),
            Close(event),
            StartEpollWait(actor, epoll, 1, -1),
            AssertPending(actor),
            Write(alias, 8, PointerMode.VALID, 1),
            Join(actor),
            Read(alias, 8, PointerMode.VALID),
            Close(alias),
            EventFd(event, 1),
            StartEpollWait(actor, epoll, 1, 200),
            AssertPending(actor),
            Join(actor),
        )
    )


def _epoll_et_story(rng: CampaignRng, actors: tuple[int, int]) -> Scenario:
    event, epoll = _distinct_slots(rng, 2)
    return Scenario(
        (
            EventFd(event, 0),
            EpollCreate(epoll, 0),
            EpollCtl(epoll, EpollCtlAction.ADD, event, EPOLLIN | EPOLLET, 51),
            StartEpollWait(actors[0], epoll, 1, -1),
            StartEpollWait(actors[1], epoll, 1, -1),
            AssertAllPending(),
            Write(event, 8, PointerMode.VALID, 1),
            Read(event, 8, PointerMode.VALID),
            Write(event, 8, PointerMode.VALID, 1),
            JoinSet((1, 2)),
        )
    )


def _epoll_oneshot_story(rng: CampaignRng, actors: tuple[int, int]) -> Scenario:
    event, epoll = _distinct_slots(rng, 2)
    events = EPOLLIN | EPOLLONESHOT
    return Scenario(
        (
            EventFd(event, 0),
            EpollCreate(epoll, 0),
            EpollCtl(epoll, EpollCtlAction.ADD, event, events, 68),
            StartEpollWait(actors[0], epoll, 1, -1),
            StartEpollWait(actors[1], epoll, 1, -1),
            AssertAllPending(),
            Write(event, 8, PointerMode.VALID, 1),
            EpollCtl(epoll, EpollCtlAction.MOD, event, events, 85),
            JoinSet((1, 2)),
        )
    )


def _epoll_exclusive_story(rng: CampaignRng, actors: tuple[int, int]) -> Scenario:
    event, first_epoll, second_epoll = _distinct_slots(rng, 3)
    events = EPOLLIN | EPOLLEXCLUSIVE
    return Scenario(
        (
            EventFd(event, 0),
            EpollCreate(first_epoll, 0),
            EpollCreate(second_epoll, 0),
            EpollCtl(first_epoll, EpollCtlAction.ADD, event, events, 102),
            EpollCtl(second_epoll, EpollCtlAction.ADD, event, events, 119),
            StartEpollWait(actors[0], first_epoll, 1, -1),
            StartEpollWait(actors[1], second_epoll, 1, -1),
            AssertAllPending(),
            Write(event, 8, PointerMode.VALID, 1),
            Read(event, 8, PointerMode.VALID),
            Write(event, 8, PointerMode.VALID, 1),
            JoinSet((1, 2)),
        )
    )


def _epoll_signal_timeout_story(rng: CampaignRng, actor: int) -> Scenario:
    event, epoll, timeout_epoll = _distinct_slots(rng, 3)
    return Scenario(
        (
            SignalConfig(SIGUSR1, SA_RESTART),
            EventFd(event, 0),
            EpollCreate(epoll, 0),
            EpollCtl(epoll, EpollCtlAction.ADD, event, EPOLLIN | EPOLLET, 136),
            StartEpollPwait(actor, epoll, 4, -1, SignalMask.USR1),
            AssertPending(actor),
            SendSignal(actor, SIGUSR1),
            AssertSignalHandled(actor, 0),
            AssertPending(actor),
            Write(event, 8, PointerMode.VALID, 1),
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


def _different_slot(rng: CampaignRng, first: int) -> int:
    candidate = rng.range(0, 15)
    return candidate if candidate < first else candidate + 1


def _distinct_slots(rng: CampaignRng, count: int) -> tuple[int, ...]:
    available = list(range(16))
    for index in range(count):
        selected = rng.range(index, len(available))
        available[index], available[selected] = available[selected], available[index]
    return tuple(available[:count])


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
