"""Controlled two-worker eventfd scenario IR and canonical v4 codec."""

import copy
import hashlib
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional, Tuple, Union

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

import scenario as simple
from linux_oracle import actor as controlled_actor


CORPUS_VERSION = 4
MAX_LOGICAL_SLOTS = simple.MAX_LOGICAL_SLOTS
MAX_OPS_PER_SCENARIO = 64
MAX_SCENARIOS_PER_ENTRY = 8
MAX_ENTRY_BYTES = 16384
MAX_U64 = simple.MAX_U64
MAX_COUNTER = simple.MAX_COUNTER
POLLIN = 1
POLLOUT = 4
POLL_EVENTS = (POLLIN, POLLOUT)
TIMEOUT_VALUES = tuple([-1] + list(range(0, 1001)))
SIGUSR1 = 10
SA_RESTART = 268435456
SIGNAL_FLAGS = (0, SA_RESTART)
MAX_TIMEOUT_NS = 1_000_000_000
EPOLL_CLOEXEC = 524288
EPOLLIN = 1
EPOLLOUT = 4
EPOLLERR = 8
EPOLLHUP = 16
EPOLLEXCLUSIVE = 268435456
EPOLLONESHOT = 1073741824
EPOLLET = 2147483648
EPOLL_READY_BITS = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP
EPOLL_MODE_BITS = EPOLLEXCLUSIVE | EPOLLONESHOT | EPOLLET
EPOLL_ALLOWED_BITS = EPOLL_READY_BITS | EPOLL_MODE_BITS

ScenarioCodecError = simple.ScenarioCodecError
Scenario = simple.Scenario
ScenarioDocument = simple.ScenarioDocument
PointerMode = simple.PointerMode
EventFd = simple.EventFd
EventFd2 = simple.EventFd2
Read = simple.Read
Write = simple.Write
Dup = simple.Dup
Dup2 = simple.Dup2
Dup3 = simple.Dup3
Close = simple.Close
GetStatusFlags = simple.GetStatusFlags
SetStatusFlags = simple.SetStatusFlags
GetFdFlags = simple.GetFdFlags
SetFdFlags = simple.SetFdFlags
PollMany = simple.PollMany
EFD_SEMAPHORE = simple.EFD_SEMAPHORE
O_NONBLOCK = simple.O_NONBLOCK


@dataclass(frozen=True)
class StartRead:
    actor: int
    slot: int
    length: int


@dataclass(frozen=True)
class StartWrite:
    actor: int
    slot: int
    value: int


@dataclass(frozen=True)
class StartPoll:
    actor: int
    slot: int
    events: int
    timeout_ms: int


class SignalMask(str, Enum):
    EMPTY = "empty"
    USR1 = "usr1"


@dataclass(frozen=True)
class StartPpoll:
    actor: int
    slot: int
    events: int
    timeout_ns: Optional[int]
    sigmask: SignalMask


@dataclass(frozen=True)
class SignalConfig:
    signo: int
    flags: int


@dataclass(frozen=True)
class SendSignal:
    actor: int
    signo: int


@dataclass(frozen=True)
class AssertSignalHandled:
    actor: int
    count: int


class EpollCtlAction(str, Enum):
    ADD = "add"
    MOD = "mod"
    DEL = "del"


@dataclass(frozen=True)
class EpollCreate:
    slot: int
    flags: int


@dataclass(frozen=True)
class EpollCtl:
    epoll_slot: int
    action: EpollCtlAction
    target_slot: int
    events: int
    data: int


@dataclass(frozen=True)
class StartEpollWait:
    actor: int
    epoll_slot: int
    maxevents: int
    timeout_ms: int


@dataclass(frozen=True)
class StartEpollPwait:
    actor: int
    epoll_slot: int
    maxevents: int
    timeout_ms: int
    sigmask: SignalMask


@dataclass(frozen=True)
class StartEpollPwait2:
    actor: int
    epoll_slot: int
    maxevents: int
    timeout_ns: Optional[int]
    sigmask: SignalMask


@dataclass(frozen=True)
class AssertPending:
    actor: int


@dataclass(frozen=True)
class AssertAllPending:
    pass


@dataclass(frozen=True)
class Join:
    actor: int


@dataclass(frozen=True)
class JoinSet:
    actors: Tuple[int, ...]

    def __init__(self, actors: Iterable[int]):
        object.__setattr__(self, "actors", tuple(actors))


ConcurrentOperation = Union[
    StartRead,
    StartWrite,
    StartPoll,
    StartPpoll,
    SignalConfig,
    SendSignal,
    AssertSignalHandled,
    EpollCreate,
    EpollCtl,
    StartEpollWait,
    StartEpollPwait,
    StartEpollPwait2,
    AssertPending,
    AssertAllPending,
    Join,
    JoinSet,
]
Operation = Union[simple.Operation, ConcurrentOperation]


@dataclass
class EpollRegistration:
    target_slot: int
    event_id: int
    description_id: int
    events: int
    data: int
    enabled: bool
    last_ready: bool
    edge_pending: bool


@dataclass
class EpollState:
    flags: int
    registrations: dict[int, EpollRegistration]


class ResourceState:
    """Validate blocking proofs while allowing Linux to choose each winner."""

    def __init__(self, *, enforce_controller_progress: bool = False) -> None:
        self.simple = simple.ResourceState()
        # A controller syscall must be safe even if a woken worker has not run
        # yet. Worker I/O updates `simple`; this shadow receives only completed
        # controller operations until an explicit join establishes a barrier.
        self.controller_simple = simple.ResourceState()
        self.enforce_controller_progress = enforce_controller_progress
        self.workers = controlled_actor.ControlledWorkers[
            ConcurrentOperation, tuple[str, int]
        ]()
        self.peak_active_workers = 0
        self._next_completion_ordinal = 1
        self.signal_flags: Optional[int] = None
        self.signal_counts = {actor: 0 for actor in controlled_actor.WORKER_ACTORS}
        self.pending_signal_counts = {
            actor: 0 for actor in controlled_actor.WORKER_ACTORS
        }
        self.epolls: dict[int, EpollState] = {}
        self.exclusive_cursor: dict[int, int] = {}

    def apply(self, operation: Operation) -> None:
        if isinstance(
            operation,
            (
                StartRead,
                StartWrite,
                StartPoll,
                StartPpoll,
                StartEpollWait,
                StartEpollPwait,
                StartEpollPwait2,
            ),
        ):
            self._start(operation)
        elif isinstance(operation, EpollCreate):
            self._epoll_create(operation)
        elif isinstance(operation, EpollCtl):
            if self.workers.active_actors:
                self._apply_trigger(operation)
            else:
                self._epoll_ctl(operation)
        elif isinstance(operation, SignalConfig):
            if self.workers.active_actors:
                raise ScenarioCodecError(
                    "actor-lifecycle", "signal-config requires idle workers"
                )
            self.signal_flags = operation.flags
        elif isinstance(operation, SendSignal):
            self._send_signal(operation)
        elif isinstance(operation, AssertSignalHandled):
            if self.signal_counts[operation.actor] != operation.count:
                raise ScenarioCodecError(
                    "blocking-proof",
                    f"worker actor {operation.actor} handler count is not {operation.count}",
                )
        elif isinstance(operation, AssertPending):
            self._transition(lambda: self.workers.assert_pending(operation.actor))
        elif isinstance(operation, AssertAllPending):
            self._transition(self.workers.assert_all_pending)
        elif isinstance(operation, Join):
            self._complete_timeout(operation.actor)
            self._transition(lambda: self.workers.join(operation.actor, lambda _call: None))
            self._synchronize_controller_state_if_idle()
        elif isinstance(operation, JoinSet):
            for actor in operation.actors:
                self._complete_timeout(actor)
            self._transition(
                lambda: self.workers.join_set(operation.actors, lambda _calls: None)
            )
            self._synchronize_controller_state_if_idle()
        elif self.workers.active_actors:
            self._apply_trigger(operation)
        else:
            self._apply_synchronous(operation)

    def finish_scenario(self) -> None:
        self._transition(self.workers.finish_scenario)

    def descriptor(self, slot: int):
        return self.simple.descriptor(slot)

    def description(self, slot: int):
        return self.simple.description(slot)

    def event(self, slot: int):
        return self.simple.event(slot)

    def _start(
        self,
        operation: Union[
            StartRead,
            StartWrite,
            StartPoll,
            StartPpoll,
            StartEpollWait,
            StartEpollPwait,
            StartEpollPwait2,
        ],
    ) -> None:
        def identify_resource() -> tuple[str, int]:
            if isinstance(
                operation, (StartEpollWait, StartEpollPwait, StartEpollPwait2)
            ):
                epoll = self.epolls.get(operation.epoll_slot)
                if epoll is None:
                    raise ScenarioCodecError(
                        "blocking-proof", "worker epoll slot is not live"
                    )
                finite_timeout = (
                    operation.timeout_ms
                    if isinstance(operation, (StartEpollWait, StartEpollPwait))
                    else operation.timeout_ns
                )
                timeout_too_short = (
                    0 <= finite_timeout < 100
                    if isinstance(operation, (StartEpollWait, StartEpollPwait))
                    else finite_timeout is not None and finite_timeout < 100_000_000
                )
                if timeout_too_short or self._epoll_has_ready(epoll):
                    raise ScenarioCodecError(
                        "blocking-proof",
                        "worker epoll wait must initially block",
                    )
                return ("epoll", operation.epoll_slot)
            description = self.simple.description(operation.slot)
            event = self.simple.event(operation.slot)
            if description is None or event is None:
                raise ScenarioCodecError(
                    "blocking-proof", f"worker slot {operation.slot} is not live"
                )
            if isinstance(operation, StartRead):
                if operation.length != 8 or description.nonblocking or event.count != 0:
                    raise ScenarioCodecError(
                        "blocking-proof", "worker read must initially block"
                    )
            elif isinstance(operation, StartWrite):
                if (
                    description.nonblocking
                    or operation.value == MAX_U64
                    or operation.value <= MAX_COUNTER - event.count
                ):
                    raise ScenarioCodecError(
                        "blocking-proof", "worker write must initially block"
                    )
            else:
                ready = event.count > 0 if operation.events == POLLIN else event.count < MAX_COUNTER
                timeout_too_short = (
                    0 <= operation.timeout_ms < 100
                    if isinstance(operation, StartPoll)
                    else operation.timeout_ns is not None
                    and operation.timeout_ns < 100_000_000
                )
                if ready or timeout_too_short:
                    raise ScenarioCodecError(
                        "blocking-proof",
                        "worker poll timeout is too short for the pending guard",
                    )
            return ("event", description.event_id)

        self._transition(
            lambda: self.workers.start(operation.actor, operation, identify_resource)
        )
        self.peak_active_workers = max(
            self.peak_active_workers, len(self.workers.active_actors)
        )

    def _send_signal(self, operation: SendSignal) -> None:
        if self.signal_flags is None:
            raise ScenarioCodecError(
                "actor-lifecycle", "send-signal requires signal-config"
            )
        worker = self.workers.worker(operation.actor)
        if worker is None:
            raise ScenarioCodecError(
                "actor-lifecycle",
                f"send-signal actor {operation.actor} requires an active worker",
            )
        self._transition(lambda: self.workers.before_trigger((operation.actor,)))
        if (
            isinstance(
                worker.operation,
                (StartPpoll, StartEpollPwait, StartEpollPwait2),
            )
            and worker.operation.sigmask is SignalMask.USR1
        ):
            self.pending_signal_counts[operation.actor] += 1
            return
        self.signal_counts[operation.actor] += 1
        interrupted = isinstance(
            worker.operation,
            (
                StartPoll,
                StartPpoll,
                StartEpollWait,
                StartEpollPwait,
                StartEpollPwait2,
            ),
        ) or self.signal_flags == 0
        if interrupted:
            self._mark_completed(operation.actor)

    def _complete_timeout(self, actor: int) -> None:
        worker = self.workers.worker(actor)
        if (
            worker is None
            or worker.completed
            or not isinstance(
                worker.operation,
                (
                    StartPoll,
                    StartPpoll,
                    StartEpollWait,
                    StartEpollPwait,
                    StartEpollPwait2,
                ),
            )
            or (
                isinstance(worker.operation, StartPoll)
                and worker.operation.timeout_ms < 0
            )
            or (
                isinstance(worker.operation, StartPpoll)
                and worker.operation.timeout_ns is None
            )
            or (
                isinstance(worker.operation, (StartEpollWait, StartEpollPwait))
                and worker.operation.timeout_ms < 0
            )
            or (
                isinstance(worker.operation, StartEpollPwait2)
                and worker.operation.timeout_ns is None
            )
        ):
            return
        self._mark_completed(actor)

    def _mark_completed(self, actor: int) -> None:
        self._deliver_pending_signals(actor)
        self._transition(lambda: self.workers.update_completable(actor, True))
        ordinal = self._next_completion_ordinal
        self._next_completion_ordinal += 1
        self._transition(
            lambda: self.workers.mark_completed(actor, ordinal)
        )

    def _apply_trigger(self, operation: Operation) -> None:
        if not isinstance(operation, (Read, Write, EpollCtl)):
            raise ScenarioCodecError(
                "actor-lifecycle",
                "only eventfd read/write or epoll MOD may trigger active workers",
            )
        if isinstance(operation, EpollCtl):
            if operation.action is not EpollCtlAction.MOD:
                raise ScenarioCodecError(
                    "actor-lifecycle", "only epoll MOD may trigger active workers"
                )
            resource_kind = "epoll"
            resource_id = operation.epoll_slot
        else:
            description = self.simple.description(operation.slot)
            if description is None:
                raise ScenarioCodecError(
                    "blocking-proof", f"trigger slot {operation.slot} is not live"
                )
            resource_kind = "event"
            resource_id = description.event_id
        selected = tuple(
            actor
            for actor in self.workers.active_actors
            if not self.workers.worker(actor).completed
            and (
                self.workers.worker(actor).resource == (resource_kind, resource_id)
                or resource_kind == "event"
                and self._epoll_worker_watches(
                    self.workers.worker(actor), resource_id
                )
            )
        )
        if not selected:
            raise ScenarioCodecError(
                "actor-lifecycle", "trigger does not target an incomplete worker resource"
            )
        self._transition(lambda: self.workers.before_trigger(selected))
        if isinstance(operation, EpollCtl):
            self._epoll_ctl(operation)
        else:
            self._apply_synchronous(operation)
        self._complete_ready_workers()

    def _complete_ready_workers(self) -> None:
        made_progress = True
        while made_progress:
            made_progress = False
            for actor in self.workers.active_actors:
                worker = self.workers.worker(actor)
                if worker.completed:
                    continue
                operation = worker.operation
                if isinstance(
                    operation,
                    (StartEpollWait, StartEpollPwait, StartEpollPwait2),
                ):
                    epoll = self.epolls[operation.epoll_slot]
                    ready = self._epoll_ready(epoll, operation.maxevents)
                    if ready:
                        self._mark_completed(actor)
                        made_progress = True
                    continue
                event = self.simple.event(operation.slot)
                description = self.simple.description(operation.slot)
                if event is None or description is None:
                    continue
                completion = None
                if isinstance(operation, StartRead) and event.count > 0:
                    completion = Read(operation.slot, operation.length, PointerMode.VALID)
                elif (
                    isinstance(operation, StartWrite)
                    and operation.value <= MAX_COUNTER - event.count
                ):
                    completion = Write(
                        operation.slot, 8, PointerMode.VALID, operation.value
                    )
                elif isinstance(operation, StartPoll) and (
                    (operation.events == POLLIN and event.count > 0)
                    or (operation.events == POLLOUT and event.count < MAX_COUNTER)
                ):
                    completion = False
                elif isinstance(operation, StartPpoll) and (
                    (operation.events == POLLIN and event.count > 0)
                    or (operation.events == POLLOUT and event.count < MAX_COUNTER)
                ):
                    completion = False
                if completion is None:
                    continue
                self._deliver_pending_signals(actor)
                self._transition(lambda actor=actor: self.workers.update_completable(actor, True))
                if completion is not False:
                    self.simple.apply(completion)
                    self._refresh_epolls(description.event_id)
                ordinal = self._next_completion_ordinal
                self._next_completion_ordinal += 1
                self._transition(
                    lambda actor=actor, ordinal=ordinal: self.workers.mark_completed(
                        actor, ordinal
                    )
                )
                made_progress = True

    def _apply_synchronous(self, operation: simple.Operation) -> None:
        if isinstance(operation, (EventFd, EventFd2)) and operation.slot in self.epolls:
            raise ScenarioCodecError(
                "resource-state", f"creation destination slot {operation.slot} is live"
            )
        if isinstance(operation, Dup) and (
            operation.source_slot in self.epolls
            or operation.destination_slot in self.epolls
        ):
            raise ScenarioCodecError("resource-state", "epoll dup is not supported")
        descriptor = (
            self.simple.descriptor(operation.slot)
            if isinstance(operation, (Read, Write, Close))
            else None
        )
        description = (
            self.simple.description(operation.slot)
            if isinstance(operation, (Read, Write, Close))
            else None
        )
        if self.enforce_controller_progress:
            try:
                self.controller_simple.apply(operation)
            except ScenarioCodecError as error:
                if (
                    self.workers.active_actors
                    and error.category == "blocking-operation"
                ):
                    raise ScenarioCodecError(
                        error.category,
                        "controller operation depends on unjoined worker progress: "
                        f"{error.detail}",
                    ) from None
                raise
        self.simple.apply(operation)
        if description is not None:
            if (
                isinstance(operation, Close)
                and descriptor is not None
                and not any(
                    candidate.description_id == descriptor.description_id
                    for candidate in self.simple.descriptors.values()
                )
            ):
                self._drop_epoll_description(descriptor.description_id)
            self._refresh_epolls(description.event_id)

    def _synchronize_controller_state_if_idle(self) -> None:
        if self.enforce_controller_progress and not self.workers.active_actors:
            self.controller_simple = copy.deepcopy(self.simple)

    def _epoll_create(self, operation: EpollCreate) -> None:
        if operation.slot in self.epolls or self.simple.descriptor(operation.slot):
            raise ScenarioCodecError(
                "resource-state", f"epoll destination slot {operation.slot} is live"
            )
        self.epolls[operation.slot] = EpollState(operation.flags, {})

    def _epoll_ctl(self, operation: EpollCtl) -> None:
        epoll = self.epolls.get(operation.epoll_slot)
        description = self.simple.description(operation.target_slot)
        event = self.simple.event(operation.target_slot)
        if epoll is None or description is None or event is None:
            raise ScenarioCodecError("resource-state", "epoll ctl slot is not live")
        existing = epoll.registrations.get(operation.target_slot)
        if operation.action is EpollCtlAction.ADD:
            if existing is not None:
                raise ScenarioCodecError("resource-state", "duplicate epoll ADD")
            ready = self._event_ready(event.count, operation.events)
            epoll.registrations[operation.target_slot] = EpollRegistration(
                operation.target_slot,
                description.event_id,
                self.simple.descriptor(operation.target_slot).description_id,
                operation.events,
                operation.data,
                True,
                ready,
                ready and bool(operation.events & EPOLLET),
            )
        elif operation.action is EpollCtlAction.MOD:
            if existing is None:
                raise ScenarioCodecError("resource-state", "epoll MOD is not registered")
            ready = self._event_ready(event.count, operation.events)
            existing.events = operation.events
            existing.data = operation.data
            existing.enabled = True
            existing.last_ready = ready
            existing.edge_pending = ready and bool(operation.events & EPOLLET)
        else:
            if existing is None:
                raise ScenarioCodecError("resource-state", "epoll DEL is not registered")
            del epoll.registrations[operation.target_slot]

    def _drop_epoll_description(self, description_id: int) -> None:
        for epoll in self.epolls.values():
            epoll.registrations = {
                slot: registration
                for slot, registration in epoll.registrations.items()
                if registration.description_id != description_id
            }

    def _refresh_epolls(self, event_id: int) -> None:
        exclusive = []
        for epoll_slot, epoll in self.epolls.items():
            for registration in epoll.registrations.values():
                if registration.event_id != event_id:
                    continue
                event = self.simple.events[event_id]
                ready = self._event_ready(event.count, registration.events)
                transitioned = not registration.last_ready and ready
                registration.last_ready = ready
                if transitioned and registration.events & EPOLLEXCLUSIVE:
                    exclusive.append((epoll_slot, registration))
                elif transitioned and registration.events & EPOLLET:
                    registration.edge_pending = True
        if exclusive:
            exclusive.sort(key=lambda item: item[0])
            cursor = self.exclusive_cursor.get(event_id, 0) % len(exclusive)
            exclusive[cursor][1].edge_pending = True
            self.exclusive_cursor[event_id] = cursor + 1

    def _epoll_worker_watches(self, worker, event_id: int) -> bool:
        if worker.resource[0] != "epoll":
            return False
        epoll = self.epolls[worker.resource[1]]
        return any(
            registration.event_id == event_id
            for registration in epoll.registrations.values()
        )

    def _epoll_has_ready(self, epoll: EpollState) -> bool:
        return any(self._registration_ready(registration) for registration in epoll.registrations.values())

    def _epoll_ready(self, epoll: EpollState, maxevents: int) -> bool:
        ready = [
            registration
            for registration in epoll.registrations.values()
            if self._registration_ready(registration)
        ][:maxevents]
        if not ready:
            return False
        for registration in ready:
            if registration.events & (EPOLLET | EPOLLEXCLUSIVE):
                registration.edge_pending = False
            if registration.events & EPOLLONESHOT:
                registration.enabled = False
        return True

    def _registration_ready(self, registration: EpollRegistration) -> bool:
        if not registration.enabled:
            return False
        if registration.events & (EPOLLET | EPOLLEXCLUSIVE):
            return registration.edge_pending
        event = self.simple.events[registration.event_id]
        return self._event_ready(event.count, registration.events)

    @staticmethod
    def _event_ready(count: int, events: int) -> bool:
        return bool(
            events & EPOLLIN and count > 0
            or events & EPOLLOUT and count < MAX_COUNTER
        )

    def _deliver_pending_signals(self, actor: int) -> None:
        pending = self.pending_signal_counts[actor]
        if pending:
            self.signal_counts[actor] += pending
            self.pending_signal_counts[actor] = 0

    @staticmethod
    def _transition(transition):
        try:
            return transition()
        except controlled_actor.WorkerLifecycleError as error:
            category = (
                "actor-lifecycle"
                if error.kind is controlled_actor.WorkerLifecycleErrorKind.LIFECYCLE
                else "blocking-proof"
            )
            raise ScenarioCodecError(category, error.detail) from None


def parse_document(encoded: Union[bytes, str]) -> ScenarioDocument:
    text = _decode_document(encoded)
    version: Optional[int] = None
    scenarios = []
    operations = []
    saw_scenario = False
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if len(raw_line.encode("utf-8")) >= 256:
            raise ScenarioCodecError("line-limit", "line is too long", line_number)
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = tuple(re.split(r"[ \t]+", line))
        if fields[0] == "version":
            if version is not None or saw_scenario or len(fields) != 2:
                raise ScenarioCodecError("version", "invalid version declaration", line_number)
            version = simple._parse_integer(fields[1], CORPUS_VERSION, CORPUS_VERSION, line_number)
            continue
        if fields[0] == "scenario":
            if version is None or len(fields) != 2 or not fields[1]:
                raise ScenarioCodecError("scenario", "invalid scenario declaration", line_number)
            if saw_scenario:
                if not operations:
                    raise ScenarioCodecError("scenario", "scenario has no operations", line_number)
                scenarios.append(Scenario(operations))
                operations = []
            saw_scenario = True
            continue
        if not saw_scenario:
            raise ScenarioCodecError(
                "scenario", "operation appears before first scenario", line_number
            )
        operations.append(_parse_operation(fields, line_number))
    if version is None or not saw_scenario or not operations:
        raise ScenarioCodecError("document", "operation corpus is incomplete")
    scenarios.append(Scenario(operations))
    document = ScenarioDocument(scenarios, version=CORPUS_VERSION)
    validate_document(document)
    return document


def serialize_document(document: ScenarioDocument) -> str:
    validate_document(document)
    return _serialize_without_validation(document)


def combine_documents(documents: Iterable[ScenarioDocument]) -> ScenarioDocument:
    document = ScenarioDocument(
        (scenario for source in documents for scenario in source.scenarios),
        version=CORPUS_VERSION,
    )
    validate_document(document)
    return document


def canonical_digest(document: ScenarioDocument) -> str:
    return hashlib.sha256(serialize_document(document).encode("utf-8")).hexdigest()


def validate_document(document: ScenarioDocument) -> None:
    if document.version != CORPUS_VERSION:
        raise ScenarioCodecError("version", f"unsupported version {document.version}")
    if not document.scenarios:
        raise ScenarioCodecError("entry-limit", "invalid scenario count")
    for scenario_index, scenario in enumerate(document.scenarios):
        if not scenario.operations or len(scenario.operations) > MAX_OPS_PER_SCENARIO:
            raise ScenarioCodecError(
                "entry-limit", f"invalid operation count in scenario {scenario_index}"
            )
        state = ResourceState()
        for operation in scenario.operations:
            _validate_operation_fields(operation)
            state.apply(operation)
        state.finish_scenario()


def validate_entry_limits(document: ScenarioDocument) -> None:
    validate_document(document)
    if len(document.scenarios) > MAX_SCENARIOS_PER_ENTRY:
        raise ScenarioCodecError("entry-limit", "too many scenarios")
    if len(_serialize_without_validation(document).encode("utf-8")) > MAX_ENTRY_BYTES:
        raise ScenarioCodecError("entry-limit", "canonical document is too large")


def analyze_scenario(source_scenario: Scenario) -> ResourceState:
    state = ResourceState()
    for operation in source_scenario.operations:
        _validate_operation_fields(operation)
        state.apply(operation)
    state.finish_scenario()
    return state


def validate_schedulable_scenario(source_scenario: Scenario) -> ResourceState:
    """Reject controller calls whose progress depends on an unjoined worker."""
    state = ResourceState(enforce_controller_progress=True)
    for operation in source_scenario.operations:
        _validate_operation_fields(operation)
        state.apply(operation)
    state.finish_scenario()
    return state


def validate_schedulable_document(document: ScenarioDocument) -> None:
    """Apply generator-only scheduling proofs without changing the v4 codec."""
    validate_entry_limits(document)
    for source_scenario in document.scenarios:
        validate_schedulable_scenario(source_scenario)


def deterministic_scenario_indexes(document: ScenarioDocument) -> Tuple[int, ...]:
    """Return scenarios that never have more than one active worker."""
    validate_document(document)
    return tuple(
        index
        for index, source_scenario in enumerate(document.scenarios)
        if analyze_scenario(source_scenario).peak_active_workers <= 1
    )


def operation_name(operation: Operation) -> str:
    if isinstance(operation, StartRead):
        return "start-read"
    if isinstance(operation, StartWrite):
        return "start-write"
    if isinstance(operation, StartPoll):
        return "start-poll"
    if isinstance(operation, StartPpoll):
        return "start-ppoll"
    if isinstance(operation, SignalConfig):
        return "signal-config"
    if isinstance(operation, SendSignal):
        return "send-signal"
    if isinstance(operation, AssertSignalHandled):
        return "assert-signal-handled"
    if isinstance(operation, EpollCreate):
        return "epoll-create"
    if isinstance(operation, EpollCtl):
        return "epoll-ctl"
    if isinstance(operation, StartEpollWait):
        return "start-epoll-wait"
    if isinstance(operation, StartEpollPwait):
        return "start-epoll-pwait"
    if isinstance(operation, StartEpollPwait2):
        return "start-epoll-pwait2"
    if isinstance(operation, AssertPending):
        return "assert-pending"
    if isinstance(operation, AssertAllPending):
        return "assert-all-pending"
    if isinstance(operation, Join):
        return "join"
    if isinstance(operation, JoinSet):
        return "join-set"
    return simple.operation_name(operation)


def _decode_document(encoded: Union[bytes, str]) -> str:
    if isinstance(encoded, bytes):
        try:
            text = encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ScenarioCodecError("encoding", "document is not UTF-8") from error
    else:
        text = encoded
    if "\x00" in text:
        raise ScenarioCodecError("encoding", "document contains NUL")
    return text


def _parse_operation(fields: Tuple[str, ...], line_number: int) -> Operation:
    name = fields[0]
    values = fields[1:]
    if name == "start-read" and len(values) == 3:
        return StartRead(
            _actor(values[0], line_number),
            simple._slot(values[1], line_number),
            simple._parse_integer(values[2], 8, 8, line_number),
        )
    if name == "start-write" and len(values) == 3:
        return StartWrite(
            _actor(values[0], line_number),
            simple._slot(values[1], line_number),
            simple._parse_integer(values[2], 0, MAX_U64, line_number),
        )
    if name == "start-poll" and len(values) == 4:
        events = simple._integer_from_values(values[2], POLL_EVENTS, line_number)
        return StartPoll(
            _actor(values[0], line_number),
            simple._slot(values[1], line_number),
            events,
            simple._integer_from_values(values[3], TIMEOUT_VALUES, line_number),
        )
    if name == "start-ppoll" and len(values) == 5:
        events = simple._integer_from_values(values[2], POLL_EVENTS, line_number)
        timeout_ns = (
            None
            if values[3] == "null"
            else simple._parse_integer(values[3], 0, MAX_TIMEOUT_NS, line_number)
        )
        try:
            sigmask = SignalMask(values[4])
        except ValueError:
            raise ScenarioCodecError(
                "operation", "invalid ppoll signal mask", line_number
            ) from None
        return StartPpoll(
            _actor(values[0], line_number),
            simple._slot(values[1], line_number),
            events,
            timeout_ns,
            sigmask,
        )
    if name == "signal-config" and len(values) == 2:
        return SignalConfig(
            simple._parse_integer(values[0], SIGUSR1, SIGUSR1, line_number),
            simple._integer_from_values(values[1], SIGNAL_FLAGS, line_number),
        )
    if name == "send-signal" and len(values) == 2:
        return SendSignal(
            _actor(values[0], line_number),
            simple._parse_integer(values[1], SIGUSR1, SIGUSR1, line_number),
        )
    if name == "assert-signal-handled" and len(values) == 2:
        return AssertSignalHandled(
            _actor(values[0], line_number),
            simple._parse_integer(values[1], 0, MAX_OPS_PER_SCENARIO, line_number),
        )
    if name == "epoll-create" and len(values) == 2:
        return EpollCreate(
            simple._slot(values[0], line_number),
            simple._integer_from_values(values[1], (0, EPOLL_CLOEXEC), line_number),
        )
    if name == "epoll-ctl" and len(values) == 5:
        try:
            action = EpollCtlAction(values[1])
        except ValueError:
            raise ScenarioCodecError(
                "operation", "invalid epoll ctl action", line_number
            ) from None
        events = simple._parse_integer(values[3], 0, EPOLL_ALLOWED_BITS, line_number)
        data = simple._parse_integer(values[4], 0, MAX_U64, line_number)
        _validate_epoll_ctl_fields(action, events, data, line_number)
        return EpollCtl(
            simple._slot(values[0], line_number),
            action,
            simple._slot(values[2], line_number),
            events,
            data,
        )
    if name in ("start-epoll-wait", "start-epoll-pwait") and len(values) in (4, 5):
        if (name == "start-epoll-wait") != (len(values) == 4):
            return simple._parse_operation(fields, line_number)
        timeout_ms = simple._integer_from_values(values[3], TIMEOUT_VALUES, line_number)
        actor = _actor(values[0], line_number)
        epoll_slot = simple._slot(values[1], line_number)
        maxevents = simple._parse_integer(values[2], 1, 4, line_number)
        if name == "start-epoll-wait":
            return StartEpollWait(actor, epoll_slot, maxevents, timeout_ms)
        try:
            sigmask = SignalMask(values[4])
        except ValueError:
            raise ScenarioCodecError(
                "operation", "invalid epoll signal mask", line_number
            ) from None
        return StartEpollPwait(
            actor, epoll_slot, maxevents, timeout_ms, sigmask
        )
    if name == "start-epoll-pwait2" and len(values) == 5:
        timeout_ns = (
            None
            if values[3] == "null"
            else simple._parse_integer(values[3], 0, MAX_TIMEOUT_NS, line_number)
        )
        try:
            sigmask = SignalMask(values[4])
        except ValueError:
            raise ScenarioCodecError(
                "operation", "invalid epoll signal mask", line_number
            ) from None
        return StartEpollPwait2(
            _actor(values[0], line_number),
            simple._slot(values[1], line_number),
            simple._parse_integer(values[2], 1, 4, line_number),
            timeout_ns,
            sigmask,
        )
    if name in ("assert-pending", "join") and len(values) == 1:
        operation_type = AssertPending if name == "assert-pending" else Join
        return operation_type(_actor(values[0], line_number))
    if name == "assert-all-pending" and not values:
        return AssertAllPending()
    if name == "join-set" and values == ("1", "2"):
        return JoinSet((1, 2))
    return simple._parse_operation(fields, line_number)


def _validate_operation_fields(operation: Operation) -> None:
    fields = tuple(_serialize_operation(operation).split())
    try:
        _parse_operation(fields, 0)
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, ScenarioCodecError):
            raise
        raise ScenarioCodecError("operation", f"invalid {type(operation).__name__}") from error


def _serialize_operation(operation: Operation) -> str:
    if isinstance(operation, StartRead):
        return f"start-read {operation.actor} {operation.slot} {operation.length}"
    if isinstance(operation, StartWrite):
        return f"start-write {operation.actor} {operation.slot} {operation.value}"
    if isinstance(operation, StartPoll):
        return (
            f"start-poll {operation.actor} {operation.slot} "
            f"{operation.events} {operation.timeout_ms}"
        )
    if isinstance(operation, StartPpoll):
        timeout = "null" if operation.timeout_ns is None else operation.timeout_ns
        return (
            f"start-ppoll {operation.actor} {operation.slot} "
            f"{operation.events} {timeout} {operation.sigmask.value}"
        )
    if isinstance(operation, SignalConfig):
        return f"signal-config {operation.signo} {operation.flags}"
    if isinstance(operation, SendSignal):
        return f"send-signal {operation.actor} {operation.signo}"
    if isinstance(operation, AssertSignalHandled):
        return f"assert-signal-handled {operation.actor} {operation.count}"
    if isinstance(operation, EpollCreate):
        return f"epoll-create {operation.slot} {operation.flags}"
    if isinstance(operation, EpollCtl):
        return (
            f"epoll-ctl {operation.epoll_slot} {operation.action.value} "
            f"{operation.target_slot} {operation.events} {operation.data}"
        )
    if isinstance(operation, (StartEpollWait, StartEpollPwait)):
        encoded = (
            f"{operation_name(operation)} {operation.actor} "
            f"{operation.epoll_slot} {operation.maxevents} {operation.timeout_ms}"
        )
        return (
            encoded
            if isinstance(operation, StartEpollWait)
            else f"{encoded} {operation.sigmask.value}"
        )
    if isinstance(operation, StartEpollPwait2):
        timeout = "null" if operation.timeout_ns is None else operation.timeout_ns
        return (
            f"start-epoll-pwait2 {operation.actor} {operation.epoll_slot} "
            f"{operation.maxevents} {timeout} {operation.sigmask.value}"
        )
    if isinstance(operation, (AssertPending, Join)):
        return f"{operation_name(operation)} {operation.actor}"
    if isinstance(operation, AssertAllPending):
        return "assert-all-pending"
    if isinstance(operation, JoinSet):
        return "join-set " + " ".join(str(actor) for actor in operation.actors)
    return simple._serialize_operation(operation)


def _serialize_without_validation(document: ScenarioDocument) -> str:
    lines = [f"version {CORPUS_VERSION}"]
    for index, scenario in enumerate(document.scenarios, start=1):
        lines.append(f"scenario generated-{index:04d}")
        lines.extend(_serialize_operation(operation) for operation in scenario.operations)
    return "\n".join(lines) + "\n"


def _actor(text: str, line_number: int) -> int:
    return simple._integer_from_values(text, controlled_actor.WORKER_ACTORS, line_number)


def _validate_epoll_ctl_fields(
    action: EpollCtlAction, events: int, data: int, line_number: int
) -> None:
    if events & ~EPOLL_ALLOWED_BITS:
        raise ScenarioCodecError("operation", "invalid epoll events", line_number)
    if action is EpollCtlAction.DEL:
        if events != 0 or data != 0:
            raise ScenarioCodecError(
                "operation", "epoll DEL requires canonical zero events/data", line_number
            )
        return
    if events & EPOLL_READY_BITS == 0:
        raise ScenarioCodecError("operation", "epoll interest is empty", line_number)
    if events & EPOLLEXCLUSIVE and (
        action is not EpollCtlAction.ADD or events & EPOLLONESHOT
    ):
        raise ScenarioCodecError(
            "operation", "invalid EPOLLEXCLUSIVE combination", line_number
        )


__all__ = [name for name in globals() if not name.startswith("_")]
