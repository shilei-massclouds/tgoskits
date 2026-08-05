"""Controlled two-worker eventfd scenario IR and canonical v4 codec."""

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
    AssertPending,
    AssertAllPending,
    Join,
    JoinSet,
]
Operation = Union[simple.Operation, ConcurrentOperation]


class ResourceState:
    """Validate blocking proofs while allowing Linux to choose each winner."""

    def __init__(self) -> None:
        self.simple = simple.ResourceState()
        self.workers = controlled_actor.ControlledWorkers[ConcurrentOperation, int]()
        self._next_completion_ordinal = 1
        self.signal_flags: Optional[int] = None
        self.signal_counts = {actor: 0 for actor in controlled_actor.WORKER_ACTORS}
        self.pending_signal_counts = {
            actor: 0 for actor in controlled_actor.WORKER_ACTORS
        }

    def apply(self, operation: Operation) -> None:
        if isinstance(operation, (StartRead, StartWrite, StartPoll, StartPpoll)):
            self._start(operation)
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
        elif isinstance(operation, JoinSet):
            for actor in operation.actors:
                self._complete_timeout(actor)
            self._transition(
                lambda: self.workers.join_set(operation.actors, lambda _calls: None)
            )
        elif self.workers.active_actors:
            self._apply_trigger(operation)
        else:
            self.simple.apply(operation)

    def finish_scenario(self) -> None:
        self._transition(self.workers.finish_scenario)

    def descriptor(self, slot: int):
        return self.simple.descriptor(slot)

    def description(self, slot: int):
        return self.simple.description(slot)

    def event(self, slot: int):
        return self.simple.event(slot)

    def _start(
        self, operation: Union[StartRead, StartWrite, StartPoll, StartPpoll]
    ) -> None:
        def identify_event() -> int:
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
            return description.event_id

        self._transition(
            lambda: self.workers.start(operation.actor, operation, identify_event)
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
            isinstance(worker.operation, StartPpoll)
            and worker.operation.sigmask is SignalMask.USR1
        ):
            self.pending_signal_counts[operation.actor] += 1
            return
        self.signal_counts[operation.actor] += 1
        interrupted = isinstance(worker.operation, (StartPoll, StartPpoll)) or self.signal_flags == 0
        if interrupted:
            self._mark_completed(operation.actor)

    def _complete_timeout(self, actor: int) -> None:
        worker = self.workers.worker(actor)
        if (
            worker is None
            or worker.completed
            or not isinstance(worker.operation, (StartPoll, StartPpoll))
            or (
                isinstance(worker.operation, StartPoll)
                and worker.operation.timeout_ms < 0
            )
            or (
                isinstance(worker.operation, StartPpoll)
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

    def _apply_trigger(self, operation: simple.Operation) -> None:
        if not isinstance(operation, (Read, Write)):
            raise ScenarioCodecError(
                "actor-lifecycle", "only eventfd read/write may trigger active workers"
            )
        description = self.simple.description(operation.slot)
        if description is None:
            raise ScenarioCodecError(
                "blocking-proof", f"trigger slot {operation.slot} is not live"
            )
        selected = tuple(
            actor
            for actor in self.workers.active_actors
            if not self.workers.worker(actor).completed
            and self.workers.worker(actor).resource == description.event_id
        )
        if not selected:
            raise ScenarioCodecError(
                "actor-lifecycle", "trigger does not target an incomplete worker resource"
            )
        self._transition(lambda: self.workers.before_trigger(selected))
        self.simple.apply(operation)
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
                ordinal = self._next_completion_ordinal
                self._next_completion_ordinal += 1
                self._transition(
                    lambda actor=actor, ordinal=ordinal: self.workers.mark_completed(
                        actor, ordinal
                    )
                )
                made_progress = True

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


__all__ = [name for name in globals() if not name.startswith("_")]
