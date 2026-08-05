"""Controlled two-worker pipe scenario IR and canonical v7 codec."""

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional, Tuple, Union

import blocking_scenario as blocking
import scenario as simple
from linux_oracle import actor as controlled_actor


CORPUS_VERSION = 7
MAX_OPS_PER_SCENARIO = 64
MAX_SCENARIOS_PER_ENTRY = 8
MAX_ENTRY_BYTES = 16384
PIPE_BUF = blocking.PIPE_BUF
PIPE_BUFFER_BYTES = blocking.PIPE_BUFFER_BYTES
MAX_IO_BYTES = blocking.MAX_IO_BYTES
POLLIN = 1
POLLOUT = 4
POLLHUP = 16
POLL_EVENTS = (POLLIN, POLLOUT)
SIGUSR1 = 10
SA_RESTART = 268435456
SIGNAL_FLAGS = (0, SA_RESTART)
MAX_TIMEOUT_NS = 1_000_000_000

Scenario = blocking.Scenario
ScenarioDocument = blocking.ScenarioDocument
ScenarioCodecError = blocking.ScenarioCodecError
ScenarioEntryLimitError = blocking.ScenarioEntryLimitError
CodecErrorCategory = blocking.CodecErrorCategory
Pipe2 = blocking.Pipe2
Read = blocking.Read
Write = blocking.Write
Dup = blocking.Dup
Close = blocking.Close
GetStatusFlags = blocking.GetStatusFlags
SetStatusFlags = blocking.SetStatusFlags
GetFdFlags = blocking.GetFdFlags
SetFdFlags = blocking.SetFdFlags
SetSize = blocking.SetSize
GetSize = blocking.GetSize
Fionread = blocking.Fionread
O_NONBLOCK = blocking.O_NONBLOCK
O_CLOEXEC = blocking.O_CLOEXEC
FD_CLOEXEC = blocking.FD_CLOEXEC


@dataclass(frozen=True)
class StartRead:
    actor: int
    slot: int
    length: int


@dataclass(frozen=True)
class StartWrite:
    actor: int
    slot: int
    length: int


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


class ResourceState(blocking.ResourceState):
    """Track record slots while leaving the first completion order open."""

    def __init__(self) -> None:
        super().__init__()
        self.workers = controlled_actor.ControlledWorkers[ConcurrentOperation, int]()
        self._next_completion_ordinal = 1
        self.signal_flags: Optional[int] = None
        self.signal_counts = {actor: 0 for actor in controlled_actor.WORKER_ACTORS}
        self.pending_signal_counts = {
            actor: 0 for actor in controlled_actor.WORKER_ACTORS
        }
        self.worker_write_progress = {
            actor: 0 for actor in controlled_actor.WORKER_ACTORS
        }

    def apply(self, operation: Operation, line_number: int = 0) -> None:
        if isinstance(operation, (StartRead, StartWrite, StartPoll, StartPpoll)):
            self._start(operation, line_number)
        elif isinstance(operation, SignalConfig):
            if self.workers.active_actors:
                blocking._raise(
                    line_number,
                    CodecErrorCategory.RESOURCE_CONFLICT,
                    "signal-config requires idle workers",
                )
            self.signal_flags = operation.flags
        elif isinstance(operation, SendSignal):
            self._send_signal(operation, line_number)
        elif isinstance(operation, AssertSignalHandled):
            if self.signal_counts[operation.actor] != operation.count:
                blocking._raise(
                    line_number,
                    CodecErrorCategory.BLOCKING_IO,
                    "unexpected signal handler count",
                )
        elif isinstance(operation, AssertPending):
            self._transition(
                line_number, lambda: self.workers.assert_pending(operation.actor)
            )
        elif isinstance(operation, AssertAllPending):
            self._transition(line_number, self.workers.assert_all_pending)
        elif isinstance(operation, Join):
            self._complete_timeout(operation.actor, line_number)
            self._transition(
                line_number,
                lambda: self.workers.join(operation.actor, lambda _worker: None),
            )
        elif isinstance(operation, JoinSet):
            for actor in operation.actors:
                self._complete_timeout(actor, line_number)
            self._transition(
                line_number,
                lambda: self.workers.join_set(operation.actors, lambda _workers: None),
            )
        elif self.workers.active_actors:
            self._apply_trigger(operation, line_number)
        else:
            self._apply_synchronous(operation, line_number)

    def finish_scenario(self, line_number: int = 0) -> None:
        self._transition(line_number, self.workers.finish_scenario)

    def _start(
        self,
        operation: Union[StartRead, StartWrite, StartPoll, StartPpoll],
        line_number: int,
    ) -> None:
        def identify_pipe() -> int:
            endpoint = (
                "reader"
                if isinstance(operation, StartRead)
                or isinstance(operation, (StartPoll, StartPpoll))
                and operation.events == POLLIN
                else "writer"
            )
            resource = self._require_endpoint(operation.slot, endpoint, line_number)
            description = self.descriptions[resource.description_id]
            pipe = self.pipes[resource.pipe_id]
            if isinstance(operation, StartRead):
                invalid = (
                    description.nonblocking
                    or operation.length <= 0
                    or pipe.queued_bytes != 0
                    or pipe.writers == 0
                )
            elif isinstance(operation, StartWrite):
                invalid = (
                    description.nonblocking
                    or operation.length <= 0
                    or operation.length > MAX_IO_BYTES
                    or pipe.readers == 0
                    or (
                        operation.length <= PIPE_BUF
                        and pipe.can_write_record(operation.length)
                    )
                    or pipe.available_buffer_slots != 0
                )
            else:
                initially_ready = (
                    pipe.queued_bytes != 0 or pipe.writers == 0
                    if operation.events == POLLIN
                    else pipe.available_buffer_slots > 0 or pipe.readers == 0
                )
                timeout_too_short = (
                    0 <= operation.timeout_ms < 100
                    if isinstance(operation, StartPoll)
                    else operation.timeout_ns is not None
                    and operation.timeout_ns < 100_000_000
                )
                invalid = timeout_too_short or initially_ready
            if invalid:
                blocking._raise(
                    line_number,
                    CodecErrorCategory.BLOCKING_IO,
                    "worker operation must initially block",
                )
            return resource.pipe_id

        self._transition(
            line_number,
            lambda: self.workers.start(
                operation.actor, operation, identify_pipe
            ),
        )
        self.worker_write_progress[operation.actor] = 0

    def _send_signal(self, operation: SendSignal, line_number: int) -> None:
        if self.signal_flags is None:
            blocking._raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "send-signal requires signal-config",
            )
        worker = self.workers.worker(operation.actor)
        if worker is None:
            blocking._raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "send-signal requires an active worker",
            )
        self._transition(
            line_number,
            lambda: self.workers.before_trigger((operation.actor,)),
        )
        if (
            isinstance(worker.operation, StartPpoll)
            and worker.operation.sigmask is SignalMask.USR1
        ):
            self.pending_signal_counts[operation.actor] += 1
            return
        self.signal_counts[operation.actor] += 1
        interrupted = (
            isinstance(worker.operation, (StartPoll, StartPpoll))
            or self.signal_flags == 0
            or isinstance(worker.operation, StartWrite)
            and self.worker_write_progress[operation.actor] > 0
        )
        if interrupted:
            self._mark_completed(operation.actor, line_number)

    def _complete_timeout(self, actor: int, line_number: int) -> None:
        worker = self.workers.worker(actor)
        if worker is None or worker.completed:
            return
        operation = worker.operation
        finite = (
            isinstance(operation, StartPoll) and operation.timeout_ms >= 0
        ) or (
            isinstance(operation, StartPpoll) and operation.timeout_ns is not None
        )
        if finite:
            self._mark_completed(actor, line_number)

    def _mark_completed(self, actor: int, line_number: int) -> None:
        self._deliver_pending_signals(actor)
        self._transition(
            line_number,
            lambda: self.workers.update_completable(actor, True),
        )
        ordinal = self._next_completion_ordinal
        self._next_completion_ordinal += 1
        self._transition(
            line_number,
            lambda: self.workers.mark_completed(actor, ordinal),
        )

    def _deliver_pending_signals(self, actor: int) -> None:
        pending = self.pending_signal_counts[actor]
        if pending:
            self.signal_counts[actor] += pending
            self.pending_signal_counts[actor] = 0

    def _apply_trigger(self, operation: simple.Operation, line_number: int) -> None:
        if not isinstance(operation, (Read, Write, Close)):
            blocking._raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "active workers allow only same-pipe read/write/close triggers",
            )
        slot = operation.slot
        resource = self._require_live(slot, line_number)
        selected = tuple(
            actor
            for actor in self.workers.active_actors
            if not self.workers.worker(actor).completed
            and self.workers.worker(actor).resource == resource.pipe_id
        )
        if not selected:
            blocking._raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "trigger does not target an incomplete worker pipe",
            )
        self._transition(
            line_number, lambda: self.workers.before_trigger(selected)
        )
        self._apply_synchronous(operation, line_number)
        self._complete_ready_workers(line_number)

    def _complete_ready_workers(self, line_number: int) -> None:
        made_progress = True
        while made_progress:
            made_progress = False
            for actor in self.workers.active_actors:
                worker = self.workers.worker(actor)
                if worker.completed:
                    continue
                operation = worker.operation
                resource = self._require_live(operation.slot, line_number)
                pipe = self.pipes[worker.resource]
                ready = False
                if isinstance(operation, StartRead):
                    ready = pipe.queued_bytes != 0 or pipe.writers == 0
                    if ready and pipe.queued_bytes:
                        pipe.read_bytes(operation.length)
                elif isinstance(operation, StartWrite):
                    if pipe.readers == 0:
                        ready = True
                    elif operation.length <= PIPE_BUF:
                        ready = pipe.can_write_record(operation.length)
                        if ready:
                            pipe.write_record(operation.length, 64 + actor)
                    elif pipe.available_buffer_slots > 0:
                        remaining = (
                            operation.length - self.worker_write_progress[actor]
                        )
                        chunk = min(remaining, PIPE_BUF)
                        pipe.write_record(chunk, 64 + actor)
                        self.worker_write_progress[actor] += chunk
                        ready = self.worker_write_progress[actor] == operation.length
                elif operation.events == POLLIN:
                    ready = pipe.queued_bytes != 0 or pipe.writers == 0
                else:
                    ready = pipe.available_buffer_slots > 0 or pipe.readers == 0
                del resource
                if not ready:
                    continue
                self._mark_completed(actor, line_number)
                made_progress = True

    @staticmethod
    def _transition(line_number: int, transition):
        try:
            return transition()
        except controlled_actor.WorkerLifecycleError as error:
            category = (
                CodecErrorCategory.RESOURCE_CONFLICT
                if error.kind is controlled_actor.WorkerLifecycleErrorKind.LIFECYCLE
                else CodecErrorCategory.BLOCKING_IO
            )
            blocking._raise(line_number, category, error.detail)


def parse_document(encoded: Union[str, bytes]) -> ScenarioDocument:
    text = simple._decode_text(encoded)
    scenarios = []
    operations = None
    saw_version = False
    operation_count = 0
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", maxsplit=1)[0].strip()
        if not line:
            continue
        fields = tuple(line.split())
        if fields[0] == "version":
            if saw_version or scenarios or operations is not None or len(fields) != 2:
                blocking._raise(line_number, CodecErrorCategory.INVALID_VERSION, line)
            if simple._parse_integer(fields[1], line_number) != CORPUS_VERSION:
                blocking._raise(line_number, CodecErrorCategory.INVALID_VERSION, line)
            saw_version = True
            continue
        if not saw_version:
            blocking._raise(line_number, CodecErrorCategory.MISSING_VERSION, line)
        if fields[0] == "scenario":
            if len(fields) != 2:
                blocking._raise(line_number, CodecErrorCategory.INVALID_SCENARIO, line)
            if operations is not None:
                scenarios.append(Scenario(operations))
            operations = []
            continue
        if operations is None:
            blocking._raise(
                line_number, CodecErrorCategory.OPERATION_BEFORE_SCENARIO, line
            )
        operations.append(_parse_operation(fields, line_number))
        operation_count += 1
    if operations is not None:
        scenarios.append(Scenario(operations))
    if not saw_version or not scenarios or operation_count == 0:
        blocking._raise(
            max(1, len(text.splitlines())),
            CodecErrorCategory.INCOMPLETE_DOCUMENT,
            "document requires a version, scenario, and operation",
        )
    document = ScenarioDocument(scenarios, version=CORPUS_VERSION)
    validate_document(document)
    return document


def serialize_document(document: ScenarioDocument) -> str:
    validate_document(document)
    text = _serialize_without_validation(document)
    if parse_document(text) != document:
        raise AssertionError("canonical concurrent pipe serialization changed the IR")
    return text


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
        blocking._raise(
            0, CodecErrorCategory.INVALID_VERSION, f"unsupported version {document.version}"
        )
    if not document.scenarios:
        blocking._raise(0, CodecErrorCategory.INCOMPLETE_DOCUMENT, "no scenarios")
    for scenario_index, source_scenario in enumerate(document.scenarios):
        if not source_scenario.operations:
            blocking._raise(
                0,
                CodecErrorCategory.INCOMPLETE_DOCUMENT,
                f"scenario {scenario_index} has no operations",
            )
        state = ResourceState()
        for operation_index, operation in enumerate(source_scenario.operations):
            _validate_operation_fields(operation)
            state.apply(operation, operation_index + 1)
        state.finish_scenario(len(source_scenario.operations) + 1)


def validate_entry_limits(document: ScenarioDocument) -> None:
    validate_document(document)
    if len(document.scenarios) > MAX_SCENARIOS_PER_ENTRY:
        raise ScenarioEntryLimitError(
            simple.EntryLimitCategory.TOO_MANY_SCENARIOS,
            f"{len(document.scenarios)} > {MAX_SCENARIOS_PER_ENTRY}",
        )
    for index, source_scenario in enumerate(document.scenarios, start=1):
        if len(source_scenario.operations) > MAX_OPS_PER_SCENARIO:
            raise ScenarioEntryLimitError(
                simple.EntryLimitCategory.TOO_MANY_OPERATIONS,
                f"scenario {index}: {len(source_scenario.operations)} > {MAX_OPS_PER_SCENARIO}",
            )
    encoded_size = len(_serialize_without_validation(document).encode("utf-8"))
    if encoded_size > MAX_ENTRY_BYTES:
        raise ScenarioEntryLimitError(
            simple.EntryLimitCategory.ENCODING_TOO_LARGE,
            f"{encoded_size} > {MAX_ENTRY_BYTES}",
        )


def analyze_scenario(source_scenario: Scenario) -> ResourceState:
    state = ResourceState()
    for operation_index, operation in enumerate(source_scenario.operations):
        _validate_operation_fields(operation)
        state.apply(operation, operation_index + 1)
    state.finish_scenario(len(source_scenario.operations) + 1)
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


def _parse_operation(fields: Tuple[str, ...], line_number: int) -> Operation:
    keyword = fields[0]
    values = fields[1:]
    if keyword == "start-read" and len(values) == 3:
        return StartRead(
            _actor(values[0], line_number),
            simple._slot(simple._parse_integer(values[1], line_number), line_number),
            simple._range(
                simple._parse_integer(values[2], line_number),
                1,
                MAX_IO_BYTES,
                line_number,
                "worker read length",
            ),
        )
    if keyword == "start-write" and len(values) == 3:
        return StartWrite(
            _actor(values[0], line_number),
            simple._slot(simple._parse_integer(values[1], line_number), line_number),
            simple._range(
                simple._parse_integer(values[2], line_number),
                1,
                MAX_IO_BYTES,
                line_number,
                "worker write length",
            ),
        )
    if keyword == "start-poll" and len(values) == 4:
        events = simple._parse_integer(values[2], line_number)
        timeout_ms = simple._parse_integer(values[3], line_number)
        if events not in POLL_EVENTS or timeout_ms < -1 or timeout_ms > 1000:
            blocking._raise(
                line_number, CodecErrorCategory.OUT_OF_RANGE, "unsupported poll arguments"
            )
        return StartPoll(
            _actor(values[0], line_number),
            simple._slot(simple._parse_integer(values[1], line_number), line_number),
            events,
            timeout_ms,
        )
    if keyword == "start-ppoll" and len(values) == 5:
        events = simple._parse_integer(values[2], line_number)
        if events not in POLL_EVENTS:
            blocking._raise(
                line_number, CodecErrorCategory.OUT_OF_RANGE, "unsupported ppoll events"
            )
        timeout_ns = (
            None
            if values[3] == "null"
            else simple._range(
                simple._parse_integer(values[3], line_number),
                0,
                MAX_TIMEOUT_NS,
                line_number,
                "ppoll timeout",
            )
        )
        try:
            sigmask = SignalMask(values[4])
        except ValueError:
            blocking._raise(
                line_number, CodecErrorCategory.OUT_OF_RANGE, "unsupported ppoll mask"
            )
        return StartPpoll(
            _actor(values[0], line_number),
            simple._slot(simple._parse_integer(values[1], line_number), line_number),
            events,
            timeout_ns,
            sigmask,
        )
    if keyword == "signal-config" and len(values) == 2:
        signo = simple._parse_integer(values[0], line_number)
        flags = simple._parse_integer(values[1], line_number)
        if signo != SIGUSR1 or flags not in SIGNAL_FLAGS:
            blocking._raise(
                line_number, CodecErrorCategory.OUT_OF_RANGE, "unsupported signal config"
            )
        return SignalConfig(signo, flags)
    if keyword == "send-signal" and len(values) == 2:
        signo = simple._parse_integer(values[1], line_number)
        if signo != SIGUSR1:
            blocking._raise(
                line_number, CodecErrorCategory.OUT_OF_RANGE, "unsupported signal"
            )
        return SendSignal(_actor(values[0], line_number), signo)
    if keyword == "assert-signal-handled" and len(values) == 2:
        return AssertSignalHandled(
            _actor(values[0], line_number),
            simple._range(
                simple._parse_integer(values[1], line_number),
                0,
                MAX_OPS_PER_SCENARIO,
                line_number,
                "signal handler count",
            ),
        )
    if keyword in ("assert-pending", "join") and len(values) == 1:
        operation_type = AssertPending if keyword == "assert-pending" else Join
        return operation_type(_actor(values[0], line_number))
    if keyword == "assert-all-pending" and not values:
        return AssertAllPending()
    if keyword == "join-set" and values == ("1", "2"):
        return JoinSet((1, 2))
    return simple._parse_operation(fields, line_number, simple.CORPUS_VERSION)


def _validate_operation_fields(operation: Operation) -> None:
    fields = tuple(_serialize_operation(operation).split())
    if _parse_operation(fields, 0) != operation:
        blocking._raise(
            0,
            CodecErrorCategory.RESOURCE_CONFLICT,
            f"invalid {type(operation).__name__}",
        )


def _serialize_operation(operation: Operation) -> str:
    if isinstance(operation, StartRead):
        return f"start-read {operation.actor} {operation.slot} {operation.length}"
    if isinstance(operation, StartWrite):
        return f"start-write {operation.actor} {operation.slot} {operation.length}"
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
    return simple.format_operation(operation, simple.CORPUS_VERSION)


def _serialize_without_validation(document: ScenarioDocument) -> str:
    lines = [f"version {CORPUS_VERSION}"]
    for index, source_scenario in enumerate(document.scenarios, start=1):
        lines.append(f"scenario generated-{index:04d}")
        lines.extend(_serialize_operation(operation) for operation in source_scenario.operations)
    return "\n".join(lines) + "\n"


def _actor(text: str, line_number: int) -> int:
    actor = simple._parse_integer(text, line_number)
    if actor not in controlled_actor.WORKER_ACTORS:
        blocking._raise(
            line_number, CodecErrorCategory.OUT_OF_RANGE, "worker actor must be 1 or 2"
        )
    return actor


__all__ = [name for name in globals() if not name.startswith("_")]
