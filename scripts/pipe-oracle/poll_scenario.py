"""Controlled pipe poll scenario IR and canonical v6 codec."""

import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Tuple, Union

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

import blocking_scenario as blocking
import scenario as simple
from linux_oracle import actor as controlled_actor


CORPUS_VERSION = 6
CONTROL_ACTOR = controlled_actor.CONTROLLER_ACTOR
WORKER_ACTOR = controlled_actor.WORKER_ACTOR
POLLIN = 1
POLLOUT = 4
POLLHUP = 16
POLL_EVENTS = (POLLIN, POLLOUT)

PIPE_BUF = blocking.PIPE_BUF
PIPE_BUFFER_BYTES = blocking.PIPE_BUFFER_BYTES
MAX_LOGICAL_SLOTS = blocking.MAX_LOGICAL_SLOTS
MAX_IO_BYTES = blocking.MAX_IO_BYTES
MAX_OPS_PER_SCENARIO = blocking.MAX_OPS_PER_SCENARIO
MAX_SCENARIOS_PER_ENTRY = 8
MAX_ENTRY_BYTES = blocking.MAX_ENTRY_BYTES
O_NONBLOCK = blocking.O_NONBLOCK
O_CLOEXEC = blocking.O_CLOEXEC
FD_CLOEXEC = blocking.FD_CLOEXEC

Scenario = blocking.Scenario
ScenarioDocument = blocking.ScenarioDocument
ScenarioCodecError = blocking.ScenarioCodecError
ScenarioEntryLimitError = blocking.ScenarioEntryLimitError
CodecErrorCategory = blocking.CodecErrorCategory

Pipe2 = blocking.Pipe2
Read = blocking.Read
ReadNull = blocking.ReadNull
Write = blocking.Write
WriteNull = blocking.WriteNull
Readv = blocking.Readv
Writev = blocking.Writev
Dup = blocking.Dup
GetStatusFlags = blocking.GetStatusFlags
SetStatusFlags = blocking.SetStatusFlags
GetFdFlags = blocking.GetFdFlags
SetFdFlags = blocking.SetFdFlags
Dup2 = blocking.Dup2
Dup3 = blocking.Dup3
Close = blocking.Close
Poll = blocking.Poll
PollMany = blocking.PollMany
SetSize = blocking.SetSize
GetSize = blocking.GetSize
Fionread = blocking.Fionread
AssertPending = blocking.AssertPending
Join = blocking.Join

FdResource = blocking.FdResource
OpenDescription = blocking.OpenDescription
PipeBuffer = blocking.PipeBuffer
PipeState = blocking.PipeState
WorkerCall = blocking.WorkerCall


@dataclass(frozen=True)
class StartPoll:
    actor: int
    slot: int
    events: int


PollOperation = Union[StartPoll, AssertPending, Join]
Operation = Union[simple.Operation, PollOperation]


class ResourceState(blocking.ResourceState):
    """Prove one pipe poll worker blocks first and can complete before join."""

    def __init__(self) -> None:
        super().__init__()
        self._worker_lifecycle = controlled_actor.SingleWorkerLifecycle[
            StartPoll, int
        ]()

    def apply(self, operation: Operation, line_number: int = 0) -> None:
        if isinstance(operation, StartPoll):
            self._start_poll(operation, line_number)
        elif isinstance(operation, AssertPending):
            self._assert_pending(line_number)
        elif isinstance(operation, Join):
            self._join_poll(line_number)
        elif self.worker is None:
            self._apply_synchronous(operation, line_number)
        else:
            self._apply_poll_trigger(operation, line_number)

    def _start_poll(self, operation: StartPoll, line_number: int) -> None:
        def identify_pipe() -> int:
            endpoint = "reader" if operation.events == POLLIN else "writer"
            resource = self._require_endpoint(operation.slot, endpoint, line_number)
            pipe = self.pipes[resource.pipe_id]
            if operation.events == POLLIN:
                initially_ready = pipe.queued_bytes != 0 or pipe.writers == 0
            else:
                initially_ready = pipe.available_buffer_slots > 0 or pipe.readers == 0
            if initially_ready:
                blocking._raise(
                    line_number,
                    CodecErrorCategory.BLOCKING_IO,
                    "worker poll would be initially ready",
                )
            return resource.pipe_id

        self._apply_worker_transition(
            line_number,
            lambda: self._worker_lifecycle.start(operation, identify_pipe),
        )

    def _apply_poll_trigger(
        self, operation: simple.Operation, line_number: int
    ) -> None:
        worker = self._apply_worker_transition(
            line_number, self._worker_lifecycle.before_trigger
        )
        pipe = self.pipes[worker.resource]
        if worker.operation.events == POLLIN:
            self._trigger_pollin(operation, worker, pipe, line_number)
        else:
            self._trigger_pollout(operation, worker, pipe, line_number)

    def _trigger_pollin(
        self,
        operation: simple.Operation,
        worker: WorkerCall,
        pipe: PipeState,
        line_number: int,
    ) -> None:
        if isinstance(operation, Write):
            self._require_same_pipe_endpoint(
                operation.slot, worker.resource, "writer", line_number
            )
            if operation.length > PIPE_BUF or not pipe.can_write_record(operation.length):
                blocking._raise(
                    line_number,
                    CodecErrorCategory.BLOCKING_IO,
                    "pollin wake write is not immediately completable",
                )
            pipe.write_record(operation.length, operation.byte)
            self._worker_lifecycle.update_completable(pipe.queued_bytes > 0)
            return
        if isinstance(operation, Close):
            self._require_same_pipe_endpoint(
                operation.slot, worker.resource, "writer", line_number
            )
            if pipe.writers != 1 or pipe.queued_bytes != 0:
                blocking._raise(
                    line_number,
                    CodecErrorCategory.RESOURCE_CONFLICT,
                    "only the empty pipe's final writer may close while pollin is pending",
                )
            self._close_slot(operation.slot, line_number)
            self._worker_lifecycle.update_completable(True)
            return
        blocking._raise(
            line_number,
            CodecErrorCategory.RESOURCE_CONFLICT,
            "pending pollin allows only same-pipe write or final-writer close",
        )

    def _trigger_pollout(
        self,
        operation: simple.Operation,
        worker: WorkerCall,
        pipe: PipeState,
        line_number: int,
    ) -> None:
        if not isinstance(operation, Read) or operation.length <= 0:
            blocking._raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "pending pollout allows only a positive same-pipe read",
            )
        self._require_same_pipe_endpoint(
            operation.slot, worker.resource, "reader", line_number
        )
        if pipe.queued_bytes == 0:
            blocking._raise(
                line_number,
                CodecErrorCategory.BLOCKING_IO,
                "pollout wake read has no queued data",
            )
        pipe.read_bytes(operation.length)
        self._worker_lifecycle.update_completable(pipe.available_buffer_slots > 0)

    def _join_poll(self, line_number: int) -> None:
        self._apply_worker_transition(
            line_number, lambda: self._worker_lifecycle.join(lambda _worker: None)
        )


def parse_document(encoded: Union[str, bytes]) -> ScenarioDocument:
    """Parse and validate one strict canonical-compatible v6 document."""
    text = simple._decode_text(encoded)
    scenarios = []
    operations = None
    saw_version = False
    operation_count = 0
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", maxsplit=1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if fields[0] == "version":
            if saw_version or scenarios or operations is not None or len(fields) != 2:
                blocking._raise(line_number, CodecErrorCategory.INVALID_VERSION, line)
            version = simple._parse_integer(fields[1], line_number)
            if version != CORPUS_VERSION:
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
                line_number,
                CodecErrorCategory.OPERATION_BEFORE_SCENARIO,
                line,
            )
        operations.append(_parse_operation(tuple(fields), line_number))
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
        raise AssertionError("canonical poll pipe serialization changed the IR")
    return text


def combine_documents(documents: Iterable[ScenarioDocument]) -> ScenarioDocument:
    document = ScenarioDocument(
        (
            source_scenario
            for source_document in documents
            for source_scenario in source_document.scenarios
        ),
        version=CORPUS_VERSION,
    )
    validate_document(document)
    return document


def canonical_digest(document: ScenarioDocument) -> str:
    return hashlib.sha256(serialize_document(document).encode("utf-8")).hexdigest()


def validate_document(document: ScenarioDocument) -> None:
    if document.version != CORPUS_VERSION:
        blocking._raise(
            0,
            CodecErrorCategory.INVALID_VERSION,
            f"unsupported version {document.version}",
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
    if isinstance(operation, StartPoll):
        return "start-poll"
    if isinstance(operation, AssertPending):
        return "assert-pending"
    if isinstance(operation, Join):
        return "join"
    return simple.operation_name(operation)


def _parse_operation(fields: Tuple[str, ...], line_number: int) -> Operation:
    keyword = fields[0]
    values = fields[1:]
    if keyword == "start-poll":
        if len(values) != 3:
            blocking._raise(
                line_number, CodecErrorCategory.INVALID_ARITY, " ".join(fields)
            )
        events = simple._parse_integer(values[2], line_number)
        if events not in POLL_EVENTS:
            blocking._raise(
                line_number,
                CodecErrorCategory.OUT_OF_RANGE,
                f"unsupported poll events {events}",
            )
        return StartPoll(
            _worker_actor(values[0], line_number),
            simple._slot(simple._parse_integer(values[1], line_number), line_number),
            events,
        )
    if keyword in ("assert-pending", "join"):
        if len(values) != 1:
            blocking._raise(
                line_number, CodecErrorCategory.INVALID_ARITY, " ".join(fields)
            )
        operation_type = AssertPending if keyword == "assert-pending" else Join
        return operation_type(_worker_actor(values[0], line_number))
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
    if isinstance(operation, StartPoll):
        return f"start-poll {operation.actor} {operation.slot} {operation.events}"
    if isinstance(operation, AssertPending):
        return f"assert-pending {operation.actor}"
    if isinstance(operation, Join):
        return f"join {operation.actor}"
    return simple.format_operation(operation, simple.CORPUS_VERSION)


def _serialize_without_validation(document: ScenarioDocument) -> str:
    lines = [f"version {CORPUS_VERSION}"]
    for index, source_scenario in enumerate(document.scenarios, start=1):
        lines.append(f"scenario generated-{index:04d}")
        lines.extend(
            _serialize_operation(operation)
            for operation in source_scenario.operations
        )
    return "\n".join(lines) + "\n"


def _worker_actor(text: str, line_number: int) -> int:
    return simple._range(
        simple._parse_integer(text, line_number),
        WORKER_ACTOR,
        WORKER_ACTOR,
        line_number,
        "worker actor",
    )


__all__ = [name for name in globals() if not name.startswith("_")]
