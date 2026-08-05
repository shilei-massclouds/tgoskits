"""Controlled two-actor pipe scenario IR and canonical v5 codec."""

import hashlib
from dataclasses import dataclass, field, replace
from typing import Dict, Iterable, Optional, Tuple, Union

import scenario as simple


CORPUS_VERSION = 5
CONTROL_ACTOR = 0
WORKER_ACTOR = 1
PIPE_BUF = 4096
PIPE_BUFFER_BYTES = 4096
DEFAULT_PIPE_CAPACITY = 65536

MAX_LOGICAL_SLOTS = simple.MAX_LOGICAL_SLOTS
MAX_IO_BYTES = simple.MAX_IO_BYTES
MAX_OPS_PER_SCENARIO = simple.MAX_OPS_PER_SCENARIO
MAX_SCENARIOS_PER_ENTRY = simple.MAX_SCENARIOS_PER_ENTRY
MAX_ENTRY_BYTES = simple.MAX_ENTRY_BYTES
O_NONBLOCK = simple.O_NONBLOCK
O_CLOEXEC = simple.O_CLOEXEC
FD_CLOEXEC = simple.FD_CLOEXEC

Scenario = simple.Scenario
ScenarioDocument = simple.ScenarioDocument
ScenarioCodecError = simple.ScenarioCodecError
ScenarioEntryLimitError = simple.ScenarioEntryLimitError
CodecErrorCategory = simple.CodecErrorCategory

Pipe2 = simple.Pipe2
Read = simple.Read
ReadNull = simple.ReadNull
Write = simple.Write
WriteNull = simple.WriteNull
Readv = simple.Readv
Writev = simple.Writev
Dup = simple.Dup
GetStatusFlags = simple.GetStatusFlags
SetStatusFlags = simple.SetStatusFlags
GetFdFlags = simple.GetFdFlags
SetFdFlags = simple.SetFdFlags
Dup2 = simple.Dup2
Dup3 = simple.Dup3
Close = simple.Close
Poll = simple.Poll
PollMany = simple.PollMany
SetSize = simple.SetSize
GetSize = simple.GetSize
Fionread = simple.Fionread


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
    byte: int


@dataclass(frozen=True)
class AssertPending:
    actor: int


@dataclass(frozen=True)
class Join:
    actor: int


BlockingOperation = Union[StartRead, StartWrite, AssertPending, Join]
Operation = Union[simple.Operation, BlockingOperation]


@dataclass(frozen=True)
class FdResource:
    endpoint: str
    pipe_id: int
    description_id: int
    close_on_exec: bool


@dataclass
class OpenDescription:
    nonblocking: bool


@dataclass
class PipeBuffer:
    start: int
    end: int

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass
class PipeState:
    capacity: int = DEFAULT_PIPE_CAPACITY
    data: bytearray = field(default_factory=bytearray)
    buffers: list[PipeBuffer] = field(default_factory=list)
    readers: int = 0
    writers: int = 0

    @property
    def queued_bytes(self) -> int:
        return len(self.data)

    @property
    def buffer_slots(self) -> int:
        return self.capacity // PIPE_BUFFER_BYTES

    @property
    def available_buffer_slots(self) -> int:
        return self.buffer_slots - len(self.buffers)

    def tail_can_merge(self, length: int) -> bool:
        return bool(self.buffers) and self.buffers[-1].end + length <= PIPE_BUFFER_BYTES

    def can_write_record(self, length: int) -> bool:
        if length == 0:
            return True
        if length > self.capacity - self.queued_bytes:
            return False
        return self.tail_can_merge(length) or self.available_buffer_slots > 0

    def write_record(self, length: int, byte: int) -> None:
        if not self.can_write_record(length):
            raise AssertionError("pipe record must fit before it is written")
        if length == 0:
            return
        if self.tail_can_merge(length):
            self.buffers[-1].end += length
        else:
            self.buffers.append(PipeBuffer(0, length))
        self.data.extend(bytes((byte,)) * length)

    def read_bytes(self, length: int) -> bytes:
        consumed = min(length, self.queued_bytes)
        result = bytes(self.data[:consumed])
        del self.data[:consumed]
        remaining = consumed
        while remaining:
            front = self.buffers[0]
            if remaining < front.length:
                front.start += remaining
                remaining = 0
            else:
                remaining -= front.length
                del self.buffers[0]
        return result


@dataclass(frozen=True)
class WorkerCall:
    operation: Union[StartRead, StartWrite]
    pipe_id: int
    pending_confirmed: bool = False
    completable: bool = False


class ResourceState:
    """Prove one worker blocks first and can complete before it is joined."""

    def __init__(self) -> None:
        self.slots: list[Optional[FdResource]] = [None] * MAX_LOGICAL_SLOTS
        self.descriptions: Dict[int, OpenDescription] = {}
        self.pipes: Dict[int, PipeState] = {}
        self.next_description_id = 0
        self.next_pipe_id = 0
        self.worker: Optional[WorkerCall] = None

    def apply(self, operation: Operation, line_number: int = 0) -> None:
        if isinstance(operation, (StartRead, StartWrite)):
            self._start_worker(operation, line_number)
        elif isinstance(operation, AssertPending):
            self._assert_pending(line_number)
        elif isinstance(operation, Join):
            self._join_worker(line_number)
        elif self.worker is None:
            self._apply_synchronous(operation, line_number)
        else:
            self._apply_controller_trigger(operation, line_number)

    def finish_scenario(self, line_number: int = 0) -> None:
        if self.worker is not None:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "scenario ends with an unfinished worker",
            )

    def descriptor(self, slot: int) -> Optional[FdResource]:
        return self.slots[slot]

    def description(self, slot: int) -> Optional[OpenDescription]:
        resource = self.descriptor(slot)
        return None if resource is None else self.descriptions[resource.description_id]

    def pipe(self, slot: int) -> Optional[PipeState]:
        resource = self.descriptor(slot)
        return None if resource is None else self.pipes[resource.pipe_id]

    def _apply_synchronous(self, operation: simple.Operation, line_number: int) -> None:
        if isinstance(operation, Pipe2):
            self._create_pipe(operation, line_number)
        elif isinstance(operation, Dup):
            self._duplicate(operation, line_number)
        elif isinstance(operation, SetStatusFlags):
            self._set_status_flags(operation, line_number)
        elif isinstance(operation, SetFdFlags):
            self._set_fd_flags(operation, line_number)
        elif isinstance(operation, Close):
            self._close_slot(operation.slot, line_number)
        elif isinstance(operation, Read):
            self._read_now(operation, line_number)
        elif isinstance(operation, Write):
            self._write_now(operation, line_number)
        elif isinstance(operation, SetSize):
            self._set_size(operation, line_number)
        elif isinstance(operation, (GetStatusFlags, GetFdFlags, GetSize, Fionread)):
            self._require_live(operation.slot, line_number)
        else:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                f"{simple.operation_name(operation)} is outside the blocking model",
            )

    def _create_pipe(self, operation: Pipe2, line_number: int) -> None:
        if operation.flags & ~simple.PIPE2_ALLOWED_FLAGS:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "blocking pipe2 requires supported flags",
            )
        if operation.read_slot == operation.write_slot:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "pipe endpoints use the same slot",
            )
        if self.slots[operation.read_slot] is not None or self.slots[operation.write_slot] is not None:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "pipe destination slot is occupied",
            )
        pipe_id = self.next_pipe_id
        self.next_pipe_id += 1
        pipe = PipeState(readers=1, writers=1)
        self.pipes[pipe_id] = pipe
        self.slots[operation.read_slot] = self._new_descriptor(
            "reader", pipe_id, operation.flags
        )
        self.slots[operation.write_slot] = self._new_descriptor(
            "writer", pipe_id, operation.flags
        )

    def _new_descriptor(self, endpoint: str, pipe_id: int, flags: int) -> FdResource:
        description_id = self.next_description_id
        self.next_description_id += 1
        self.descriptions[description_id] = OpenDescription(
            bool(flags & O_NONBLOCK)
        )
        return FdResource(
            endpoint,
            pipe_id,
            description_id,
            bool(flags & O_CLOEXEC),
        )

    def _duplicate(self, operation: Dup, line_number: int) -> None:
        if operation.source_slot == operation.destination_slot:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "dup source and destination use the same slot",
            )
        source = self._require_live(operation.source_slot, line_number)
        if self.slots[operation.destination_slot] is not None:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "dup destination slot is occupied",
            )
        self.slots[operation.destination_slot] = replace(source, close_on_exec=False)
        pipe = self.pipes[source.pipe_id]
        if source.endpoint == "reader":
            pipe.readers += 1
        else:
            pipe.writers += 1

    def _set_status_flags(self, operation: SetStatusFlags, line_number: int) -> None:
        if operation.flags not in (0, O_NONBLOCK):
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "blocking model supports only O_NONBLOCK status changes",
            )
        resource = self._require_live(operation.slot, line_number)
        self.descriptions[resource.description_id].nonblocking = bool(
            operation.flags & O_NONBLOCK
        )

    def _set_fd_flags(self, operation: SetFdFlags, line_number: int) -> None:
        if operation.flags not in (0, FD_CLOEXEC):
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "blocking model supports only FD_CLOEXEC descriptor changes",
            )
        resource = self._require_live(operation.slot, line_number)
        self.slots[operation.slot] = replace(
            resource, close_on_exec=bool(operation.flags & FD_CLOEXEC)
        )

    def _close_slot(self, slot: int, line_number: int) -> None:
        resource = self._require_live(slot, line_number)
        pipe = self.pipes[resource.pipe_id]
        if resource.endpoint == "reader":
            pipe.readers -= 1
        else:
            pipe.writers -= 1
        self.slots[slot] = None

    def _read_now(self, operation: Read, line_number: int) -> None:
        resource = self._require_endpoint(operation.slot, "reader", line_number)
        pipe = self.pipes[resource.pipe_id]
        if operation.length == 0:
            return
        if pipe.queued_bytes == 0 and pipe.writers > 0:
            _raise(
                line_number,
                CodecErrorCategory.BLOCKING_IO,
                "controller read would block",
            )
        pipe.read_bytes(operation.length)

    def _write_now(self, operation: Write, line_number: int) -> None:
        resource = self._require_endpoint(operation.slot, "writer", line_number)
        pipe = self.pipes[resource.pipe_id]
        if operation.length == 0:
            return
        if pipe.readers == 0 or operation.length > PIPE_BUF or not pipe.can_write_record(operation.length):
            _raise(
                line_number,
                CodecErrorCategory.BLOCKING_IO,
                "controller write is not immediately completable",
            )
        pipe.write_record(operation.length, operation.byte)

    def _set_size(self, operation: SetSize, line_number: int) -> None:
        resource = self._require_live(operation.slot, line_number)
        pipe = self.pipes[resource.pipe_id]
        if operation.size != PIPE_BUFFER_BYTES or pipe.queued_bytes != 0:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "blocking model fixes empty pipe capacity at 4096",
            )
        pipe.capacity = PIPE_BUFFER_BYTES

    def _start_worker(
        self, operation: Union[StartRead, StartWrite], line_number: int
    ) -> None:
        if self.worker is not None:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "only one worker call may be active",
            )
        endpoint = "reader" if isinstance(operation, StartRead) else "writer"
        resource = self._require_endpoint(operation.slot, endpoint, line_number)
        description = self.descriptions[resource.description_id]
        pipe = self.pipes[resource.pipe_id]
        if description.nonblocking:
            _raise(
                line_number,
                CodecErrorCategory.BLOCKING_IO,
                "worker endpoint must not have O_NONBLOCK",
            )
        if isinstance(operation, StartRead):
            if operation.length <= 0 or pipe.queued_bytes != 0 or pipe.writers == 0:
                _raise(
                    line_number,
                    CodecErrorCategory.BLOCKING_IO,
                    "worker read would not block",
                )
        elif (
            operation.length <= 0
            or operation.length > PIPE_BUF
            or pipe.readers == 0
            or pipe.can_write_record(operation.length)
            or pipe.available_buffer_slots != 0
        ):
            _raise(
                line_number,
                CodecErrorCategory.BLOCKING_IO,
                "worker atomic write is not proven to block before committing",
            )
        self.worker = WorkerCall(operation, resource.pipe_id)

    def _assert_pending(self, line_number: int) -> None:
        if self.worker is None:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "assert-pending requires an active worker",
            )
        if self.worker.completable:
            _raise(
                line_number,
                CodecErrorCategory.BLOCKING_IO,
                "worker may complete before assert-pending",
            )
        self.worker = replace(self.worker, pending_confirmed=True)

    def _apply_controller_trigger(
        self, operation: simple.Operation, line_number: int
    ) -> None:
        worker = self.worker
        if worker is None:
            raise AssertionError("active worker is required")
        if worker.completable:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "join must immediately follow a completing trigger",
            )
        if not worker.pending_confirmed:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "worker pending state was not confirmed",
            )
        pipe = self.pipes[worker.pipe_id]
        if isinstance(worker.operation, StartRead):
            self._trigger_read_worker(operation, worker, pipe, line_number)
        else:
            self._trigger_write_worker(operation, worker, pipe, line_number)

    def _trigger_read_worker(
        self,
        operation: simple.Operation,
        worker: WorkerCall,
        pipe: PipeState,
        line_number: int,
    ) -> None:
        if isinstance(operation, Write):
            resource = self._require_same_pipe_endpoint(
                operation.slot, worker.pipe_id, "writer", line_number
            )
            del resource
            if operation.length > PIPE_BUF or not pipe.can_write_record(operation.length):
                _raise(
                    line_number,
                    CodecErrorCategory.BLOCKING_IO,
                    "read wake write is not immediately completable",
                )
            pipe.write_record(operation.length, operation.byte)
            self.worker = replace(worker, completable=pipe.queued_bytes > 0)
            return
        if isinstance(operation, Close):
            resource = self._require_same_pipe_endpoint(
                operation.slot, worker.pipe_id, "writer", line_number
            )
            if pipe.writers != 1 or pipe.queued_bytes != 0:
                _raise(
                    line_number,
                    CodecErrorCategory.RESOURCE_CONFLICT,
                    "only the empty pipe's final writer may close while read is pending",
                )
            del resource
            self._close_slot(operation.slot, line_number)
            self.worker = replace(worker, completable=True)
            return
        _raise(
            line_number,
            CodecErrorCategory.RESOURCE_CONFLICT,
            "pending read allows only same-pipe write or final-writer close",
        )

    def _trigger_write_worker(
        self,
        operation: simple.Operation,
        worker: WorkerCall,
        pipe: PipeState,
        line_number: int,
    ) -> None:
        if not isinstance(operation, Read) or operation.length <= 0:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "pending write allows only a positive same-pipe read",
            )
        self._require_same_pipe_endpoint(
            operation.slot, worker.pipe_id, "reader", line_number
        )
        if pipe.queued_bytes == 0:
            _raise(
                line_number,
                CodecErrorCategory.BLOCKING_IO,
                "write wake read has no queued data",
            )
        pipe.read_bytes(operation.length)
        self.worker = replace(
            worker,
            completable=pipe.can_write_record(worker.operation.length),
        )

    def _join_worker(self, line_number: int) -> None:
        worker = self.worker
        if worker is None:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "join requires an active worker",
            )
        if not worker.pending_confirmed or not worker.completable:
            _raise(
                line_number,
                CodecErrorCategory.BLOCKING_IO,
                "worker is not proven completable before join",
            )
        pipe = self.pipes[worker.pipe_id]
        if isinstance(worker.operation, StartRead):
            if pipe.queued_bytes:
                pipe.read_bytes(worker.operation.length)
            elif pipe.writers != 0:
                raise AssertionError("joined empty read requires EOF")
        else:
            pipe.write_record(worker.operation.length, worker.operation.byte)
        self.worker = None

    def _require_live(self, slot: int, line_number: int) -> FdResource:
        resource = self.slots[slot]
        if resource is None:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                f"slot {slot} is not live",
            )
        return resource

    def _require_endpoint(
        self, slot: int, endpoint: str, line_number: int
    ) -> FdResource:
        resource = self._require_live(slot, line_number)
        if resource.endpoint != endpoint:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                f"slot {slot} is not a {endpoint} endpoint",
            )
        return resource

    def _require_same_pipe_endpoint(
        self, slot: int, pipe_id: int, endpoint: str, line_number: int
    ) -> FdResource:
        resource = self._require_endpoint(slot, endpoint, line_number)
        if resource.pipe_id != pipe_id:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "controller trigger targets a different pipe",
            )
        return resource


def parse_document(encoded: Union[str, bytes]) -> ScenarioDocument:
    """Parse and validate one strict canonical-compatible v5 document."""
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
                _raise(line_number, CodecErrorCategory.INVALID_VERSION, line)
            version = simple._parse_integer(fields[1], line_number)
            if version != CORPUS_VERSION:
                _raise(line_number, CodecErrorCategory.INVALID_VERSION, line)
            saw_version = True
            continue
        if not saw_version:
            _raise(line_number, CodecErrorCategory.MISSING_VERSION, line)
        if fields[0] == "scenario":
            if len(fields) != 2:
                _raise(line_number, CodecErrorCategory.INVALID_SCENARIO, line)
            if operations is not None:
                scenarios.append(Scenario(operations))
            operations = []
            continue
        if operations is None:
            _raise(
                line_number,
                CodecErrorCategory.OPERATION_BEFORE_SCENARIO,
                line,
            )
        operations.append(_parse_operation(tuple(fields), line_number))
        operation_count += 1
    if operations is not None:
        scenarios.append(Scenario(operations))
    if not saw_version or not scenarios or operation_count == 0:
        _raise(
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
        raise AssertionError("canonical blocking pipe serialization changed the IR")
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
        _raise(
            0,
            CodecErrorCategory.INVALID_VERSION,
            f"unsupported version {document.version}",
        )
    if not document.scenarios:
        _raise(0, CodecErrorCategory.INCOMPLETE_DOCUMENT, "no scenarios")
    for scenario_index, source_scenario in enumerate(document.scenarios):
        if not source_scenario.operations:
            _raise(
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
    if isinstance(operation, AssertPending):
        return "assert-pending"
    if isinstance(operation, Join):
        return "join"
    return simple.operation_name(operation)


def _parse_operation(fields: Tuple[str, ...], line_number: int) -> Operation:
    keyword = fields[0]
    values = fields[1:]
    if keyword == "start-read":
        if len(values) != 3:
            _raise(line_number, CodecErrorCategory.INVALID_ARITY, " ".join(fields))
        return StartRead(
            _worker_actor(values[0], line_number),
            simple._slot(simple._parse_integer(values[1], line_number), line_number),
            simple._range(
                simple._parse_integer(values[2], line_number),
                1,
                MAX_IO_BYTES,
                line_number,
                "worker read length",
            ),
        )
    if keyword == "start-write":
        if len(values) != 4:
            _raise(line_number, CodecErrorCategory.INVALID_ARITY, " ".join(fields))
        return StartWrite(
            _worker_actor(values[0], line_number),
            simple._slot(simple._parse_integer(values[1], line_number), line_number),
            simple._range(
                simple._parse_integer(values[2], line_number),
                1,
                PIPE_BUF,
                line_number,
                "worker write length",
            ),
            simple._range(
                simple._parse_integer(values[3], line_number),
                0,
                255,
                line_number,
                "worker write byte",
            ),
        )
    if keyword in ("assert-pending", "join"):
        if len(values) != 1:
            _raise(line_number, CodecErrorCategory.INVALID_ARITY, " ".join(fields))
        operation_type = AssertPending if keyword == "assert-pending" else Join
        return operation_type(_worker_actor(values[0], line_number))
    return simple._parse_operation(fields, line_number, simple.CORPUS_VERSION)


def _validate_operation_fields(operation: Operation) -> None:
    fields = tuple(_serialize_operation(operation).split())
    if _parse_operation(fields, 0) != operation:
        _raise(
            0,
            CodecErrorCategory.RESOURCE_CONFLICT,
            f"invalid {type(operation).__name__}",
        )


def _serialize_operation(operation: Operation) -> str:
    if isinstance(operation, StartRead):
        return f"start-read {operation.actor} {operation.slot} {operation.length}"
    if isinstance(operation, StartWrite):
        return (
            f"start-write {operation.actor} {operation.slot} "
            f"{operation.length} {operation.byte}"
        )
    if isinstance(operation, AssertPending):
        return f"assert-pending {operation.actor}"
    if isinstance(operation, Join):
        return f"join {operation.actor}"
    return simple.format_operation(operation, simple.CORPUS_VERSION)


def _serialize_without_validation(document: ScenarioDocument) -> str:
    lines = [f"version {CORPUS_VERSION}"]
    for index, source_scenario in enumerate(document.scenarios, start=1):
        lines.append(f"scenario generated-{index:04d}")
        lines.extend(_serialize_operation(operation) for operation in source_scenario.operations)
    return "\n".join(lines) + "\n"


def _worker_actor(text: str, line_number: int) -> int:
    return simple._range(
        simple._parse_integer(text, line_number),
        WORKER_ACTOR,
        WORKER_ACTOR,
        line_number,
        "worker actor",
    )


def _raise(line_number: int, category: CodecErrorCategory, detail: str):
    raise ScenarioCodecError(line_number, category, detail)


__all__ = [name for name in globals() if not name.startswith("_")]
