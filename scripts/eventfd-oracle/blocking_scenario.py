"""Controlled two-actor eventfd scenario IR and canonical v2 codec."""

import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional, Tuple, Union

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

import scenario as simple
from linux_oracle import actor as controlled_actor


CORPUS_VERSION = 2
CONTROL_ACTOR = controlled_actor.CONTROLLER_ACTOR
WORKER_ACTOR = controlled_actor.WORKER_ACTOR

MAX_LOGICAL_SLOTS = simple.MAX_LOGICAL_SLOTS
MAX_OPS_PER_SCENARIO = simple.MAX_OPS_PER_SCENARIO
MAX_SCENARIOS_PER_ENTRY = simple.MAX_SCENARIOS_PER_ENTRY
MAX_ENTRY_BYTES = simple.MAX_ENTRY_BYTES
MAX_U64 = simple.MAX_U64
MAX_COUNTER = simple.MAX_COUNTER
O_NONBLOCK = simple.O_NONBLOCK
EFD_SEMAPHORE = simple.EFD_SEMAPHORE
PointerMode = simple.PointerMode
Scenario = simple.Scenario
ScenarioDocument = simple.ScenarioDocument
ScenarioCodecError = simple.ScenarioCodecError

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


@dataclass(frozen=True)
class StartRead:
    actor: int
    slot: int


@dataclass(frozen=True)
class StartWrite:
    actor: int
    slot: int
    value: int


@dataclass(frozen=True)
class AssertPending:
    actor: int


@dataclass(frozen=True)
class Join:
    actor: int


BlockingOperation = Union[StartRead, StartWrite, AssertPending, Join]
Operation = Union[simple.Operation, BlockingOperation]


WorkerCall = controlled_actor.WorkerCall


class ResourceState:
    """Proves one worker blocks first and can complete before it is joined."""

    def __init__(self) -> None:
        self.simple = simple.ResourceState()
        self._worker_lifecycle = controlled_actor.SingleWorkerLifecycle[
            Union[StartRead, StartWrite], int
        ]()

    @property
    def worker(self) -> Optional[WorkerCall]:
        return self._worker_lifecycle.worker

    def apply(self, operation: Operation) -> None:
        if isinstance(operation, (StartRead, StartWrite)):
            self._start_worker(operation)
        elif isinstance(operation, AssertPending):
            self._assert_pending(operation)
        elif isinstance(operation, Join):
            self._join_worker(operation)
        elif self.worker is None:
            self.simple.apply(operation)
        else:
            self._apply_controller_trigger(operation)

    def finish_scenario(self) -> None:
        self._apply_worker_transition(self._worker_lifecycle.finish_scenario)

    def descriptor(self, slot: int):
        return self.simple.descriptor(slot)

    def description(self, slot: int):
        return self.simple.description(slot)

    def event(self, slot: int):
        return self.simple.event(slot)

    def _start_worker(self, operation: Union[StartRead, StartWrite]) -> None:
        def identify_event() -> int:
            description = self.simple.description(operation.slot)
            event = self.simple.event(operation.slot)
            if description is None or event is None:
                raise ScenarioCodecError(
                    "blocking-proof", f"worker slot {operation.slot} is not live"
                )
            if description.nonblocking:
                raise ScenarioCodecError(
                    "blocking-proof", "worker eventfd must not have O_NONBLOCK"
                )
            if isinstance(operation, StartRead):
                if event.count != 0:
                    raise ScenarioCodecError(
                        "blocking-proof", "worker read would not block"
                    )
            elif (
                operation.value == MAX_U64
                or operation.value <= MAX_COUNTER - event.count
            ):
                raise ScenarioCodecError(
                    "blocking-proof", "worker write would not block"
                )
            return description.event_id

        self._apply_worker_transition(
            lambda: self._worker_lifecycle.start(operation, identify_event)
        )

    def _assert_pending(self, operation: AssertPending) -> None:
        del operation
        self._apply_worker_transition(self._worker_lifecycle.assert_pending)

    def _apply_controller_trigger(self, operation: simple.Operation) -> None:
        worker = self._apply_worker_transition(
            self._worker_lifecycle.before_trigger
        )
        if not isinstance(operation, (Read, Write)):
            raise ScenarioCodecError(
                "actor-lifecycle", "only same-event read/write may run while worker is active"
            )
        if operation.length != 8 or operation.pointer_mode is not PointerMode.VALID:
            raise ScenarioCodecError(
                "blocking-proof", "controller trigger must use an exact valid buffer"
            )
        if isinstance(operation, Write) and operation.value == MAX_U64:
            raise ScenarioCodecError(
                "blocking-proof", "controller trigger write value is invalid"
            )
        description = self.simple.description(operation.slot)
        if description is None or description.event_id != worker.resource:
            raise ScenarioCodecError(
                "actor-lifecycle", "controller trigger targets a different eventfd"
            )

        self.simple.apply(operation)
        event = self.simple.event(operation.slot)
        if event is None:
            raise AssertionError("trigger event must remain live")
        if isinstance(worker.operation, StartRead):
            completable = event.count > 0
        else:
            completable = worker.operation.value <= MAX_COUNTER - event.count
        self._worker_lifecycle.update_completable(completable)

    def _join_worker(self, operation: Join) -> None:
        del operation

        def complete(worker: WorkerCall) -> None:
            if isinstance(worker.operation, StartRead):
                joined_operation: simple.Operation = Read(
                    worker.operation.slot, 8, PointerMode.VALID
                )
            else:
                joined_operation = Write(
                    worker.operation.slot,
                    8,
                    PointerMode.VALID,
                    worker.operation.value,
                )
            self.simple.apply(joined_operation)

        self._apply_worker_transition(
            lambda: self._worker_lifecycle.join(complete)
        )

    @staticmethod
    def _apply_worker_transition(transition: Callable[[], object]):
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
    """Parse and validate one canonical-format-compatible v2 document."""
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
                raise ScenarioCodecError(
                    "version", "invalid version declaration", line_number
                )
            version = simple._parse_integer(
                fields[1], CORPUS_VERSION, CORPUS_VERSION, line_number
            )
            continue
        if fields[0] == "scenario":
            if version is None or len(fields) != 2 or not fields[1]:
                raise ScenarioCodecError(
                    "scenario", "invalid scenario declaration", line_number
                )
            if saw_scenario:
                if not operations:
                    raise ScenarioCodecError(
                        "scenario", "scenario has no operations", line_number
                    )
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
        (
            scenario
            for source_document in documents
            for scenario in source_document.scenarios
        ),
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
        raise ScenarioCodecError(
            "entry-limit", "canonical document is too large"
        )


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
    if isinstance(operation, AssertPending):
        return "assert-pending"
    if isinstance(operation, Join):
        return "join"
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
    if name == "start-read" and len(values) == 2:
        return StartRead(
            _worker_actor(values[0], line_number),
            simple._slot(values[1], line_number),
        )
    if name == "start-write" and len(values) == 3:
        return StartWrite(
            _worker_actor(values[0], line_number),
            simple._slot(values[1], line_number),
            simple._parse_integer(values[2], 0, MAX_U64, line_number),
        )
    if name in ("assert-pending", "join") and len(values) == 1:
        operation_type = AssertPending if name == "assert-pending" else Join
        return operation_type(_worker_actor(values[0], line_number))
    return simple._parse_operation(fields, line_number)


def _validate_operation_fields(operation: Operation) -> None:
    fields = tuple(_serialize_operation(operation).split())
    parsed = _parse_operation(fields, 0)
    if parsed != operation:
        raise ScenarioCodecError(
            "operation", f"invalid {type(operation).__name__}"
        )


def _serialize_operation(operation: Operation) -> str:
    if isinstance(operation, StartRead):
        return f"start-read {operation.actor} {operation.slot}"
    if isinstance(operation, StartWrite):
        return f"start-write {operation.actor} {operation.slot} {operation.value}"
    if isinstance(operation, AssertPending):
        return f"assert-pending {operation.actor}"
    if isinstance(operation, Join):
        return f"join {operation.actor}"
    return simple._serialize_operation(operation)


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
    return simple._parse_integer(text, WORKER_ACTOR, WORKER_ACTOR, line_number)


__all__ = [name for name in globals() if not name.startswith("_")]
