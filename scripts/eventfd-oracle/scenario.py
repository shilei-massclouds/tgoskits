"""Immutable eventfd scenario IR and canonical ``eventfd.ops`` v1 codec."""

import hashlib
import re
from dataclasses import dataclass, replace
from enum import IntEnum
from typing import Dict, Iterable, Optional, Tuple, Union


CORPUS_VERSION = 1
MAX_LOGICAL_SLOTS = 16
MAX_OPS_PER_SCENARIO = 32
MAX_SCENARIOS_PER_ENTRY = 4
MAX_ENTRY_BYTES = 4096
MAX_IO_BYTES = 16
MAX_POLL_FDS = 4
MAX_POLL_MASK = 32767
MAX_U32 = (1 << 32) - 1
MAX_U64 = (1 << 64) - 1
MAX_COUNTER = MAX_U64 - 1

EFD_SEMAPHORE = 1
O_NONBLOCK = 2048
O_CLOEXEC = 524288
FD_CLOEXEC = 1
UNKNOWN_FLAG = 0x40000000
EFD_ALLOWED_FLAGS = EFD_SEMAPHORE | O_NONBLOCK | O_CLOEXEC
EFD_FLAG_VALUES = tuple(
    sorted(
        {
            semaphore | nonblocking | cloexec
            for semaphore in (0, EFD_SEMAPHORE)
            for nonblocking in (0, O_NONBLOCK)
            for cloexec in (0, O_CLOEXEC)
        }
        | {UNKNOWN_FLAG}
    )
)
DUP3_FLAG_VALUES = (0, O_CLOEXEC, O_NONBLOCK, O_NONBLOCK | O_CLOEXEC, UNKNOWN_FLAG)
STATUS_FLAG_VALUES = (0, O_NONBLOCK)
FD_FLAG_VALUES = (0, FD_CLOEXEC)
POLL_LITERAL_FDS = (-2, -1, 2147483647)


class PointerMode(IntEnum):
    VALID = 0
    INVALID = 1


class PollFdMode(IntEnum):
    SLOT = 0
    LITERAL = 1


@dataclass(frozen=True)
class EventFd:
    slot: int
    initval: int


@dataclass(frozen=True)
class EventFd2:
    slot: int
    initval: int
    flags: int


@dataclass(frozen=True)
class Read:
    slot: int
    length: int
    pointer_mode: PointerMode


@dataclass(frozen=True)
class Write:
    slot: int
    length: int
    pointer_mode: PointerMode
    value: int


@dataclass(frozen=True)
class Dup:
    source_slot: int
    destination_slot: int


@dataclass(frozen=True)
class Dup2:
    source_slot: int
    destination_slot: int


@dataclass(frozen=True)
class Dup3:
    source_slot: int
    destination_slot: int
    flags: int


@dataclass(frozen=True)
class Close:
    slot: int


@dataclass(frozen=True)
class GetStatusFlags:
    slot: int


@dataclass(frozen=True)
class SetStatusFlags:
    slot: int
    flags: int


@dataclass(frozen=True)
class GetFdFlags:
    slot: int


@dataclass(frozen=True)
class SetFdFlags:
    slot: int
    flags: int


@dataclass(frozen=True)
class PollFdEntry:
    fd_mode: PollFdMode
    fd_arg: int
    events: int


@dataclass(frozen=True)
class PollMany:
    entries: Tuple[PollFdEntry, ...]

    def __init__(self, entries: Iterable[PollFdEntry]):
        object.__setattr__(self, "entries", tuple(entries))


Operation = Union[
    EventFd,
    EventFd2,
    Read,
    Write,
    Dup,
    Dup2,
    Dup3,
    Close,
    GetStatusFlags,
    SetStatusFlags,
    GetFdFlags,
    SetFdFlags,
    PollMany,
]


@dataclass(frozen=True)
class Scenario:
    operations: Tuple[Operation, ...]

    def __init__(self, operations: Iterable[Operation]):
        object.__setattr__(self, "operations", tuple(operations))


@dataclass(frozen=True)
class ScenarioDocument:
    scenarios: Tuple[Scenario, ...]
    version: int = CORPUS_VERSION

    def __init__(self, scenarios: Iterable[Scenario], version: int = CORPUS_VERSION):
        object.__setattr__(self, "scenarios", tuple(scenarios))
        object.__setattr__(self, "version", version)


class ScenarioCodecError(ValueError):
    """A stable fail-closed codec or resource validation error."""

    def __init__(self, category: str, detail: str, line_number: Optional[int] = None):
        self.category = category
        self.detail = detail
        self.line_number = line_number
        location = f" at line {line_number}" if line_number is not None else ""
        super().__init__(f"{category}{location}: {detail}")


@dataclass(frozen=True)
class EventState:
    count: int
    semaphore: bool


@dataclass(frozen=True)
class DescriptionState:
    event_id: int
    nonblocking: bool


@dataclass(frozen=True)
class DescriptorState:
    description_id: int
    cloexec: bool


class ResourceState:
    """Conservative execution state used only to prove that calls cannot block."""

    def __init__(self) -> None:
        self.events: Dict[int, EventState] = {}
        self.descriptions: Dict[int, DescriptionState] = {}
        self.descriptors: Dict[int, DescriptorState] = {}
        self._next_identity = 0

    def apply(self, operation: Operation) -> None:
        if isinstance(operation, (EventFd, EventFd2)):
            self._apply_create(operation)
        elif isinstance(operation, Read):
            self._apply_read(operation)
        elif isinstance(operation, Write):
            self._apply_write(operation)
        elif isinstance(operation, Dup):
            self._apply_dup(operation)
        elif isinstance(operation, Dup2):
            self._apply_dup2(operation)
        elif isinstance(operation, Dup3):
            self._apply_dup3(operation)
        elif isinstance(operation, Close):
            self.descriptors.pop(operation.slot, None)
        elif isinstance(operation, SetStatusFlags):
            self._apply_status_flags(operation)
        elif isinstance(operation, SetFdFlags):
            descriptor = self.descriptors.get(operation.slot)
            if descriptor is not None:
                self.descriptors[operation.slot] = replace(
                    descriptor, cloexec=bool(operation.flags & FD_CLOEXEC)
                )

    def descriptor(self, slot: int) -> Optional[DescriptorState]:
        return self.descriptors.get(slot)

    def description(self, slot: int) -> Optional[DescriptionState]:
        descriptor = self.descriptors.get(slot)
        if descriptor is None:
            return None
        return self.descriptions[descriptor.description_id]

    def event(self, slot: int) -> Optional[EventState]:
        description = self.description(slot)
        if description is None:
            return None
        return self.events[description.event_id]

    def _apply_create(self, operation: Union[EventFd, EventFd2]) -> None:
        flags = operation.flags if isinstance(operation, EventFd2) else 0
        if flags & ~EFD_ALLOWED_FLAGS:
            return
        if operation.slot in self.descriptors:
            raise ScenarioCodecError(
                "resource-state", f"creation destination slot {operation.slot} is live"
            )
        identity = self._next_identity
        self._next_identity += 1
        self.events[identity] = EventState(
            count=operation.initval,
            semaphore=bool(flags & EFD_SEMAPHORE),
        )
        self.descriptions[identity] = DescriptionState(
            event_id=identity,
            nonblocking=bool(flags & O_NONBLOCK),
        )
        self.descriptors[operation.slot] = DescriptorState(
            description_id=identity,
            cloexec=bool(flags & O_CLOEXEC),
        )

    def _apply_read(self, operation: Read) -> None:
        description = self.description(operation.slot)
        event = self.event(operation.slot)
        if description is None or event is None or operation.length < 8:
            return
        if event.count == 0:
            if not description.nonblocking:
                raise ScenarioCodecError(
                    "blocking-operation",
                    f"read from empty blocking eventfd slot {operation.slot}",
                )
            return
        consumed = 1 if event.semaphore else event.count
        self.events[description.event_id] = replace(event, count=event.count - consumed)

    def _apply_write(self, operation: Write) -> None:
        description = self.description(operation.slot)
        event = self.event(operation.slot)
        if (
            description is None
            or event is None
            or operation.length < 8
            or operation.pointer_mode is PointerMode.INVALID
            or operation.value == MAX_U64
        ):
            return
        if operation.value <= MAX_COUNTER - event.count:
            self.events[description.event_id] = replace(
                event, count=event.count + operation.value
            )
            return
        if not description.nonblocking:
            raise ScenarioCodecError(
                "blocking-operation",
                f"overflowing write to blocking eventfd slot {operation.slot}",
            )

    def _apply_dup(self, operation: Dup) -> None:
        if operation.source_slot == operation.destination_slot:
            raise ScenarioCodecError("resource-state", "dup source and destination match")
        if operation.destination_slot in self.descriptors:
            raise ScenarioCodecError(
                "resource-state",
                f"dup destination slot {operation.destination_slot} is live",
            )
        source = self.descriptors.get(operation.source_slot)
        if source is not None:
            self.descriptors[operation.destination_slot] = replace(source, cloexec=False)

    def _apply_dup2(self, operation: Dup2) -> None:
        source = self.descriptors.get(operation.source_slot)
        if source is None or operation.source_slot == operation.destination_slot:
            return
        self.descriptors[operation.destination_slot] = replace(source, cloexec=False)

    def _apply_dup3(self, operation: Dup3) -> None:
        source = self.descriptors.get(operation.source_slot)
        if (
            source is None
            or operation.source_slot == operation.destination_slot
            or operation.flags & ~O_CLOEXEC
        ):
            return
        self.descriptors[operation.destination_slot] = replace(
            source, cloexec=bool(operation.flags & O_CLOEXEC)
        )

    def _apply_status_flags(self, operation: SetStatusFlags) -> None:
        descriptor = self.descriptors.get(operation.slot)
        if descriptor is None:
            return
        description = self.descriptions[descriptor.description_id]
        self.descriptions[descriptor.description_id] = replace(
            description, nonblocking=bool(operation.flags & O_NONBLOCK)
        )


def parse_document(encoded: Union[bytes, str]) -> ScenarioDocument:
    """Parse, validate, and return one eventfd scenario document."""
    if isinstance(encoded, bytes):
        try:
            text = encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ScenarioCodecError("encoding", "document is not UTF-8") from error
    else:
        text = encoded
    if "\x00" in text:
        raise ScenarioCodecError("encoding", "document contains NUL")

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
        fields = re.split(r"[ \t]+", line)
        if fields[0] == "version":
            if version is not None or saw_scenario or len(fields) != 2:
                raise ScenarioCodecError("version", "invalid version declaration", line_number)
            version = _parse_integer(fields[1], 1, CORPUS_VERSION, line_number)
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
    document = ScenarioDocument(scenarios, version)
    validate_document(document)
    return document


def serialize_document(document: ScenarioDocument) -> str:
    """Validate and render canonical bytes for a document."""
    validate_document(document)
    lines = [f"version {CORPUS_VERSION}"]
    for index, scenario in enumerate(document.scenarios, start=1):
        lines.append(f"scenario generated-{index:04d}")
        lines.extend(_serialize_operation(operation) for operation in scenario.operations)
    return "\n".join(lines) + "\n"


def combine_documents(documents: Iterable[ScenarioDocument]) -> ScenarioDocument:
    scenarios = tuple(
        scenario for document in documents for scenario in document.scenarios
    )
    combined = ScenarioDocument(scenarios)
    validate_document(combined)
    return combined


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


def validate_entry_limits(document: ScenarioDocument) -> None:
    validate_document(document)
    if len(document.scenarios) > MAX_SCENARIOS_PER_ENTRY:
        raise ScenarioCodecError("entry-limit", "too many scenarios")
    rendered = _serialize_without_validation(document)
    if len(rendered.encode("utf-8")) > MAX_ENTRY_BYTES:
        raise ScenarioCodecError("entry-limit", "canonical document is too large")


def analyze_scenario(scenario: Scenario) -> ResourceState:
    state = ResourceState()
    for operation in scenario.operations:
        _validate_operation_fields(operation)
        state.apply(operation)
    return state


def operation_name(operation: Operation) -> str:
    names = {
        EventFd: "eventfd",
        EventFd2: "eventfd2",
        Read: "read",
        Write: "write",
        Dup: "dup",
        Dup2: "dup2",
        Dup3: "dup3",
        Close: "close",
        GetStatusFlags: "get-status-flags",
        SetStatusFlags: "set-status-flags",
        GetFdFlags: "get-fd-flags",
        SetFdFlags: "set-fd-flags",
        PollMany: "poll-many",
    }
    return names[type(operation)]


def _parse_operation(fields: Tuple[str, ...], line_number: int) -> Operation:
    name = fields[0]
    values = fields[1:]
    if name == "eventfd" and len(values) == 2:
        return EventFd(_slot(values[0], line_number), _u32(values[1], line_number))
    if name == "eventfd2" and len(values) == 3:
        flags = _integer_from_values(values[2], EFD_FLAG_VALUES, line_number)
        return EventFd2(
            _slot(values[0], line_number), _u32(values[1], line_number), flags
        )
    if name == "read" and len(values) == 3:
        return Read(
            _slot(values[0], line_number),
            _parse_integer(values[1], 0, MAX_IO_BYTES, line_number),
            PointerMode(_parse_integer(values[2], 0, 1, line_number)),
        )
    if name == "write" and len(values) == 4:
        return Write(
            _slot(values[0], line_number),
            _parse_integer(values[1], 0, MAX_IO_BYTES, line_number),
            PointerMode(_parse_integer(values[2], 0, 1, line_number)),
            _parse_integer(values[3], 0, MAX_U64, line_number),
        )
    if name in ("dup", "dup2") and len(values) == 2:
        operation_type = Dup if name == "dup" else Dup2
        return operation_type(_slot(values[0], line_number), _slot(values[1], line_number))
    if name == "dup3" and len(values) == 3:
        return Dup3(
            _slot(values[0], line_number),
            _slot(values[1], line_number),
            _integer_from_values(values[2], DUP3_FLAG_VALUES, line_number),
        )
    if name in ("close", "get-status-flags", "get-fd-flags") and len(values) == 1:
        operation_type = {
            "close": Close,
            "get-status-flags": GetStatusFlags,
            "get-fd-flags": GetFdFlags,
        }[name]
        return operation_type(_slot(values[0], line_number))
    if name == "set-status-flags" and len(values) == 2:
        return SetStatusFlags(
            _slot(values[0], line_number),
            _integer_from_values(values[1], STATUS_FLAG_VALUES, line_number),
        )
    if name == "set-fd-flags" and len(values) == 2:
        return SetFdFlags(
            _slot(values[0], line_number),
            _integer_from_values(values[1], FD_FLAG_VALUES, line_number),
        )
    if name == "poll-many" and values:
        count = _parse_integer(values[0], 0, MAX_POLL_FDS, line_number)
        if len(values) != 1 + count * 3:
            raise ScenarioCodecError("operation", "poll-many field count mismatch", line_number)
        entries = []
        for index in range(count):
            mode = PollFdMode(_parse_integer(values[1 + index * 3], 0, 1, line_number))
            raw_fd = values[2 + index * 3]
            fd_arg = (
                _slot(raw_fd, line_number)
                if mode is PollFdMode.SLOT
                else _integer_from_values(raw_fd, POLL_LITERAL_FDS, line_number)
            )
            events = _parse_integer(
                values[3 + index * 3], 0, MAX_POLL_MASK, line_number
            )
            entries.append(PollFdEntry(mode, fd_arg, events))
        return PollMany(entries)
    raise ScenarioCodecError("operation", f"invalid operation {name!r}", line_number)


def _validate_operation_fields(operation: Operation) -> None:
    try:
        parse_document_fields = _serialize_operation(operation).split()
        _parse_operation(tuple(parse_document_fields), 0)
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, ScenarioCodecError):
            raise
        raise ScenarioCodecError("operation", f"invalid {type(operation).__name__}") from error


def _serialize_operation(operation: Operation) -> str:
    if isinstance(operation, EventFd):
        return f"eventfd {operation.slot} {operation.initval}"
    if isinstance(operation, EventFd2):
        return f"eventfd2 {operation.slot} {operation.initval} {operation.flags}"
    if isinstance(operation, Read):
        return f"read {operation.slot} {operation.length} {int(operation.pointer_mode)}"
    if isinstance(operation, Write):
        return (
            f"write {operation.slot} {operation.length} "
            f"{int(operation.pointer_mode)} {operation.value}"
        )
    if isinstance(operation, (Dup, Dup2)):
        return (
            f"{operation_name(operation)} {operation.source_slot} "
            f"{operation.destination_slot}"
        )
    if isinstance(operation, Dup3):
        return (
            f"dup3 {operation.source_slot} {operation.destination_slot} {operation.flags}"
        )
    if isinstance(operation, (Close, GetStatusFlags, GetFdFlags)):
        return f"{operation_name(operation)} {operation.slot}"
    if isinstance(operation, (SetStatusFlags, SetFdFlags)):
        return f"{operation_name(operation)} {operation.slot} {operation.flags}"
    if isinstance(operation, PollMany):
        fields = ["poll-many", str(len(operation.entries))]
        for entry in operation.entries:
            fields.extend((str(int(entry.fd_mode)), str(entry.fd_arg), str(entry.events)))
        return " ".join(fields)
    raise ScenarioCodecError("operation", f"unsupported operation {type(operation).__name__}")


def _serialize_without_validation(document: ScenarioDocument) -> str:
    lines = [f"version {CORPUS_VERSION}"]
    for index, scenario in enumerate(document.scenarios, start=1):
        lines.append(f"scenario generated-{index:04d}")
        lines.extend(_serialize_operation(operation) for operation in scenario.operations)
    return "\n".join(lines) + "\n"


def _slot(text: str, line_number: int) -> int:
    return _parse_integer(text, 0, MAX_LOGICAL_SLOTS - 1, line_number)


def _u32(text: str, line_number: int) -> int:
    return _parse_integer(text, 0, MAX_U32, line_number)


def _integer_from_values(text: str, values: Tuple[int, ...], line_number: int) -> int:
    parsed = _parse_integer(text, min(values), max(values), line_number)
    if parsed not in values:
        raise ScenarioCodecError("integer", f"unsupported value {parsed}", line_number)
    return parsed


def _parse_integer(text: str, minimum: int, maximum: int, line_number: int) -> int:
    try:
        parsed = int(text, 0)
    except ValueError as error:
        raise ScenarioCodecError("integer", f"invalid integer {text!r}", line_number) from error
    if parsed < minimum or parsed > maximum:
        raise ScenarioCodecError("integer", f"integer {parsed} is out of range", line_number)
    return parsed


__all__ = [name for name in globals() if not name.startswith("_")]
