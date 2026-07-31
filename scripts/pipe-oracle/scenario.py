"""Immutable pipe scenario IR and the canonical ``pipe.ops`` codec."""

import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, Optional, Tuple, Union


LEGACY_CORPUS_VERSION = 1
CORPUS_VERSION = 2
MAX_LOGICAL_SLOTS = 16
MAX_IO_BYTES = 8192
MAX_POLL_MASK = 32767
MAX_PIPE_SIZE = 2147483647
MAX_FLAG_VALUE = 2147483647
MAX_OPS_PER_SCENARIO = 32
MAX_SCENARIOS_PER_ENTRY = 4
MAX_ENTRY_BYTES = 4096

O_NONBLOCK = 2048
O_CLOEXEC = 524288
FD_CLOEXEC = 1
PIPE2_ALLOWED_FLAGS = O_NONBLOCK | O_CLOEXEC
DUP3_ALLOWED_FLAGS = O_CLOEXEC
LEGACY_PIPE2_FLAGS = PIPE2_ALLOWED_FLAGS
UNKNOWN_FLAG = 0x40000000
PIPE2_FLAG_VALUES = (
    0,
    O_NONBLOCK,
    O_CLOEXEC,
    PIPE2_ALLOWED_FLAGS,
    UNKNOWN_FLAG,
)
DUP3_FLAG_VALUES = (
    0,
    O_CLOEXEC,
    O_NONBLOCK,
    O_CLOEXEC | O_NONBLOCK,
    UNKNOWN_FLAG,
)


@dataclass(frozen=True)
class Pipe2:
    read_slot: int
    write_slot: int
    flags: int = LEGACY_PIPE2_FLAGS


@dataclass(frozen=True)
class Read:
    slot: int
    length: int


@dataclass(frozen=True)
class ReadNull:
    slot: int


@dataclass(frozen=True)
class Write:
    slot: int
    length: int
    byte: int


@dataclass(frozen=True)
class WriteNull:
    slot: int


@dataclass(frozen=True)
class Dup:
    source_slot: int
    destination_slot: int


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
class Poll:
    slot: int
    events: int


@dataclass(frozen=True)
class SetSize:
    slot: int
    size: int


@dataclass(frozen=True)
class GetSize:
    slot: int


@dataclass(frozen=True)
class Fionread:
    slot: int


Operation = Union[
    Pipe2,
    Read,
    ReadNull,
    Write,
    WriteNull,
    Dup,
    GetStatusFlags,
    SetStatusFlags,
    GetFdFlags,
    SetFdFlags,
    Dup2,
    Dup3,
    Close,
    Poll,
    SetSize,
    GetSize,
    Fionread,
]


@dataclass(frozen=True)
class Scenario:
    operations: Tuple[Operation, ...]

    def __init__(self, operations: Iterable[Operation]):
        object.__setattr__(self, "operations", tuple(operations))


@dataclass(frozen=True)
class ScenarioDocument:
    scenarios: Tuple[Scenario, ...]
    version: int

    def __init__(
        self,
        scenarios: Iterable[Scenario],
        version: int = CORPUS_VERSION,
    ):
        object.__setattr__(self, "scenarios", tuple(scenarios))
        object.__setattr__(self, "version", version)


class CodecErrorCategory(str, Enum):
    INVALID_ENCODING = "invalid-encoding"
    MISSING_VERSION = "missing-version"
    DUPLICATE_VERSION = "duplicate-version"
    INVALID_VERSION = "invalid-version"
    INVALID_SCENARIO = "invalid-scenario"
    OPERATION_BEFORE_SCENARIO = "operation-before-scenario"
    UNKNOWN_OPERATION = "unknown-operation"
    INVALID_ARITY = "invalid-arity"
    INVALID_NUMBER = "invalid-number"
    OUT_OF_RANGE = "out-of-range"
    RESOURCE_CONFLICT = "resource-conflict"
    BLOCKING_IO = "blocking-io"
    INCOMPLETE_DOCUMENT = "incomplete-document"


class ScenarioCodecError(ValueError):
    """A stable, line-addressable corpus decoding failure."""

    def __init__(
        self,
        line_number: int,
        category: CodecErrorCategory,
        detail: str,
    ):
        self.line_number = line_number
        self.category = category
        self.detail = detail
        super().__init__(f"line {line_number}: {category.value}: {detail}")


class EntryLimitCategory(str, Enum):
    TOO_MANY_SCENARIOS = "too-many-scenarios"
    EMPTY_SCENARIO = "empty-scenario"
    TOO_MANY_OPERATIONS = "too-many-operations"
    ENCODING_TOO_LARGE = "encoding-too-large"


class ScenarioEntryLimitError(ValueError):
    """A structured corpus entry exceeds a campaign resource limit."""

    def __init__(self, category: EntryLimitCategory, detail: str):
        self.category = category
        self.detail = detail
        super().__init__(f"{category.value}: {detail}")


_DECIMAL_OR_HEX = re.compile(r"^[+-]?(?:[0-9]+|0[xX][0-9a-fA-F]+)$")


def parse_document(encoded: Union[str, bytes]) -> ScenarioDocument:
    """Parse harness-compatible text and discard non-semantic scenario names."""

    text = _decode_text(encoded)
    scenarios = []
    current_operations = None
    resource_state = None
    saw_version = False
    version = None
    operation_count = 0

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", maxsplit=1)[0].strip()
        if not line:
            continue
        fields = line.split()
        keyword = fields[0]

        if keyword == "version":
            if saw_version:
                _raise(line_number, CodecErrorCategory.DUPLICATE_VERSION, line)
            if scenarios:
                _raise(line_number, CodecErrorCategory.INVALID_VERSION, line)
            if len(fields) != 2:
                _raise(line_number, CodecErrorCategory.INVALID_VERSION, line)
            version = _parse_integer(fields[1], line_number)
            if version not in (LEGACY_CORPUS_VERSION, CORPUS_VERSION):
                _raise(line_number, CodecErrorCategory.INVALID_VERSION, line)
            saw_version = True
            continue

        if not saw_version:
            _raise(line_number, CodecErrorCategory.MISSING_VERSION, line)

        if keyword == "scenario":
            if len(fields) != 2:
                _raise(line_number, CodecErrorCategory.INVALID_SCENARIO, line)
            if current_operations is not None:
                scenarios.append(Scenario(current_operations))
            current_operations = []
            resource_state = _ResourceState()
            continue

        if current_operations is None or resource_state is None:
            _raise(
                line_number,
                CodecErrorCategory.OPERATION_BEFORE_SCENARIO,
                line,
            )

        operation = _parse_operation(fields, line_number, version)
        resource_state.apply(operation, line_number)
        current_operations.append(operation)
        operation_count += 1

    if current_operations is not None:
        scenarios.append(Scenario(current_operations))
    if not saw_version or not scenarios or operation_count == 0:
        _raise(
            max(1, len(text.splitlines())),
            CodecErrorCategory.INCOMPLETE_DOCUMENT,
            "document requires a version, scenario, and operation",
        )
    return ScenarioDocument(scenarios, version)


def serialize_document(document: ScenarioDocument) -> str:
    """Return canonical versioned text after validating harness parseability."""

    text = serialize_unchecked_document(document)
    parsed = parse_document(text)
    if parsed != document:
        raise AssertionError("canonical pipe.ops serialization changed the scenario IR")
    return text


def serialize_unchecked_document(document: ScenarioDocument) -> str:
    """Serialize typed operations without validating ranges or resource conflicts."""

    lines = [f"version {document.version}"]
    for index, scenario in enumerate(document.scenarios, start=1):
        lines.append(f"scenario generated-{index:04d}")
        lines.extend(
            format_operation(operation, document.version)
            for operation in scenario.operations
        )
    return "\n".join(lines) + "\n"


def canonical_digest(document: ScenarioDocument) -> str:
    return hashlib.sha256(serialize_document(document).encode("utf-8")).hexdigest()


def validate_entry_limits(document: ScenarioDocument) -> None:
    if len(document.scenarios) > MAX_SCENARIOS_PER_ENTRY:
        raise ScenarioEntryLimitError(
            EntryLimitCategory.TOO_MANY_SCENARIOS,
            f"{len(document.scenarios)} > {MAX_SCENARIOS_PER_ENTRY}",
        )
    for index, scenario in enumerate(document.scenarios, start=1):
        if not scenario.operations:
            raise ScenarioEntryLimitError(
                EntryLimitCategory.EMPTY_SCENARIO,
                f"scenario {index} has no operations",
            )
        if len(scenario.operations) > MAX_OPS_PER_SCENARIO:
            raise ScenarioEntryLimitError(
                EntryLimitCategory.TOO_MANY_OPERATIONS,
                f"scenario {index}: {len(scenario.operations)} > {MAX_OPS_PER_SCENARIO}",
            )
    encoded_size = len(serialize_document(document).encode("utf-8"))
    if encoded_size > MAX_ENTRY_BYTES:
        raise ScenarioEntryLimitError(
            EntryLimitCategory.ENCODING_TOO_LARGE,
            f"{encoded_size} > {MAX_ENTRY_BYTES}",
        )


def combine_documents(documents: Iterable[ScenarioDocument]) -> ScenarioDocument:
    return ScenarioDocument(
        (
            scenario
            for document in documents
            for scenario in document.scenarios
        ),
        version=CORPUS_VERSION,
    )


def operation_name(operation: Operation) -> str:
    return format_operation(operation).split(maxsplit=1)[0]


def format_operation(operation: Operation, version: int = CORPUS_VERSION) -> str:
    if isinstance(operation, Pipe2):
        if version == LEGACY_CORPUS_VERSION:
            return f"pipe2 {operation.read_slot} {operation.write_slot}"
        return f"pipe2 {operation.read_slot} {operation.write_slot} {operation.flags}"
    if isinstance(operation, Read):
        return f"read {operation.slot} {operation.length}"
    if isinstance(operation, ReadNull):
        return f"read-null {operation.slot}"
    if isinstance(operation, Write):
        return f"write {operation.slot} {operation.length} {operation.byte}"
    if isinstance(operation, WriteNull):
        return f"write-null {operation.slot}"
    if isinstance(operation, Dup):
        return f"dup {operation.source_slot} {operation.destination_slot}"
    if isinstance(operation, GetStatusFlags):
        return f"get-status-flags {operation.slot}"
    if isinstance(operation, SetStatusFlags):
        return f"set-status-flags {operation.slot} {operation.flags}"
    if isinstance(operation, GetFdFlags):
        return f"get-fd-flags {operation.slot}"
    if isinstance(operation, SetFdFlags):
        return f"set-fd-flags {operation.slot} {operation.flags}"
    if isinstance(operation, Dup2):
        return f"dup2 {operation.source_slot} {operation.destination_slot}"
    if isinstance(operation, Dup3):
        return (
            f"dup3 {operation.source_slot} {operation.destination_slot} "
            f"{operation.flags}"
        )
    if isinstance(operation, Close):
        return f"close {operation.slot}"
    if isinstance(operation, Poll):
        return f"poll {operation.slot} {operation.events}"
    if isinstance(operation, SetSize):
        return f"set-size {operation.slot} {operation.size}"
    if isinstance(operation, GetSize):
        return f"get-size {operation.slot}"
    if isinstance(operation, Fionread):
        return f"fionread {operation.slot}"
    raise TypeError(f"unsupported operation type: {type(operation).__name__}")


def _decode_text(encoded: Union[str, bytes]) -> str:
    if isinstance(encoded, str):
        return encoded
    try:
        return encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        line_number = encoded[: error.start].count(b"\n") + 1
        raise ScenarioCodecError(
            line_number,
            CodecErrorCategory.INVALID_ENCODING,
            "pipe.ops is not UTF-8",
        ) from error


def _parse_operation(fields, line_number: int, version: int) -> Operation:
    keyword = fields[0]
    arities = {
        "pipe2": 3 if version == LEGACY_CORPUS_VERSION else 4,
        "read": 3,
        "read-null": 2,
        "write": 4,
        "write-null": 2,
        "dup": 3,
        "close": 2,
        "poll": 3,
        "set-size": 3,
        "get-size": 2,
        "fionread": 2,
    }
    if version == CORPUS_VERSION:
        arities.update(
            {
                "get-status-flags": 2,
                "set-status-flags": 3,
                "get-fd-flags": 2,
                "set-fd-flags": 3,
                "dup2": 3,
                "dup3": 4,
            }
        )
    if keyword not in arities:
        _raise(line_number, CodecErrorCategory.UNKNOWN_OPERATION, keyword)
    if len(fields) != arities[keyword]:
        _raise(line_number, CodecErrorCategory.INVALID_ARITY, " ".join(fields))

    values = [_parse_integer(field, line_number) for field in fields[1:]]
    if keyword == "pipe2":
        flags = (
            LEGACY_PIPE2_FLAGS
            if version == LEGACY_CORPUS_VERSION
            else _enum_flags(
                values[2],
                PIPE2_FLAG_VALUES,
                line_number,
                "pipe2 flags",
            )
        )
        return Pipe2(
            _slot(values[0], line_number),
            _slot(values[1], line_number),
            flags,
        )
    if keyword == "read":
        return Read(
            _slot(values[0], line_number),
            _range(values[1], 0, MAX_IO_BYTES, line_number, "read length"),
        )
    if keyword == "read-null":
        return ReadNull(_slot(values[0], line_number))
    if keyword == "write":
        return Write(
            _slot(values[0], line_number),
            _range(values[1], 0, MAX_IO_BYTES, line_number, "write length"),
            _range(values[2], 0, 255, line_number, "write byte"),
        )
    if keyword == "write-null":
        return WriteNull(_slot(values[0], line_number))
    if keyword == "dup":
        return Dup(_slot(values[0], line_number), _slot(values[1], line_number))
    if keyword == "get-status-flags":
        return GetStatusFlags(_slot(values[0], line_number))
    if keyword == "set-status-flags":
        return SetStatusFlags(
            _slot(values[0], line_number),
            _flags(values[1], line_number, "status flags"),
        )
    if keyword == "get-fd-flags":
        return GetFdFlags(_slot(values[0], line_number))
    if keyword == "set-fd-flags":
        return SetFdFlags(
            _slot(values[0], line_number),
            _flags(values[1], line_number, "fd flags"),
        )
    if keyword == "dup2":
        return Dup2(_slot(values[0], line_number), _slot(values[1], line_number))
    if keyword == "dup3":
        return Dup3(
            _slot(values[0], line_number),
            _slot(values[1], line_number),
            _enum_flags(
                values[2],
                DUP3_FLAG_VALUES,
                line_number,
                "dup3 flags",
            ),
        )
    if keyword == "close":
        return Close(_slot(values[0], line_number))
    if keyword == "poll":
        return Poll(
            _slot(values[0], line_number),
            _range(values[1], 0, MAX_POLL_MASK, line_number, "poll mask"),
        )
    if keyword == "set-size":
        return SetSize(
            _slot(values[0], line_number),
            _range(values[1], 0, MAX_PIPE_SIZE, line_number, "pipe size"),
        )
    if keyword == "get-size":
        return GetSize(_slot(values[0], line_number))
    return Fionread(_slot(values[0], line_number))


def _parse_integer(text: str, line_number: int) -> int:
    if not _DECIMAL_OR_HEX.fullmatch(text):
        _raise(line_number, CodecErrorCategory.INVALID_NUMBER, text)
    signless = text.lstrip("+-")
    base = 16 if signless.lower().startswith("0x") else 10
    try:
        return int(text, base)
    except ValueError:
        _raise(line_number, CodecErrorCategory.INVALID_NUMBER, text)


def _slot(value: int, line_number: int) -> int:
    return _range(value, 0, MAX_LOGICAL_SLOTS - 1, line_number, "logical slot")


def _flags(value: int, line_number: int, name: str) -> int:
    return _range(value, 0, MAX_FLAG_VALUE, line_number, name)


def _enum_flags(
    value: int,
    supported_values: Tuple[int, ...],
    line_number: int,
    name: str,
) -> int:
    _flags(value, line_number, name)
    if value not in supported_values:
        _raise(
            line_number,
            CodecErrorCategory.OUT_OF_RANGE,
            f"unsupported {name} {value}",
        )
    return value


def _range(value: int, minimum: int, maximum: int, line_number: int, name: str) -> int:
    if value < minimum or value > maximum:
        _raise(
            line_number,
            CodecErrorCategory.OUT_OF_RANGE,
            f"{name} {value} is outside {minimum}..{maximum}",
        )
    return value


@dataclass(frozen=True)
class _FdResource:
    endpoint: str
    description_id: int
    close_on_exec: bool


class _ResourceState:
    """Track statically knowable fd and open-file-description state."""

    def __init__(self):
        self.slots: list[Optional[_FdResource]] = [None] * MAX_LOGICAL_SLOTS
        self.nonblocking: Dict[int, bool] = {}
        self.next_description_id = 0

    def apply(self, operation: Operation, line_number: int) -> None:
        if isinstance(operation, Pipe2):
            self._apply_pipe2(operation, line_number)
        elif isinstance(operation, Dup):
            self._apply_dup(operation, line_number)
        elif isinstance(operation, Dup2):
            self._apply_dup2(operation)
        elif isinstance(operation, Dup3):
            self._apply_dup3(operation)
        elif isinstance(operation, SetStatusFlags):
            resource = self.slots[operation.slot]
            if resource is not None:
                self.nonblocking[resource.description_id] = bool(
                    operation.flags & O_NONBLOCK
                )
        elif isinstance(operation, SetFdFlags):
            resource = self.slots[operation.slot]
            if resource is not None:
                self.slots[operation.slot] = _FdResource(
                    resource.endpoint,
                    resource.description_id,
                    bool(operation.flags & FD_CLOEXEC),
                )
        elif isinstance(operation, Close):
            if self.slots[operation.slot] is not None:
                self.slots[operation.slot] = None
        elif isinstance(operation, (Read, Write)):
            self._validate_nonblocking_io(operation, line_number)

    def _apply_pipe2(self, operation: Pipe2, line_number: int) -> None:
        if operation.flags & ~PIPE2_ALLOWED_FLAGS:
            return
        if operation.read_slot == operation.write_slot:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "pipe2 endpoints use the same slot",
            )
        if (
            self.slots[operation.read_slot] is not None
            or self.slots[operation.write_slot] is not None
        ):
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "pipe2 destination slot is occupied",
            )
        close_on_exec = bool(operation.flags & O_CLOEXEC)
        nonblocking = bool(operation.flags & O_NONBLOCK)
        self.slots[operation.read_slot] = self._new_resource(
            "reader", nonblocking, close_on_exec
        )
        self.slots[operation.write_slot] = self._new_resource(
            "writer", nonblocking, close_on_exec
        )

    def _apply_dup(self, operation: Dup, line_number: int) -> None:
        if operation.source_slot == operation.destination_slot:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "dup source and destination use the same slot",
            )
        if self.slots[operation.destination_slot] is not None:
            _raise(
                line_number,
                CodecErrorCategory.RESOURCE_CONFLICT,
                "dup destination slot is occupied",
            )
        source = self.slots[operation.source_slot]
        if source is not None:
            self.slots[operation.destination_slot] = _FdResource(
                source.endpoint,
                source.description_id,
                False,
            )

    def _apply_dup2(self, operation: Dup2) -> None:
        source = self.slots[operation.source_slot]
        if source is None or operation.source_slot == operation.destination_slot:
            return
        self.slots[operation.destination_slot] = _FdResource(
            source.endpoint,
            source.description_id,
            False,
        )

    def _apply_dup3(self, operation: Dup3) -> None:
        source = self.slots[operation.source_slot]
        if (
            source is None
            or operation.source_slot == operation.destination_slot
            or operation.flags & ~DUP3_ALLOWED_FLAGS
        ):
            return
        self.slots[operation.destination_slot] = _FdResource(
            source.endpoint,
            source.description_id,
            bool(operation.flags & O_CLOEXEC),
        )

    def _validate_nonblocking_io(
        self,
        operation: Union[Read, Write],
        line_number: int,
    ) -> None:
        if operation.length == 0:
            return
        resource = self.slots[operation.slot]
        if resource is None:
            return
        if not self.nonblocking[resource.description_id]:
            _raise(
                line_number,
                CodecErrorCategory.BLOCKING_IO,
                "positive-length I/O requires statically enabled O_NONBLOCK",
            )

    def _new_resource(
        self,
        endpoint: str,
        nonblocking: bool,
        close_on_exec: bool,
    ) -> _FdResource:
        description_id = self.next_description_id
        self.next_description_id += 1
        self.nonblocking[description_id] = nonblocking
        return _FdResource(endpoint, description_id, close_on_exec)


def _raise(line_number: int, category: CodecErrorCategory, detail: str):
    raise ScenarioCodecError(line_number, category, detail)
