"""Lossless conversion from a restricted syzkaller AST to ``pipe.ops`` v4."""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from scenario import (
    CORPUS_VERSION,
    DUP3_ALLOWED_FLAGS,
    MAX_FLAG_VALUE,
    MAX_IO_BYTES,
    MAX_LOGICAL_SLOTS,
    MAX_PIPE_SIZE,
    PIPE2_ALLOWED_FLAGS,
    Close,
    Dup,
    Dup2,
    Dup3,
    Fionread,
    GetFdFlags,
    GetSize,
    GetStatusFlags,
    Pipe2,
    PollFdEntry,
    PollFdMode,
    PollMany,
    Read,
    ReadNull,
    Readv,
    Scenario,
    ScenarioCodecError,
    ScenarioDocument,
    ScenarioEntryLimitError,
    SetFdFlags,
    SetSize,
    SetStatusFlags,
    Write,
    WriteNull,
    Writev,
    format_operation,
    serialize_document,
    validate_entry_limits,
)
from syz_ast import (
    SyzArgument,
    SyzArray,
    SyzAuto,
    SyzCall,
    SyzInteger,
    SyzNil,
    SyzPointer,
    SyzProgram,
    SyzResource,
    SyzResultCapture,
    SyzString,
    SyzStruct,
)
from syz_rejection import SyzConversionError, SyzRejectionCategory
from syz_vector import (
    VectorMemoryRegion,
    VectorPayloadError,
    VectorShapeError,
    convert_readv_arguments,
    convert_writev_arguments,
)


SUPPORTED_SYZKALLER_REVISION = "e611ffe1caa28a0228c8f3642cc768f0dba3dd0c"
IMPORTER_VERSION = "2"

F_GETFD = 1
F_SETFD = 2
F_GETFL = 3
F_SETFL = 4
F_SETPIPE_SZ = 1031
F_GETPIPE_SZ = 1032
FIONREAD = 21531
POLL_LITERAL_FDS = {-2, -1, 2147483647}


@dataclass(frozen=True)
class ConversionResult:
    document: ScenarioDocument
    operation_log: Tuple[Dict[str, object], ...]


@dataclass(frozen=True)
class _ResourceBinding:
    slot: int
    generation: int


@dataclass(frozen=True)
class _MemoryRegion:
    start: int
    end: int
    call_index: int
    line_number: int


def convert_syz_program(program: SyzProgram) -> ConversionResult:
    """Convert an allowlisted synchronous program and validate the v4 IR."""

    converter = _Converter()
    operations = []
    operation_log = []
    for call_index, call in enumerate(program.calls):
        operation = converter.convert_call(call, call_index)
        operations.append(operation)
        operation_log.append(
            {
                "line": call.line_number,
                "syz_call": call.name,
                "pipe_operation": format_operation(operation),
            }
        )
    document = ScenarioDocument((Scenario(operations),), version=CORPUS_VERSION)
    try:
        validate_entry_limits(document)
        serialize_document(document)
    except ScenarioCodecError as error:
        category = (
            SyzRejectionCategory.BLOCKING_IO
            if error.category.value == "blocking-io"
            else SyzRejectionCategory.UNSUPPORTED_ARGUMENT
        )
        call_index = error.line_number - 3
        source_line = (
            program.calls[call_index].line_number
            if 0 <= call_index < len(program.calls)
            else 1
        )
        raise SyzConversionError(source_line, category, error.detail) from error
    except ScenarioEntryLimitError as error:
        raise SyzConversionError(
            1,
            SyzRejectionCategory.ENTRY_LIMIT,
            f"{error.category.value}: {error.detail}",
        ) from error
    return ConversionResult(document, tuple(operation_log))


class _Converter:
    def __init__(self):
        self.bindings: Dict[str, _ResourceBinding] = {}
        self.slot_live = [False] * MAX_LOGICAL_SLOTS
        self.slot_generation = [0] * MAX_LOGICAL_SLOTS
        self.invalid_slot: Optional[int] = None
        self.memory_regions: List[_MemoryRegion] = []

    def convert_call(self, call: SyzCall, call_index: int):
        if call.properties:
            self._reject(
                call,
                SyzRejectionCategory.CALL_PROPERTIES,
                "call properties require executor scheduling semantics",
            )
        if call.name.startswith("syz_"):
            self._reject(
                call,
                SyzRejectionCategory.PSEUDO_SYSCALL,
                call.name,
            )
        converters = {
            "pipe": self._convert_pipe,
            "pipe2": self._convert_pipe2,
            "read": self._convert_read,
            "write": self._convert_write,
            "readv": self._convert_readv,
            "writev": self._convert_writev,
            "close": self._convert_close,
            "dup": self._convert_dup,
            "dup2": self._convert_dup2,
            "dup3": self._convert_dup3,
            "fcntl$getflags": self._convert_fcntl_get,
            "fcntl$setflags": self._convert_fcntl_setflags,
            "fcntl$setstatus": self._convert_fcntl_setstatus,
            "fcntl$setpipe": self._convert_fcntl_setpipe,
            "ioctl$int_out": self._convert_fionread,
            "poll": self._convert_poll,
        }
        converter = converters.get(call.name)
        if converter is None:
            self._reject(call, SyzRejectionCategory.UNSUPPORTED_CALL, call.name)
        return converter(call, call_index)

    def _convert_pipe(self, call: SyzCall, call_index: int) -> Pipe2:
        self._require_no_assignment(call)
        self._require_arity(call, 1)
        read_slot, write_slot = self._pipe_slots(call, call.arguments[0], call_index)
        return Pipe2(read_slot, write_slot, 0)

    def _convert_pipe2(self, call: SyzCall, call_index: int) -> Pipe2:
        self._require_no_assignment(call)
        self._require_arity(call, 2)
        flags = self._integer(call, call.arguments[1], "pipe2 flags")
        if flags & ~PIPE2_ALLOWED_FLAGS:
            self._reject(
                call,
                SyzRejectionCategory.UNSUPPORTED_CONSTANT,
                f"pipe2 flags {flags} are not losslessly executable",
            )
        read_slot, write_slot = self._pipe_slots(call, call.arguments[0], call_index)
        return Pipe2(read_slot, write_slot, flags)

    def _pipe_slots(
        self,
        call: SyzCall,
        argument: SyzArgument,
        call_index: int,
    ) -> Tuple[int, int]:
        pointer = self._valid_pointer(call, argument, call_index, 8, "pipefd")
        if not isinstance(pointer.value, SyzStruct) or len(pointer.value.fields) != 2:
            self._reject(
                call,
                SyzRejectionCategory.POINTER_SHAPE,
                "pipefd must be a two-field struct",
            )
        read_slot = self._allocate_live_slot(call)
        write_slot = self._allocate_live_slot(call)
        self._bind_pipe_field(call, pointer.value.fields[0], read_slot)
        self._bind_pipe_field(call, pointer.value.fields[1], write_slot)
        return read_slot, write_slot

    def _bind_pipe_field(
        self,
        call: SyzCall,
        field: SyzArgument,
        slot: int,
    ) -> None:
        capture = None
        value = field
        if isinstance(field, SyzResultCapture):
            capture = field.name
            value = field.value
        if not isinstance(value, SyzInteger) or value.value != 0:
            self._reject(
                call,
                SyzRejectionCategory.POINTER_SHAPE,
                "pipefd output fields must use their zero default",
            )
        if capture is not None:
            self._bind(call, capture, slot)

    def _convert_read(self, call: SyzCall, call_index: int):
        self._require_no_assignment(call)
        self._require_arity(call, 3)
        slot = self._fd_slot(call, call.arguments[0])
        count = self._bounded_integer(call, call.arguments[2], 0, MAX_IO_BYTES, "read count")
        pointer = call.arguments[1]
        if self._is_invalid_pointer(pointer):
            if count != 0:
                self._reject(
                    call,
                    SyzRejectionCategory.BUFFER_SHAPE,
                    "positive-length invalid read buffers are not expressible in v4",
                )
            return ReadNull(slot)
        valid = self._valid_pointer(call, pointer, call_index, max(1, count), "read buffer")
        data = self._buffer_data(call, valid.value)
        if len(data) < count:
            self._reject(
                call,
                SyzRejectionCategory.BUFFER_SHAPE,
                f"read buffer has {len(data)} bytes for count {count}",
            )
        return Read(slot, count)

    def _convert_write(self, call: SyzCall, call_index: int):
        self._require_no_assignment(call)
        self._require_arity(call, 3)
        slot = self._fd_slot(call, call.arguments[0])
        count = self._bounded_integer(call, call.arguments[2], 0, MAX_IO_BYTES, "write count")
        pointer = call.arguments[1]
        if self._is_invalid_pointer(pointer):
            if count != 0:
                self._reject(
                    call,
                    SyzRejectionCategory.BUFFER_SHAPE,
                    "positive-length invalid write buffers are not expressible in v4",
                )
            return WriteNull(slot)
        valid = self._valid_pointer(call, pointer, call_index, max(1, count), "write buffer")
        data = self._buffer_data(call, valid.value)
        if len(data) < count:
            self._reject(
                call,
                SyzRejectionCategory.BUFFER_SHAPE,
                f"write buffer has {len(data)} bytes for count {count}",
            )
        prefix = data[:count]
        if prefix and any(byte != prefix[0] for byte in prefix):
            self._reject(
                call,
                SyzRejectionCategory.NON_UNIFORM_PAYLOAD,
                "positive write payload prefix is not one repeated byte",
            )
        return Write(slot, count, prefix[0] if prefix else 0)

    def _convert_readv(self, call: SyzCall, call_index: int) -> Readv:
        self._require_no_assignment(call)
        self._require_arity(call, 3)
        slot = self._fd_slot(call, call.arguments[0])
        try:
            conversion = convert_readv_arguments(
                call.arguments[1],
                call.arguments[2],
            )
        except VectorShapeError as error:
            self._reject(call, SyzRejectionCategory.VECTOR_SHAPE, str(error))
        self._record_vector_regions(call, conversion.regions, call_index)
        return Readv(
            slot,
            conversion.iov_mode,
            conversion.iovcnt,
            conversion.segments,
        )

    def _convert_writev(self, call: SyzCall, call_index: int) -> Writev:
        self._require_no_assignment(call)
        self._require_arity(call, 3)
        slot = self._fd_slot(call, call.arguments[0])
        try:
            conversion = convert_writev_arguments(
                call.arguments[1],
                call.arguments[2],
            )
        except VectorShapeError as error:
            self._reject(
                call,
                SyzRejectionCategory.VECTOR_SHAPE,
                str(error),
            )
        except VectorPayloadError as error:
            self._reject(
                call,
                SyzRejectionCategory.NON_UNIFORM_PAYLOAD,
                str(error),
            )
        self._record_vector_regions(call, conversion.regions, call_index)
        return Writev(
            slot,
            conversion.iov_mode,
            conversion.iovcnt,
            conversion.segments,
        )

    def _convert_close(self, call: SyzCall, _call_index: int) -> Close:
        self._require_no_assignment(call)
        self._require_arity(call, 1)
        slot = self._fd_slot(call, call.arguments[0])
        if self.slot_live[slot]:
            self.slot_live[slot] = False
            self.slot_generation[slot] += 1
        return Close(slot)

    def _convert_dup(self, call: SyzCall, _call_index: int) -> Dup:
        self._require_arity(call, 1)
        if call.assignment is None:
            self._reject(
                call,
                SyzRejectionCategory.UNSUPPORTED_RESULT,
                "dup result must be captured to preserve the new descriptor",
            )
        source = self._fd_slot(call, call.arguments[0])
        destination = self._allocate_live_slot(call)
        self._bind(call, call.assignment, destination)
        return Dup(source, destination)

    def _convert_dup2(self, call: SyzCall, _call_index: int) -> Dup2:
        self._require_arity(call, 2)
        source = self._fd_slot(call, call.arguments[0])
        destination = self._live_resource_slot(call, call.arguments[1])
        if call.assignment is not None:
            self._bind(call, call.assignment, destination)
        return Dup2(source, destination)

    def _convert_dup3(self, call: SyzCall, _call_index: int) -> Dup3:
        self._require_arity(call, 3)
        source = self._fd_slot(call, call.arguments[0])
        destination = self._live_resource_slot(call, call.arguments[1])
        flags = self._integer(call, call.arguments[2], "dup3 flags")
        if flags & ~DUP3_ALLOWED_FLAGS:
            self._reject(
                call,
                SyzRejectionCategory.UNSUPPORTED_CONSTANT,
                f"dup3 flags {flags} are not losslessly executable",
            )
        if source == destination and call.assignment is not None:
            self._reject(
                call,
                SyzRejectionCategory.UNSUPPORTED_RESULT,
                "a captured same-fd dup3 failure is not a usable fd resource",
            )
        if call.assignment is not None:
            self._bind(call, call.assignment, destination)
        return Dup3(source, destination, flags)

    def _convert_fcntl_get(self, call: SyzCall, _call_index: int):
        self._require_no_assignment(call)
        self._require_arity(call, 2)
        slot = self._fd_slot(call, call.arguments[0])
        command = self._integer(call, call.arguments[1], "fcntl command")
        operations = {
            F_GETFD: GetFdFlags(slot),
            F_GETFL: GetStatusFlags(slot),
            F_GETPIPE_SZ: GetSize(slot),
        }
        operation = operations.get(command)
        if operation is None:
            self._reject(
                call,
                SyzRejectionCategory.UNSUPPORTED_CONSTANT,
                f"fcntl$getflags command {command} is outside the allowlist",
            )
        return operation

    def _convert_fcntl_setflags(self, call: SyzCall, _call_index: int) -> SetFdFlags:
        self._require_no_assignment(call)
        self._require_arity(call, 3)
        slot = self._fd_slot(call, call.arguments[0])
        self._require_command(call, call.arguments[1], F_SETFD)
        flags = self._bounded_integer(call, call.arguments[2], 0, MAX_FLAG_VALUE, "fd flags")
        return SetFdFlags(slot, flags)

    def _convert_fcntl_setstatus(
        self,
        call: SyzCall,
        _call_index: int,
    ) -> SetStatusFlags:
        self._require_no_assignment(call)
        self._require_arity(call, 3)
        slot = self._fd_slot(call, call.arguments[0])
        self._require_command(call, call.arguments[1], F_SETFL)
        flags = self._bounded_integer(
            call,
            call.arguments[2],
            0,
            MAX_FLAG_VALUE,
            "status flags",
        )
        return SetStatusFlags(slot, flags)

    def _convert_fcntl_setpipe(self, call: SyzCall, _call_index: int) -> SetSize:
        self._require_no_assignment(call)
        self._require_arity(call, 3)
        slot = self._fd_slot(call, call.arguments[0])
        self._require_command(call, call.arguments[1], F_SETPIPE_SZ)
        size = self._bounded_integer(
            call,
            call.arguments[2],
            0,
            MAX_PIPE_SIZE,
            "pipe size",
        )
        return SetSize(slot, size)

    def _convert_fionread(self, call: SyzCall, call_index: int) -> Fionread:
        self._require_no_assignment(call)
        self._require_arity(call, 3)
        slot = self._fd_slot(call, call.arguments[0])
        self._require_command(call, call.arguments[1], FIONREAD)
        pointer = self._valid_pointer(call, call.arguments[2], call_index, 8, "FIONREAD output")
        value = pointer.value
        if isinstance(value, SyzResultCapture):
            self._reject(
                call,
                SyzRejectionCategory.UNSUPPORTED_RESULT,
                "scalar FIONREAD result captures are not resources",
            )
        if not isinstance(value, (SyzInteger, SyzAuto)):
            self._reject(
                call,
                SyzRejectionCategory.POINTER_SHAPE,
                "FIONREAD output must use an integer default",
            )
        return Fionread(slot)

    def _convert_poll(self, call: SyzCall, call_index: int) -> PollMany:
        self._require_no_assignment(call)
        self._require_arity(call, 3)
        count = self._bounded_integer(call, call.arguments[1], 0, 4, "poll nfds")
        timeout = self._signed(call, call.arguments[2], 32, "poll timeout")
        if timeout != 0:
            self._reject(
                call,
                SyzRejectionCategory.POLL_SHAPE,
                f"poll timeout {timeout} is not synchronous timeout zero",
            )
        pointer = self._valid_pointer(
            call,
            call.arguments[0],
            call_index,
            max(1, count * 8),
            "pollfd array",
        )
        if not isinstance(pointer.value, SyzArray):
            self._reject(
                call,
                SyzRejectionCategory.POLL_SHAPE,
                "poll fds must be an array",
            )
        if len(pointer.value.elements) != count:
            self._reject(
                call,
                SyzRejectionCategory.POLL_SHAPE,
                f"poll nfds {count} does not match array length {len(pointer.value.elements)}",
            )
        entries = [self._poll_entry(call, entry) for entry in pointer.value.elements]
        return PollMany(entries)

    def _poll_entry(self, call: SyzCall, argument: SyzArgument) -> PollFdEntry:
        if not isinstance(argument, SyzStruct) or len(argument.fields) != 3:
            self._reject(
                call,
                SyzRejectionCategory.POLL_SHAPE,
                "pollfd must be a three-field struct",
            )
        fd_argument, events_argument, revents_argument = argument.fields
        if isinstance(fd_argument, SyzResource):
            fd_mode = PollFdMode.SLOT
            fd_arg = self._live_resource_slot(call, fd_argument)
        elif isinstance(fd_argument, SyzInteger):
            fd_mode = PollFdMode.LITERAL
            fd_arg = _signed_value(fd_argument.value, 32)
            if fd_arg not in POLL_LITERAL_FDS:
                self._reject(
                    call,
                    SyzRejectionCategory.POLL_SHAPE,
                    f"unsupported literal poll fd {fd_arg}",
                )
        else:
            self._reject(
                call,
                SyzRejectionCategory.POLL_SHAPE,
                "poll fd must be a resource or allowlisted literal",
            )
        events = self._bounded_integer(call, events_argument, 0, 32767, "poll events")
        revents = self._integer(call, revents_argument, "poll revents")
        if revents != 0:
            self._reject(
                call,
                SyzRejectionCategory.POLL_SHAPE,
                "poll revents must use the zero output default",
            )
        return PollFdEntry(fd_mode, fd_arg, events)

    def _fd_slot(self, call: SyzCall, argument: SyzArgument) -> int:
        if isinstance(argument, SyzResource):
            return self._live_resource_slot(call, argument)
        if isinstance(argument, SyzInteger) and argument.value == 0xFFFFFFFFFFFFFFFF:
            return self._reserve_invalid_slot(call)
        self._reject(
            call,
            SyzRejectionCategory.UNSUPPORTED_ARGUMENT,
            "fd must be a live resource or the canonical -1 literal",
        )

    def _live_resource_slot(self, call: SyzCall, argument: SyzArgument) -> int:
        if not isinstance(argument, SyzResource):
            self._reject(
                call,
                SyzRejectionCategory.UNSUPPORTED_ARGUMENT,
                "fd destination must be a resource",
            )
        if argument.divisor is not None or argument.addend is not None:
            self._reject(
                call,
                SyzRejectionCategory.RESOURCE_ARITHMETIC,
                argument.name,
            )
        binding = self.bindings.get(argument.name)
        if binding is None:
            self._reject(
                call,
                SyzRejectionCategory.UNDEFINED_RESOURCE,
                argument.name,
            )
        if (
            not self.slot_live[binding.slot]
            or self.slot_generation[binding.slot] != binding.generation
        ):
            self._reject(
                call,
                SyzRejectionCategory.USE_AFTER_CLOSE,
                argument.name,
            )
        return binding.slot

    def _allocate_live_slot(self, call: SyzCall) -> int:
        for slot in range(MAX_LOGICAL_SLOTS):
            if not self.slot_live[slot] and slot != self.invalid_slot:
                self.slot_live[slot] = True
                return slot
        self._reject(
            call,
            SyzRejectionCategory.SLOT_LIMIT,
            f"more than {MAX_LOGICAL_SLOTS} logical fd slots are required",
        )

    def _reserve_invalid_slot(self, call: SyzCall) -> int:
        if self.invalid_slot is not None:
            return self.invalid_slot
        for slot in reversed(range(MAX_LOGICAL_SLOTS)):
            if not self.slot_live[slot]:
                self.invalid_slot = slot
                return slot
        self._reject(
            call,
            SyzRejectionCategory.SLOT_LIMIT,
            "no logical slot remains for the invalid fd literal",
        )

    def _bind(self, call: SyzCall, name: str, slot: int) -> None:
        if name in self.bindings:
            self._reject(call, SyzRejectionCategory.DUPLICATE_RESULT, name)
        self.bindings[name] = _ResourceBinding(slot, self.slot_generation[slot])

    def _valid_pointer(
        self,
        call: SyzCall,
        argument: SyzArgument,
        call_index: int,
        size: int,
        name: str,
    ) -> SyzPointer:
        if not isinstance(argument, SyzPointer) or argument.value is None:
            self._reject(
                call,
                SyzRejectionCategory.POINTER_SHAPE,
                f"{name} must be an initialized pointer",
            )
        if argument.any_pointer:
            self._reject(
                call,
                SyzRejectionCategory.POINTER_SHAPE,
                f"{name} cannot use an ANY pointer",
            )
        if not argument.auto:
            assert argument.address is not None
            region_size = max(1, size, argument.region_size or 0)
            self._record_memory_region(
                call,
                argument.address,
                argument.address + region_size,
                call_index,
            )
        return argument

    def _record_memory_region(
        self,
        call: SyzCall,
        start: int,
        end: int,
        call_index: int,
    ) -> None:
        if end > 0x10000000000000000:
            self._reject(
                call,
                SyzRejectionCategory.POINTER_SHAPE,
                "anchored memory region overflows unsigned 64-bit address space",
            )
        for region in self.memory_regions:
            if region.call_index != call_index and start < region.end and region.start < end:
                self._reject(
                    call,
                    SyzRejectionCategory.MEMORY_OVERLAP,
                    f"anchored region overlaps line {region.line_number}",
                )
        self.memory_regions.append(_MemoryRegion(start, end, call_index, call.line_number))

    def _record_vector_regions(
        self,
        call: SyzCall,
        regions: Tuple[VectorMemoryRegion, ...],
        call_index: int,
    ) -> None:
        for vector_region in regions:
            for existing in self.memory_regions:
                if (
                    vector_region.start < existing.end
                    and existing.start < vector_region.end
                ):
                    self._reject(
                        call,
                        SyzRejectionCategory.MEMORY_OVERLAP,
                        f"anchored iovec region overlaps line {existing.line_number}",
                    )
            self.memory_regions.append(
                _MemoryRegion(
                    vector_region.start,
                    vector_region.end,
                    call_index,
                    call.line_number,
                )
            )

    def _buffer_data(self, call: SyzCall, argument: Optional[SyzArgument]) -> bytes:
        if not isinstance(argument, SyzString) or argument.base64_encoded:
            self._reject(
                call,
                SyzRejectionCategory.BUFFER_SHAPE,
                "buffer must use an ordinary serialized string",
            )
        return argument.effective_data()

    def _is_invalid_pointer(self, argument: SyzArgument) -> bool:
        return isinstance(argument, (SyzInteger, SyzNil))

    def _require_command(
        self,
        call: SyzCall,
        argument: SyzArgument,
        expected: int,
    ) -> None:
        actual = self._integer(call, argument, "command")
        if actual != expected:
            self._reject(
                call,
                SyzRejectionCategory.UNSUPPORTED_CONSTANT,
                f"command {actual} does not match required {expected}",
            )

    def _integer(self, call: SyzCall, argument: SyzArgument, name: str) -> int:
        if not isinstance(argument, SyzInteger):
            self._reject(
                call,
                SyzRejectionCategory.UNSUPPORTED_ARGUMENT,
                f"{name} must be an integer",
            )
        return argument.value

    def _bounded_integer(
        self,
        call: SyzCall,
        argument: SyzArgument,
        minimum: int,
        maximum: int,
        name: str,
    ) -> int:
        value = self._integer(call, argument, name)
        if value < minimum or value > maximum:
            self._reject(
                call,
                SyzRejectionCategory.UNSUPPORTED_CONSTANT,
                f"{name} {value} is outside {minimum}..{maximum}",
            )
        return value

    def _signed(
        self,
        call: SyzCall,
        argument: SyzArgument,
        bits: int,
        name: str,
    ) -> int:
        value = self._integer(call, argument, name)
        signed = _signed_value(value, bits)
        if value not in (signed, signed & 0xFFFFFFFFFFFFFFFF):
            self._reject(
                call,
                SyzRejectionCategory.UNSUPPORTED_CONSTANT,
                f"{name} does not fit int{bits}",
            )
        return signed

    def _require_arity(self, call: SyzCall, expected: int) -> None:
        if len(call.arguments) != expected:
            self._reject(
                call,
                SyzRejectionCategory.INVALID_ARITY,
                f"{call.name} has {len(call.arguments)} arguments, expected {expected}",
            )

    def _require_no_assignment(self, call: SyzCall) -> None:
        if call.assignment is not None:
            self._reject(
                call,
                SyzRejectionCategory.UNSUPPORTED_RESULT,
                f"{call.name} does not return a resource",
            )

    def _reject(
        self,
        call: SyzCall,
        category: SyzRejectionCategory,
        detail: str,
    ):
        raise SyzConversionError(call.line_number, category, detail)


def _signed_value(value: int, bits: int) -> int:
    mask = (1 << bits) - 1
    truncated = value & mask
    sign_bit = 1 << (bits - 1)
    return truncated - (1 << bits) if truncated & sign_bit else truncated

__all__ = [
    "ConversionResult", "IMPORTER_VERSION", "SUPPORTED_SYZKALLER_REVISION",
    "SyzConversionError", "SyzRejectionCategory", "convert_syz_program",
]
