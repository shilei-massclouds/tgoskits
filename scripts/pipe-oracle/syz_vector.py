"""Pinned syzkaller iovec shapes that map exactly to ``pipe.ops`` v4."""

from dataclasses import dataclass
from typing import Optional, Sequence, Tuple, Union

from scenario import (
    IOVCNT_VALUES,
    MAX_IO_BYTES,
    MAX_IOV_SEGMENTS,
    IovBaseMode,
    IovMode,
    ReadvSegment,
    WritevSegment,
)
from syz_ast import (
    SyzArgument,
    SyzArray,
    SyzInteger,
    SyzNil,
    SyzPointer,
    SyzString,
    SyzStruct,
)


X86_64_IOVEC_BYTES = 16


class VectorShapeError(ValueError):
    """The pinned iovec cannot be represented by the bounded v4 IR."""


class VectorPayloadError(ValueError):
    """A writev segment does not have a uniform effective prefix."""


@dataclass(frozen=True)
class VectorMemoryRegion:
    start: int
    end: int


@dataclass(frozen=True)
class ReadvConversion:
    iov_mode: IovMode
    iovcnt: int
    segments: Tuple[ReadvSegment, ...]
    regions: Tuple[VectorMemoryRegion, ...]


@dataclass(frozen=True)
class WritevConversion:
    iov_mode: IovMode
    iovcnt: int
    segments: Tuple[WritevSegment, ...]
    regions: Tuple[VectorMemoryRegion, ...]


def convert_readv_arguments(
    pointer_argument: SyzArgument,
    count_argument: SyzArgument,
) -> ReadvConversion:
    """Convert the vector-specific readv arguments without fd state."""

    iov_mode, iovcnt, elements, outer_region = _vector_arguments(
        pointer_argument,
        count_argument,
    )
    segments = []
    regions = _initial_regions(outer_region)
    for element in elements:
        base, length = _segment_fields(element)
        base_mode, _data, region = _buffer(base, length)
        segments.append(ReadvSegment(base_mode, length))
        if region is not None:
            regions.append(region)
    _validate_total(segments)
    return ReadvConversion(iov_mode, iovcnt, tuple(segments), tuple(regions))


def convert_writev_arguments(
    pointer_argument: SyzArgument,
    count_argument: SyzArgument,
) -> WritevConversion:
    """Convert the vector-specific writev arguments without fd state."""

    iov_mode, iovcnt, elements, outer_region = _vector_arguments(
        pointer_argument,
        count_argument,
    )
    segments = []
    regions = _initial_regions(outer_region)
    for element in elements:
        base, length = _segment_fields(element)
        base_mode, data, region = _buffer(base, length)
        prefix = data[:length]
        if prefix and any(byte != prefix[0] for byte in prefix):
            raise VectorPayloadError(
                "positive writev segment prefix is not one repeated byte"
            )
        segments.append(
            WritevSegment(base_mode, length, prefix[0] if prefix else 0)
        )
        if region is not None:
            regions.append(region)
    _validate_total(segments)
    return WritevConversion(iov_mode, iovcnt, tuple(segments), tuple(regions))


def _vector_arguments(
    pointer_argument: SyzArgument,
    count_argument: SyzArgument,
) -> Tuple[
    IovMode,
    int,
    Tuple[SyzArgument, ...],
    Optional[VectorMemoryRegion],
]:
    iovcnt = _iovcnt(count_argument)
    if isinstance(pointer_argument, (SyzInteger, SyzNil)):
        return IovMode.INVALID, iovcnt, (), None
    if (
        not isinstance(pointer_argument, SyzPointer)
        or pointer_argument.value is None
        or pointer_argument.any_pointer
        or not isinstance(pointer_argument.value, SyzArray)
    ):
        raise VectorShapeError(
            "iovec must be an initialized ordinary array pointer"
        )
    expected = iovcnt if 0 <= iovcnt <= MAX_IOV_SEGMENTS else 0
    elements = pointer_argument.value.elements
    if len(elements) != expected:
        raise VectorShapeError(
            f"iovcnt {iovcnt} does not match array length {len(elements)}"
        )
    region = _anchored_region(
        pointer_argument,
        max(1, expected * X86_64_IOVEC_BYTES),
    )
    return IovMode.VALID, iovcnt, elements, region


def _iovcnt(argument: SyzArgument) -> int:
    if not isinstance(argument, SyzInteger):
        raise VectorShapeError("iovcnt must be an integer")
    iovcnt = _signed_64(argument.value)
    if iovcnt not in IOVCNT_VALUES:
        raise VectorShapeError(f"iovcnt {iovcnt} is outside the v4 boundary")
    return iovcnt


def _segment_fields(argument: SyzArgument) -> Tuple[SyzArgument, int]:
    if not isinstance(argument, SyzStruct) or len(argument.fields) != 2:
        raise VectorShapeError("iovec entry must be a two-field struct")
    base, length_argument = argument.fields
    if not isinstance(length_argument, SyzInteger):
        raise VectorShapeError("iovec length must be an integer")
    length = length_argument.value
    if length > MAX_IO_BYTES:
        raise VectorShapeError(f"iovec length {length} exceeds {MAX_IO_BYTES}")
    return base, length


def _buffer(
    argument: SyzArgument,
    length: int,
) -> Tuple[IovBaseMode, bytes, Optional[VectorMemoryRegion]]:
    if isinstance(argument, (SyzInteger, SyzNil)):
        return IovBaseMode.INVALID, b"", None
    if (
        not isinstance(argument, SyzPointer)
        or argument.value is None
        or argument.any_pointer
        or not isinstance(argument.value, SyzString)
        or argument.value.base64_encoded
    ):
        raise VectorShapeError(
            "iovec base must be invalid or an initialized ordinary string pointer"
        )
    data = argument.value.effective_data()
    if len(data) < length:
        raise VectorShapeError(
            f"iovec buffer has {len(data)} bytes for length {length}"
        )
    return IovBaseMode.VALID, data, _anchored_region(argument, max(1, length))


def _anchored_region(
    pointer: SyzPointer,
    size: int,
) -> Optional[VectorMemoryRegion]:
    if pointer.auto:
        return None
    assert pointer.address is not None
    region_size = max(size, pointer.region_size or 0)
    end = pointer.address + region_size
    if end > 0x10000000000000000:
        raise VectorShapeError(
            "anchored iovec region overflows unsigned 64-bit address space"
        )
    return VectorMemoryRegion(pointer.address, end)


def _initial_regions(
    region: Optional[VectorMemoryRegion],
) -> list[VectorMemoryRegion]:
    return [] if region is None else [region]


def _validate_total(
    segments: Sequence[Union[ReadvSegment, WritevSegment]],
) -> None:
    total = sum(segment.length for segment in segments)
    if total > MAX_IO_BYTES:
        raise VectorShapeError(
            f"iovec total length {total} exceeds {MAX_IO_BYTES}"
        )


def _signed_64(value: int) -> int:
    sign_bit = 1 << 63
    return value - (1 << 64) if value & sign_bit else value


__all__ = [
    "ReadvConversion",
    "VectorMemoryRegion",
    "VectorPayloadError",
    "VectorShapeError",
    "WritevConversion",
    "convert_readv_arguments",
    "convert_writev_arguments",
]
