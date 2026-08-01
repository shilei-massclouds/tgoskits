"""Typed syntax tree for the restricted syzkaller program importer."""

from dataclasses import dataclass
from typing import Optional, Tuple, Union


@dataclass(frozen=True)
class SyzInteger:
    value: int
    text: str


@dataclass(frozen=True)
class SyzResource:
    name: str
    divisor: Optional[int] = None
    addend: Optional[int] = None


@dataclass(frozen=True)
class SyzResultCapture:
    name: str
    value: "SyzArgument"


@dataclass(frozen=True)
class SyzPointer:
    auto: bool
    address: Optional[int]
    region_size: Optional[int]
    value: Optional["SyzArgument"]
    any_pointer: bool = False


@dataclass(frozen=True)
class SyzString:
    data: bytes
    declared_size: Optional[int]
    base64_encoded: bool = False

    def effective_data(self) -> bytes:
        if self.declared_size is None:
            return self.data
        if self.declared_size <= len(self.data):
            return self.data[: self.declared_size]
        return self.data + bytes(self.declared_size - len(self.data))


@dataclass(frozen=True)
class SyzStruct:
    fields: Tuple["SyzArgument", ...]


@dataclass(frozen=True)
class SyzArray:
    elements: Tuple["SyzArgument", ...]


@dataclass(frozen=True)
class SyzUnion:
    field: str
    value: Optional["SyzArgument"]


@dataclass(frozen=True)
class SyzNil:
    pass


@dataclass(frozen=True)
class SyzAuto:
    pass


SyzArgument = Union[
    SyzInteger,
    SyzResource,
    SyzResultCapture,
    SyzPointer,
    SyzString,
    SyzStruct,
    SyzArray,
    SyzUnion,
    SyzNil,
    SyzAuto,
]


@dataclass(frozen=True)
class SyzCallProperty:
    name: str
    value: Optional[int]


@dataclass(frozen=True)
class SyzCall:
    name: str
    arguments: Tuple[SyzArgument, ...]
    assignment: Optional[str]
    properties: Tuple[SyzCallProperty, ...]
    line_number: int


@dataclass(frozen=True)
class SyzProgram:
    calls: Tuple[SyzCall, ...]
