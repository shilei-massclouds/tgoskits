"""Resource lineage analysis for syzkaller vector-slice projection."""

from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Tuple

from syz_ast import (
    SyzArgument,
    SyzArray,
    SyzCall,
    SyzPointer,
    SyzProgram,
    SyzResource,
    SyzResultCapture,
    SyzStruct,
    SyzUnion,
)


_PIPE_CALLS = {"pipe", "pipe2"}
_DUP_REPLACEMENT_CALLS = {"dup2", "dup3"}


@dataclass(frozen=True)
class ResourceUse:
    resource: SyzResource
    family: Optional[int]
    description: Optional[int]
    live: bool
    slot_id: Optional[int]
    producer_index: Optional[int]


@dataclass(frozen=True)
class CallEvent:
    index: int
    call: SyzCall
    uses: Tuple[ResourceUse, ...]
    pipe_family: Optional[int]
    result_family: Optional[int]
    dup_families: Optional[Tuple[Optional[int], Optional[int]]]

    def touches_family(self, family: int) -> bool:
        return (
            self.pipe_family == family
            or self.result_family == family
            or any(resource.family == family for resource in self.uses)
        )


@dataclass(frozen=True)
class _Binding:
    slot_id: int
    generation: int
    original_family: Optional[int]
    original_description: Optional[int]
    producer_index: int


@dataclass
class _SlotState:
    generation: int
    live: bool
    family: Optional[int]
    description: Optional[int]


class ProgramResourceAnalysis:
    """Resolve resource uses against descriptor state before each source call."""

    def __init__(self, program: SyzProgram):
        self.bindings: Dict[str, _Binding] = {}
        self.slots: Dict[int, _SlotState] = {}
        self.next_slot = 0
        self.next_family = 0
        self.next_description = 0
        self.events = tuple(self._analyze(program))

    def _analyze(self, program: SyzProgram) -> Iterable[CallEvent]:
        for index, call in enumerate(program.calls):
            uses = tuple(self._snapshot(resource) for resource in _resources(call.arguments))
            pipe_family = None
            result_family = None
            dup_families = None
            if call.name in _PIPE_CALLS:
                pipe_family = self.next_family
                self.next_family += 1
                self._bind_pipe_outputs(call, index, pipe_family)
                result_family = pipe_family
            elif call.name == "dup":
                result_family = uses[0].family if uses else None
                self._apply_dup(call, index, uses)
            elif call.name in _DUP_REPLACEMENT_CALLS:
                source_family = uses[0].family if len(uses) > 0 else None
                destination_family = uses[1].family if len(uses) > 1 else None
                dup_families = (source_family, destination_family)
                result_family = self._apply_dup_replacement(call, index, uses)
            else:
                self._apply_close(call, uses)
                self._bind_external_results(call, index)
            yield CallEvent(
                index,
                call,
                uses,
                pipe_family,
                result_family,
                dup_families,
            )

    def _snapshot(self, resource: SyzResource) -> ResourceUse:
        binding = self.bindings.get(resource.name)
        if binding is None:
            return ResourceUse(resource, None, None, False, None, None)
        slot = self.slots[binding.slot_id]
        current = slot.generation == binding.generation
        family = slot.family if current else binding.original_family
        description = slot.description if current else binding.original_description
        return ResourceUse(
            resource,
            family,
            description,
            current and slot.live,
            binding.slot_id,
            binding.producer_index,
        )

    def _bind_pipe_outputs(self, call: SyzCall, index: int, family: int) -> None:
        if not call.arguments:
            return
        captures = _result_captures(call.arguments[0])
        for capture in captures[:2]:
            description = self.next_description
            self.next_description += 1
            self._new_binding(capture, family, description, index)

    def _apply_dup(
        self,
        call: SyzCall,
        index: int,
        uses: Tuple[ResourceUse, ...],
    ) -> None:
        if call.assignment is None:
            return
        source = uses[0] if uses else None
        family = source.family if source is not None and source.live else None
        description = source.description if source is not None and source.live else None
        self._new_binding(call.assignment, family, description, index)

    def _apply_dup_replacement(
        self,
        call: SyzCall,
        index: int,
        uses: Tuple[ResourceUse, ...],
    ) -> Optional[int]:
        if len(uses) < 2:
            self._bind_external_results(call, index)
            return None
        source, destination = uses[:2]
        if (
            source.live
            and destination.live
            and source.slot_id is not None
            and destination.slot_id is not None
            and source.slot_id != destination.slot_id
        ):
            destination_slot = self.slots[destination.slot_id]
            destination_slot.family = source.family
            destination_slot.description = source.description
        if call.assignment is not None and destination.slot_id is not None:
            slot = self.slots[destination.slot_id]
            self._bind_existing_slot(call.assignment, destination.slot_id, slot, index)
        return source.family if source.live else destination.family

    def _apply_close(
        self,
        call: SyzCall,
        uses: Tuple[ResourceUse, ...],
    ) -> None:
        if call.name != "close" or not uses:
            return
        resource = uses[0]
        if resource.live and resource.slot_id is not None:
            slot = self.slots[resource.slot_id]
            slot.live = False
            slot.generation += 1

    def _bind_external_results(self, call: SyzCall, index: int) -> None:
        names = list(_result_captures_from_arguments(call.arguments))
        if call.assignment is not None:
            names.append(call.assignment)
        for name in names:
            self._new_binding(name, None, self._external_description(), index)

    def _external_description(self) -> int:
        description = self.next_description
        self.next_description += 1
        return description

    def _new_binding(
        self,
        name: str,
        family: Optional[int],
        description: Optional[int],
        producer_index: int,
    ) -> None:
        if name in self.bindings:
            return
        slot_id = self.next_slot
        self.next_slot += 1
        slot = _SlotState(0, True, family, description)
        self.slots[slot_id] = slot
        self._bind_existing_slot(name, slot_id, slot, producer_index)

    def _bind_existing_slot(
        self,
        name: str,
        slot_id: int,
        slot: _SlotState,
        producer_index: int,
    ) -> None:
        if name in self.bindings:
            return
        self.bindings[name] = _Binding(
            slot_id,
            slot.generation,
            slot.family,
            slot.description,
            producer_index,
        )


def _resources(arguments: Iterable[SyzArgument]) -> Iterable[SyzResource]:
    for argument in arguments:
        if isinstance(argument, SyzResource):
            yield argument
        elif isinstance(argument, SyzResultCapture):
            yield from _resources((argument.value,))
        elif isinstance(argument, SyzPointer) and argument.value is not None:
            yield from _resources((argument.value,))
        elif isinstance(argument, SyzStruct):
            yield from _resources(argument.fields)
        elif isinstance(argument, SyzArray):
            yield from _resources(argument.elements)
        elif isinstance(argument, SyzUnion) and argument.value is not None:
            yield from _resources((argument.value,))


def _result_captures(argument: SyzArgument) -> Tuple[str, ...]:
    return tuple(_result_capture_names((argument,)))


def _result_captures_from_arguments(
    arguments: Iterable[SyzArgument],
) -> Iterable[str]:
    yield from _result_capture_names(arguments)


def _result_capture_names(arguments: Iterable[SyzArgument]) -> Iterable[str]:
    for argument in arguments:
        if isinstance(argument, SyzResultCapture):
            yield argument.name
            yield from _result_capture_names((argument.value,))
        elif isinstance(argument, SyzPointer) and argument.value is not None:
            yield from _result_capture_names((argument.value,))
        elif isinstance(argument, SyzStruct):
            yield from _result_capture_names(argument.fields)
        elif isinstance(argument, SyzArray):
            yield from _result_capture_names(argument.elements)
        elif isinstance(argument, SyzUnion) and argument.value is not None:
            yield from _result_capture_names((argument.value,))


__all__ = ["CallEvent", "ProgramResourceAnalysis", "ResourceUse"]
