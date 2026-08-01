"""Deterministic structure-aware reduction for canonical pipe scenarios."""

import hashlib
from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from scenario import (
    Close,
    Dup,
    Dup2,
    Dup3,
    Fionread,
    GetFdFlags,
    GetSize,
    GetStatusFlags,
    IovBaseMode,
    IovMode,
    Operation,
    O_CLOEXEC,
    O_NONBLOCK,
    Pipe2,
    Poll,
    PollFdEntry,
    PollFdMode,
    PollMany,
    POLL_LITERAL_FDS,
    Read,
    ReadNull,
    Readv,
    Scenario,
    ScenarioCodecError,
    ScenarioDocument,
    SetFdFlags,
    ScenarioEntryLimitError,
    SetSize,
    SetStatusFlags,
    Write,
    WriteNull,
    Writev,
    serialize_document,
    validate_entry_limits,
)


@dataclass(frozen=True, order=True)
class OperationOrigin:
    scenario_index: int
    operation_index: int


@dataclass(frozen=True)
class ReductionInput:
    document: ScenarioDocument
    origins: Tuple[Tuple[OperationOrigin, ...], ...]

    @classmethod
    def initial(cls, document: ScenarioDocument) -> "ReductionInput":
        next_operation = 0
        scenario_origins = []
        for scenario_index, item in enumerate(document.scenarios):
            origins = []
            for _operation in item.operations:
                origins.append(OperationOrigin(scenario_index, next_operation))
                next_operation += 1
            scenario_origins.append(tuple(origins))
        return cls(document, tuple(scenario_origins))

    def __post_init__(self) -> None:
        if len(self.document.scenarios) != len(self.origins):
            raise ValueError("reduction origin scenarios do not match the document")
        if any(
            len(item.operations) != len(origins)
            for item, origins in zip(self.document.scenarios, self.origins)
        ):
            raise ValueError("reduction operation origins do not match the document")


@dataclass(frozen=True)
class ReductionCandidate:
    reduction_input: ReductionInput
    transform: str
    digest: str
    complexity: Tuple[int, ...]


class StructuredReducer:
    """Yield deterministic candidates and persist an exact algorithm cursor."""

    _STAGES = (
        "tail",
        "scenario-block",
        "operation-block",
        "operation-single",
        "dup-chain",
        "dense-slots",
        "parameters",
    )

    def __init__(
        self,
        reduction_input: ReductionInput,
        critical_origin: Optional[OperationOrigin] = None,
    ):
        self.best = reduction_input
        self.critical_origin = critical_origin
        self.stage_index = 0
        self.candidate_index = 0
        self.seen_digests = {self._digest(reduction_input.document)}

    @classmethod
    def restore(
        cls,
        reduction_input: ReductionInput,
        snapshot: Dict[str, Any],
    ) -> "StructuredReducer":
        expected_keys = {
            "stage_index",
            "candidate_index",
            "seen_digests",
            "critical_origin",
        }
        if not isinstance(snapshot, dict) or set(snapshot) != expected_keys:
            raise ValueError("invalid reducer snapshot keys")
        critical_metadata = snapshot["critical_origin"]
        if critical_metadata is None:
            critical_origin = None
        elif (
            isinstance(critical_metadata, list)
            and len(critical_metadata) == 2
            and all(_is_nonnegative_integer(value) for value in critical_metadata)
        ):
            critical_origin = OperationOrigin(*critical_metadata)
        else:
            raise ValueError("invalid reducer critical origin")
        reducer = cls(reduction_input, critical_origin)
        stage_index = snapshot["stage_index"]
        candidate_index = snapshot["candidate_index"]
        seen_digests = snapshot["seen_digests"]
        if (
            not _is_nonnegative_integer(stage_index)
            or stage_index > len(cls._STAGES)
            or not _is_nonnegative_integer(candidate_index)
            or not isinstance(seen_digests, list)
            or seen_digests != sorted(set(seen_digests))
            or not all(_is_digest(digest) for digest in seen_digests)
        ):
            raise ValueError("invalid reducer snapshot cursor")
        reducer.stage_index = stage_index
        reducer.candidate_index = candidate_index
        reducer.seen_digests = set(seen_digests)
        if reducer._digest(reduction_input.document) not in reducer.seen_digests:
            raise ValueError("reducer snapshot omits the current best digest")
        return reducer

    def snapshot(self) -> Dict[str, Any]:
        return {
            "stage_index": self.stage_index,
            "candidate_index": self.candidate_index,
            "seen_digests": sorted(self.seen_digests),
            "critical_origin": (
                None
                if self.critical_origin is None
                else [
                    self.critical_origin.scenario_index,
                    self.critical_origin.operation_index,
                ]
            ),
        }

    def next_candidate(self) -> Optional[ReductionCandidate]:
        while self.stage_index < len(self._STAGES):
            stage = self._STAGES[self.stage_index]
            transformations = tuple(self._stage_candidates(stage))
            while self.candidate_index < len(transformations):
                transform, candidate_input = transformations[self.candidate_index]
                self.candidate_index += 1
                candidate = self._validated_candidate(transform, candidate_input)
                if candidate is None or candidate.digest in self.seen_digests:
                    continue
                self.seen_digests.add(candidate.digest)
                return candidate
            self.stage_index += 1
            self.candidate_index = 0
        return None

    def accept(self, candidate: ReductionCandidate) -> None:
        current_key = complexity_key(self.best.document)
        if candidate.complexity >= current_key:
            raise ValueError("accepted reduction candidate is not strictly smaller")
        if candidate.digest not in self.seen_digests:
            raise ValueError("accepted reduction candidate was not yielded")
        self.best = candidate.reduction_input
        self.stage_index = 0
        self.candidate_index = 0

    def _stage_candidates(
        self,
        stage: str,
    ) -> Iterable[Tuple[str, ReductionInput]]:
        if stage == "tail":
            return _tail_candidates(self.best, self.critical_origin)
        if stage == "scenario-block":
            return _scenario_block_candidates(self.best, self.critical_origin)
        if stage == "operation-block":
            return _operation_block_candidates(self.best, self.critical_origin)
        if stage == "operation-single":
            return _operation_single_candidates(self.best, self.critical_origin)
        if stage == "dup-chain":
            return _dup_chain_candidates(self.best, self.critical_origin)
        if stage == "dense-slots":
            return _dense_slot_candidates(self.best)
        if stage == "parameters":
            return _parameter_candidates(self.best)
        raise AssertionError(f"unknown reducer stage: {stage}")

    def _validated_candidate(
        self,
        transform: str,
        candidate_input: ReductionInput,
    ) -> Optional[ReductionCandidate]:
        if self.critical_origin is not None and not _contains_origin(
            candidate_input,
            self.critical_origin,
        ):
            return None
        try:
            validate_entry_limits(candidate_input.document)
            encoded = serialize_document(candidate_input.document).encode("utf-8")
        except (ScenarioCodecError, ScenarioEntryLimitError, AssertionError):
            return None
        candidate_key = complexity_key(candidate_input.document)
        if candidate_key >= complexity_key(self.best.document):
            return None
        return ReductionCandidate(
            candidate_input,
            transform,
            hashlib.sha256(encoded).hexdigest(),
            candidate_key,
        )

    @staticmethod
    def _digest(document: ScenarioDocument) -> str:
        return hashlib.sha256(serialize_document(document).encode("utf-8")).hexdigest()


def complexity_key(document: ScenarioDocument) -> Tuple[int, ...]:
    operations = tuple(
        operation
        for scenario in document.scenarios
        for operation in scenario.operations
    )
    return (
        len(operations),
        len(document.scenarios),
        sum(sum(_operation_slots(operation)) for operation in operations),
        sum(_operation_parameter_cost(operation) for operation in operations),
        len(serialize_document(document).encode("utf-8")),
    )


def _tail_candidates(
    reduction_input: ReductionInput,
    critical_origin: Optional[OperationOrigin],
) -> Tuple[Tuple[str, ReductionInput], ...]:
    if critical_origin is None:
        return ()
    position = _find_origin(reduction_input, critical_origin)
    if position is None:
        raise ValueError("critical operation origin is absent from the current best")
    scenario_index, operation_index = position
    scenario = reduction_input.document.scenarios[scenario_index]
    if (
        operation_index + 1 == len(scenario.operations)
        and scenario_index + 1 == len(reduction_input.document.scenarios)
    ):
        return ()
    scenarios = list(reduction_input.document.scenarios[: scenario_index + 1])
    origins = list(reduction_input.origins[: scenario_index + 1])
    scenarios[-1] = Scenario(scenario.operations[: operation_index + 1])
    origins[-1] = origins[-1][: operation_index + 1]
    return ((
        "delete-tail-after-critical",
        _make_input(scenarios, origins, reduction_input.document.version),
    ),)


def _scenario_block_candidates(
    reduction_input: ReductionInput,
    critical_origin: Optional[OperationOrigin],
) -> Tuple[Tuple[str, ReductionInput], ...]:
    count = len(reduction_input.document.scenarios)
    candidates = []
    for width in _coarse_widths(count, include_one=True):
        for start in range(0, count - width + 1):
            if width == count:
                continue
            kept_indices = [
                index for index in range(count) if not start <= index < start + width
            ]
            candidate = _make_input(
                [reduction_input.document.scenarios[index] for index in kept_indices],
                [reduction_input.origins[index] for index in kept_indices],
                reduction_input.document.version,
            )
            if critical_origin is None or _contains_origin(candidate, critical_origin):
                candidates.append(
                    (f"delete-scenarios:{start}:{width}", candidate)
                )
    return tuple(candidates)


def _operation_block_candidates(
    reduction_input: ReductionInput,
    critical_origin: Optional[OperationOrigin],
) -> Tuple[Tuple[str, ReductionInput], ...]:
    candidates = []
    for scenario_index, scenario in enumerate(reduction_input.document.scenarios):
        count = len(scenario.operations)
        for width in _coarse_widths(count, include_one=False):
            for start in range(0, count - width + 1):
                if width == count:
                    continue
                candidate = _delete_operations(
                    reduction_input,
                    scenario_index,
                    start,
                    width,
                )
                if critical_origin is None or _contains_origin(candidate, critical_origin):
                    candidates.append(
                        (
                            f"delete-operations:{scenario_index}:{start}:{width}",
                            candidate,
                        )
                    )
    return tuple(candidates)


def _operation_single_candidates(
    reduction_input: ReductionInput,
    critical_origin: Optional[OperationOrigin],
) -> Tuple[Tuple[str, ReductionInput], ...]:
    candidates = []
    for scenario_index in reversed(range(len(reduction_input.document.scenarios))):
        scenario = reduction_input.document.scenarios[scenario_index]
        if len(scenario.operations) <= 1:
            continue
        for operation_index in reversed(range(len(scenario.operations))):
            if reduction_input.origins[scenario_index][operation_index] == critical_origin:
                continue
            candidates.append(
                (
                    f"delete-operation:{scenario_index}:{operation_index}",
                    _delete_operations(
                        reduction_input,
                        scenario_index,
                        operation_index,
                        1,
                    ),
                )
            )
    return tuple(candidates)


def _dup_chain_candidates(
    reduction_input: ReductionInput,
    critical_origin: Optional[OperationOrigin],
) -> Tuple[Tuple[str, ReductionInput], ...]:
    candidates = []
    for scenario_index, scenario in enumerate(reduction_input.document.scenarios):
        for operation_index, operation in enumerate(scenario.operations):
            if not isinstance(operation, (Dup, Dup2, Dup3)):
                continue
            if isinstance(operation, Dup3) and (
                operation.source_slot == operation.destination_slot
                or operation.flags & ~O_CLOEXEC
            ):
                continue
            if reduction_input.origins[scenario_index][operation_index] == critical_origin:
                continue
            rewritten = _remove_dup_and_redirect(
                reduction_input,
                scenario_index,
                operation_index,
                critical_origin,
            )
            if rewritten is not None:
                candidates.append(
                    (f"compress-dup:{scenario_index}:{operation_index}", rewritten)
                )
    return tuple(candidates)


def _dense_slot_candidates(
    reduction_input: ReductionInput,
) -> Tuple[Tuple[str, ReductionInput], ...]:
    used = sorted(
        {
            slot
            for scenario in reduction_input.document.scenarios
            for operation in scenario.operations
            for slot in _operation_slots(operation)
        }
    )
    mapping = {slot: index for index, slot in enumerate(used)}
    if all(slot == renamed for slot, renamed in mapping.items()):
        return ()
    scenarios = [
        Scenario(_replace_operation_slots(operation, mapping) for operation in scenario.operations)
        for scenario in reduction_input.document.scenarios
    ]
    return ((
        "dense-slot-rename",
        _make_input(
            scenarios,
            reduction_input.origins,
            reduction_input.document.version,
        ),
    ),)


def _parameter_candidates(
    reduction_input: ReductionInput,
) -> Tuple[Tuple[str, ReductionInput], ...]:
    candidates = []
    for scenario_index, scenario in enumerate(reduction_input.document.scenarios):
        for operation_index, operation in enumerate(scenario.operations):
            replacements = _operation_parameter_replacements(operation)
            for field_name, value, replacement in replacements:
                scenarios = list(reduction_input.document.scenarios)
                operations = list(scenario.operations)
                operations[operation_index] = replacement
                scenarios[scenario_index] = Scenario(operations)
                candidates.append(
                    (
                        f"shrink-{field_name}:{scenario_index}:{operation_index}:{value}",
                        _make_input(
                            scenarios,
                            reduction_input.origins,
                            reduction_input.document.version,
                        ),
                    )
                )
    return tuple(candidates)


def _remove_dup_and_redirect(
    reduction_input: ReductionInput,
    scenario_index: int,
    operation_index: int,
    critical_origin: Optional[OperationOrigin],
) -> Optional[ReductionInput]:
    scenario = reduction_input.document.scenarios[scenario_index]
    origins = reduction_input.origins[scenario_index]
    duplicate = scenario.operations[operation_index]
    assert isinstance(duplicate, (Dup, Dup2, Dup3))
    operations = list(scenario.operations[:operation_index])
    kept_origins = list(origins[:operation_index])
    redirecting = True
    for following, origin in zip(
        scenario.operations[operation_index + 1 :],
        origins[operation_index + 1 :],
    ):
        if redirecting and isinstance(following, Close) and following.slot == duplicate.destination_slot:
            if origin == critical_origin:
                return None
            redirecting = False
            continue
        if redirecting and _uses_slot_as_destination(following, duplicate.destination_slot):
            return None
        operations.append(
            _replace_operation_slots(
                following,
                {duplicate.destination_slot: duplicate.source_slot},
            )
            if redirecting
            else following
        )
        kept_origins.append(origin)
    if not operations:
        return None
    scenarios = list(reduction_input.document.scenarios)
    all_origins = list(reduction_input.origins)
    scenarios[scenario_index] = Scenario(operations)
    all_origins[scenario_index] = tuple(kept_origins)
    return _make_input(
        scenarios,
        all_origins,
        reduction_input.document.version,
    )


def _operation_parameter_replacements(
    operation: Operation,
) -> Tuple[Tuple[str, int, Operation], ...]:
    replacements = []
    if isinstance(operation, (Read, Write)):
        for value in _smaller_simple_values(
            operation.length,
            (0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096),
        ):
            replacements.append(("length", value, replace(operation, length=value)))
    if isinstance(operation, Write):
        for value in _smaller_simple_values(operation.byte, (0, 1, 65, 127, 255)):
            replacements.append(("byte", value, replace(operation, byte=value)))
    if isinstance(operation, (Readv, Writev)):
        replacements.extend(_vector_parameter_replacements(operation))
    if isinstance(operation, Poll):
        for value in _smaller_simple_values(operation.events, (0, 1, 2, 4, 8, 16, 32, 64)):
            replacements.append(("poll-mask", value, replace(operation, events=value)))
    if isinstance(operation, PollMany):
        replacements.extend(_poll_many_parameter_replacements(operation))
    if isinstance(operation, SetSize):
        for value in _smaller_simple_values(
            operation.size,
            (0, 1, 4096, 65536, 1048576),
        ):
            replacements.append(("pipe-size", value, replace(operation, size=value)))
    if isinstance(operation, Pipe2):
        for value in _smaller_simple_values(
            operation.flags,
            (0, O_NONBLOCK, O_CLOEXEC, O_NONBLOCK | O_CLOEXEC),
        ):
            replacements.append(("pipe2-flags", value, replace(operation, flags=value)))
    if isinstance(operation, SetStatusFlags):
        for value in _smaller_simple_values(operation.flags, (0, O_NONBLOCK)):
            replacements.append(("status-flags", value, replace(operation, flags=value)))
    if isinstance(operation, SetFdFlags):
        for value in _smaller_simple_values(operation.flags, (0, 1)):
            replacements.append(("fd-flags", value, replace(operation, flags=value)))
    if isinstance(operation, Dup3):
        for value in _smaller_simple_values(
            operation.flags,
            (0, O_NONBLOCK, O_CLOEXEC, O_NONBLOCK | O_CLOEXEC),
        ):
            replacements.append(("dup3-flags", value, replace(operation, flags=value)))
    return tuple(replacements)


def _vector_parameter_replacements(operation):
    replacements = []
    if operation.iovcnt != 0:
        replacements.append(
            (
                "iov-count",
                0,
                replace(operation, iovcnt=0, segments=()),
            )
        )
    if operation.iov_mode == IovMode.INVALID and operation.iovcnt in (-1, 0, 1025):
        replacements.append(
            (
                "iov-mode",
                int(IovMode.VALID),
                replace(operation, iov_mode=IovMode.VALID),
            )
        )
    for segment_index, segment in enumerate(operation.segments):
        if segment.base_mode == IovBaseMode.INVALID:
            segments = list(operation.segments)
            segments[segment_index] = replace(segment, base_mode=IovBaseMode.VALID)
            replacements.append(
                (
                    f"base-mode-{segment_index}",
                    int(IovBaseMode.VALID),
                    replace(operation, segments=tuple(segments)),
                )
            )
        for value in _smaller_simple_values(
            segment.length,
            (0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096),
        ):
            segments = list(operation.segments)
            segments[segment_index] = replace(segment, length=value)
            replacements.append(
                (
                    f"segment-length-{segment_index}",
                    value,
                    replace(operation, segments=tuple(segments)),
                )
            )
        if isinstance(operation, Writev):
            for value in _smaller_simple_values(segment.byte, (0, 1, 65, 127, 255)):
                segments = list(operation.segments)
                segments[segment_index] = replace(segment, byte=value)
                replacements.append(
                    (
                        f"segment-byte-{segment_index}",
                        value,
                        replace(operation, segments=tuple(segments)),
                    )
                )
    if operation.iov_mode == IovMode.VALID and operation.iovcnt > 1:
        for count in range(operation.iovcnt - 1, 0, -1):
            replacements.append(
                (
                    "iov-count",
                    count,
                    replace(
                        operation,
                        iovcnt=count,
                        segments=operation.segments[:count],
                    ),
                )
            )
    return tuple(replacements)


def _poll_many_parameter_replacements(operation):
    replacements = []
    for entry_index, entry in enumerate(operation.entries):
        entries = list(operation.entries)
        del entries[entry_index]
        replacements.append(
            (
                f"poll-entry-delete-{entry_index}",
                entry_index,
                replace(operation, entries=tuple(entries)),
            )
        )
        if entry.fd_mode == PollFdMode.LITERAL:
            entries = list(operation.entries)
            entries[entry_index] = PollFdEntry(PollFdMode.SLOT, 0, entry.events)
            replacements.append(
                (
                    f"poll-fd-mode-{entry_index}",
                    int(PollFdMode.SLOT),
                    replace(operation, entries=tuple(entries)),
                )
            )
            for value in POLL_LITERAL_FDS:
                if abs(value) >= abs(entry.fd_arg):
                    continue
                entries = list(operation.entries)
                entries[entry_index] = replace(entry, fd_arg=value)
                replacements.append(
                    (
                        f"poll-fd-arg-{entry_index}",
                        value,
                        replace(operation, entries=tuple(entries)),
                    )
                )
        else:
            for value in _smaller_simple_values(entry.fd_arg, (0, 1, 2, 3)):
                entries = list(operation.entries)
                entries[entry_index] = replace(entry, fd_arg=value)
                replacements.append(
                    (
                        f"poll-fd-arg-{entry_index}",
                        value,
                        replace(operation, entries=tuple(entries)),
                    )
                )
        for value in _smaller_simple_values(
            entry.events,
            (0, 1, 2, 4, 8, 16, 32, 64),
        ):
            entries = list(operation.entries)
            entries[entry_index] = replace(entry, events=value)
            replacements.append(
                (
                    f"poll-mask-{entry_index}",
                    value,
                    replace(operation, entries=tuple(entries)),
                )
            )

    ordered_entries = tuple(sorted(operation.entries, key=_poll_entry_sort_key))
    if ordered_entries != operation.entries:
        replacements.append(
            (
                "poll-entry-order",
                0,
                replace(operation, entries=ordered_entries),
            )
        )
    return replacements


def _delete_operations(
    reduction_input: ReductionInput,
    scenario_index: int,
    start: int,
    width: int,
) -> ReductionInput:
    scenarios = list(reduction_input.document.scenarios)
    origins = list(reduction_input.origins)
    scenario = scenarios[scenario_index]
    scenarios[scenario_index] = Scenario(
        scenario.operations[:start] + scenario.operations[start + width :]
    )
    origins[scenario_index] = (
        origins[scenario_index][:start] + origins[scenario_index][start + width :]
    )
    return _make_input(
        scenarios,
        origins,
        reduction_input.document.version,
    )


def _make_input(
    scenarios: Sequence[Scenario],
    origins: Sequence[Sequence[OperationOrigin]],
    version: int,
) -> ReductionInput:
    return ReductionInput(
        ScenarioDocument(scenarios, version=version),
        tuple(tuple(item) for item in origins),
    )


def _replace_operation_slots(
    operation: Operation,
    mapping: Dict[int, int],
) -> Operation:
    rename = lambda slot: mapping.get(slot, slot)
    if isinstance(operation, Pipe2):
        return Pipe2(
            rename(operation.read_slot),
            rename(operation.write_slot),
            operation.flags,
        )
    if isinstance(
        operation,
        (
            Read,
            ReadNull,
            Write,
            WriteNull,
            Readv,
            Writev,
            Close,
            Poll,
            SetSize,
            GetSize,
            Fionread,
            GetStatusFlags,
            SetStatusFlags,
            GetFdFlags,
            SetFdFlags,
        ),
    ):
        return replace(operation, slot=rename(operation.slot))
    if isinstance(operation, PollMany):
        return replace(
            operation,
            entries=tuple(
                replace(entry, fd_arg=rename(entry.fd_arg))
                if entry.fd_mode == PollFdMode.SLOT
                else entry
                for entry in operation.entries
            ),
        )
    if isinstance(operation, (Dup, Dup2, Dup3)):
        return replace(
            operation,
            source_slot=rename(operation.source_slot),
            destination_slot=rename(operation.destination_slot),
        )
    raise TypeError(f"unsupported operation type: {type(operation).__name__}")


def _operation_slots(operation: Operation) -> Tuple[int, ...]:
    if isinstance(operation, Pipe2):
        return operation.read_slot, operation.write_slot
    if isinstance(operation, (Dup, Dup2, Dup3)):
        return operation.source_slot, operation.destination_slot
    if isinstance(
        operation,
        (
            Read,
            ReadNull,
            Write,
            WriteNull,
            Readv,
            Writev,
            Close,
            Poll,
            SetSize,
            GetSize,
            Fionread,
            GetStatusFlags,
            SetStatusFlags,
            GetFdFlags,
            SetFdFlags,
        ),
    ):
        return (operation.slot,)
    if isinstance(operation, PollMany):
        return tuple(
            entry.fd_arg
            for entry in operation.entries
            if entry.fd_mode == PollFdMode.SLOT
        )
    raise TypeError(f"unsupported operation type: {type(operation).__name__}")


def _operation_parameter_cost(operation: Operation) -> int:
    if isinstance(operation, Read):
        return operation.length
    if isinstance(operation, Write):
        return operation.length + operation.byte
    if isinstance(operation, (Readv, Writev)):
        segment_cost = sum(
            int(segment.base_mode)
            + segment.length
            + (segment.byte if isinstance(operation, Writev) else 0)
            for segment in operation.segments
        )
        return (
            int(operation.iov_mode)
            + abs(operation.iovcnt)
            + len(operation.segments)
            + segment_cost
        )
    if isinstance(operation, Poll):
        return operation.events
    if isinstance(operation, PollMany):
        return (
            sum(_poll_entry_cost(entry) for entry in operation.entries)
            + _poll_entry_order_cost(operation.entries)
        )
    if isinstance(operation, SetSize):
        return operation.size
    if isinstance(operation, (Pipe2, SetStatusFlags, SetFdFlags, Dup3)):
        return operation.flags
    return 0


def _poll_entry_cost(entry: PollFdEntry) -> int:
    return 1 + int(entry.fd_mode) + abs(entry.fd_arg) + entry.events


def _poll_entry_sort_key(entry: PollFdEntry) -> Tuple[int, int, int]:
    return int(entry.fd_mode), entry.fd_arg, entry.events


def _poll_entry_order_cost(entries: Sequence[PollFdEntry]) -> int:
    keys = tuple(_poll_entry_sort_key(entry) for entry in entries)
    return sum(
        left > right
        for left_index, left in enumerate(keys)
        for right in keys[left_index + 1 :]
    )


def _uses_slot_as_destination(operation: Operation, slot: int) -> bool:
    return (
        isinstance(operation, Pipe2)
        and slot in (operation.read_slot, operation.write_slot)
    ) or (
        isinstance(operation, (Dup, Dup2, Dup3))
        and operation.destination_slot == slot
    )


def _find_origin(
    reduction_input: ReductionInput,
    origin: OperationOrigin,
) -> Optional[Tuple[int, int]]:
    for scenario_index, origins in enumerate(reduction_input.origins):
        for operation_index, candidate in enumerate(origins):
            if candidate == origin:
                return scenario_index, operation_index
    return None


def _contains_origin(reduction_input: ReductionInput, origin: OperationOrigin) -> bool:
    return _find_origin(reduction_input, origin) is not None


def _coarse_widths(count: int, *, include_one: bool) -> Tuple[int, ...]:
    if count <= 1:
        return ()
    widths = []
    width = max(1, count // 2)
    minimum = 1 if include_one else 2
    while width >= minimum:
        if width not in widths:
            widths.append(width)
        if width == 1:
            break
        width //= 2
    return tuple(widths)


def _smaller_simple_values(current: int, values: Iterable[int]) -> Tuple[int, ...]:
    return tuple(value for value in values if value < current)


def _is_nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


__all__ = [
    "OperationOrigin",
    "ReductionCandidate",
    "ReductionInput",
    "StructuredReducer",
    "complexity_key",
]
