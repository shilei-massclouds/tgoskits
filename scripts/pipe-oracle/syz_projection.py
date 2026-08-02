"""Auditable resource-closed vector projection for mixed syzkaller programs."""

from dataclasses import dataclass, replace
from typing import Dict, Iterable, List, Optional, Tuple

from scenario import (
    CORPUS_VERSION,
    IovMode,
    Scenario,
    ScenarioDocument,
    canonical_digest,
    serialize_document,
    validate_entry_limits,
)
from syz_ast import (
    SyzArgument,
    SyzCall,
    SyzInteger,
    SyzPointer,
    SyzProgram,
    SyzResource,
    SyzResultCapture,
    SyzStruct,
)
from syz_converter import (
    SyzConversionError,
    convert_syz_program,
)
from syz_vector import (
    VectorPayloadError,
    VectorShapeError,
    convert_readv_arguments,
    convert_writev_arguments,
)
from syz_projection_resources import CallEvent, ProgramResourceAnalysis


PROJECTED_IMPORTER_VERSION = "3"
O_NONBLOCK = 2048
O_CLOEXEC = 524288
F_SETFL = 4
MAX_PROJECTED_SCENARIOS = 4

_PIPE_CALLS = {"pipe", "pipe2"}
_VECTOR_CALLS = {"readv", "writev"}
_DUP_REPLACEMENT_CALLS = {"dup2", "dup3"}
_LOSSLESS_CALLS = {
    "pipe",
    "pipe2",
    "read",
    "write",
    "readv",
    "writev",
    "close",
    "dup",
    "dup2",
    "dup3",
    "fcntl$getflags",
    "fcntl$setflags",
    "fcntl$setstatus",
    "fcntl$setpipe",
    "ioctl$int_out",
    "poll",
}


@dataclass(frozen=True)
class ProjectionOutcome:
    document: Optional[ScenarioDocument]
    operation_log: Tuple[Dict[str, object], ...]
    diagnostics: Dict[str, object]
    rejection_category: Optional[str]
    rejection_detail: Optional[str]


@dataclass(frozen=True)
class _ProjectedCall:
    call: SyzCall
    source_line: Optional[int]
    source_name: str
    origin: str
    repair_reasons: Tuple[str, ...] = ()
    before_line: Optional[int] = None


@dataclass(frozen=True)
class _TargetSuccess:
    scenario: Scenario
    operation_log: Tuple[Dict[str, object], ...]
    diagnostic: Dict[str, object]
    scenario_digest: str


class _TargetBarrier(ValueError):
    def __init__(self, category: str, detail: str):
        self.category = category
        self.detail = detail
        super().__init__(f"{category}: {detail}")


def project_vector_slices(
    program: SyzProgram,
    lossless_error: SyzConversionError,
) -> ProjectionOutcome:
    """Project resource-closed pipe scenarios for each vector target."""

    analysis = ProgramResourceAnalysis(program)
    target_events = tuple(
        event for event in analysis.events if event.call.name in _VECTOR_CALLS
    )
    lossless_rejection = _conversion_rejection(lossless_error)
    if not target_events:
        diagnostics = {
            "attempted": True,
            "lossless_rejection": lossless_rejection,
            "targets": [],
        }
        return ProjectionOutcome(
            None,
            (),
            diagnostics,
            "projection-no-vector-target",
            "program contains no readv/writev target",
        )

    diagnostics = []
    unique_scenarios: List[_TargetSuccess] = []
    scenario_digests = set()
    for target_index, event in enumerate(target_events):
        result = _project_target(program, analysis, event, target_index)
        diagnostic = result.diagnostic
        if diagnostic["status"] == "rejected":
            diagnostics.append(diagnostic)
            continue
        if result.scenario_digest in scenario_digests:
            diagnostic["status"] = "duplicate"
        else:
            scenario_digests.add(result.scenario_digest)
            unique_scenarios.append(result)
        diagnostics.append(diagnostic)

    projection = {
        "attempted": True,
        "lossless_rejection": lossless_rejection,
        "targets": diagnostics,
    }
    if not unique_scenarios:
        return ProjectionOutcome(
            None,
            (),
            projection,
            "projection-no-accepted-target",
            "every readv/writev target was rejected",
        )
    if len(unique_scenarios) > MAX_PROJECTED_SCENARIOS:
        return ProjectionOutcome(
            None,
            (),
            projection,
            "projection-entry-limit",
            f"{len(unique_scenarios)} distinct scenarios exceed "
            f"the {MAX_PROJECTED_SCENARIOS}-scenario limit",
        )

    document = ScenarioDocument(
        (result.scenario for result in unique_scenarios),
        version=CORPUS_VERSION,
    )
    try:
        validate_entry_limits(document)
        serialize_document(document)
    except ValueError as error:
        return ProjectionOutcome(
            None,
            (),
            projection,
            "projection-entry-limit",
            str(error),
        )
    operation_log = tuple(
        {
            **operation,
            "scenario": scenario_index,
        }
        for scenario_index, result in enumerate(unique_scenarios)
        for operation in result.operation_log
    )
    return ProjectionOutcome(document, operation_log, projection, None, None)


def empty_projection_diagnostics() -> Dict[str, object]:
    """Return the stable v3 diagnostic for an input that was not projected."""

    return {
        "attempted": False,
        "lossless_rejection": None,
        "targets": [],
    }


def projection_summary(inputs: Iterable[Dict[str, object]]) -> Dict[str, object]:
    """Aggregate path-independent projection decisions for report schema v3."""

    conversions: Dict[str, int] = {}
    target_status = {"accepted": 0, "duplicate": 0, "rejected": 0}
    target_rejections: Dict[str, int] = {}
    transformations = {"retained": 0, "dropped": 0, "synthesized": 0}
    for input_report in inputs:
        kind = input_report.get("conversion_kind")
        if isinstance(kind, str):
            conversions[kind] = conversions.get(kind, 0) + 1
        projection = input_report.get("projection")
        if not isinstance(projection, dict):
            continue
        for target in projection.get("targets", []):
            status = target["status"]
            target_status[status] += 1
            category = target.get("rejection_category")
            if isinstance(category, str):
                target_rejections[category] = target_rejections.get(category, 0) + 1
            transformations["retained"] += len(target["retained_calls"])
            transformations["dropped"] += len(target["dropped_calls"])
            transformations["synthesized"] += len(target["synthesized_calls"])
    return {
        "conversion_kinds": dict(sorted(conversions.items())),
        "projection_targets": target_status,
        "projection_target_rejections": dict(sorted(target_rejections.items())),
        "projection_transformations": transformations,
    }


def _project_target(
    program: SyzProgram,
    analysis: ProgramResourceAnalysis,
    target_event: CallEvent,
    target_index: int,
) -> _TargetSuccess:
    base = _target_diagnostic(target_event, target_index)
    try:
        family = _target_family(target_event)
        retained_events = _selected_events(analysis, target_event, family)
        _check_barriers(retained_events, target_event, family)
        projected_calls = _repair_calls(retained_events, target_event, family)
        conversion = convert_syz_program(
            SyzProgram(tuple(projected.call for projected in projected_calls))
        )
        diagnostic, operation_log = _successful_diagnostic(
            program,
            target_event,
            base,
            retained_events,
            projected_calls,
            conversion.operation_log,
        )
        digest = canonical_digest(conversion.document)
        diagnostic["canonical_scenario_digest"] = digest
        return _TargetSuccess(
            conversion.document.scenarios[0],
            operation_log,
            diagnostic,
            digest,
        )
    except _TargetBarrier as error:
        retained = locals().get("retained_events", ())
        diagnostic = _rejected_diagnostic(
            program,
            target_event,
            base,
            error.category,
            error.detail,
            retained,
        )
    except SyzConversionError as error:
        retained = locals().get("retained_events", ())
        diagnostic = _rejected_diagnostic(
            program,
            target_event,
            base,
            error.category.value,
            error.detail,
            retained,
        )
    return _TargetSuccess(Scenario(()), (), diagnostic, "")


def _target_family(target_event: CallEvent) -> int:
    call = target_event.call
    if not call.arguments or not isinstance(call.arguments[0], SyzResource):
        raise _TargetBarrier(
            "unrelated-vector",
            "vector fd is not a pipe-backed resource",
        )
    use = target_event.uses[0]
    if use.resource.divisor is not None or use.resource.addend is not None:
        if use.family is not None:
            raise _TargetBarrier(
                "resource-arithmetic",
                f"vector fd {use.resource.name} uses resource arithmetic",
            )
        raise _TargetBarrier(
            "unrelated-vector",
            "vector fd arithmetic does not resolve to a pipe",
        )
    if use.slot_id is None:
        raise _TargetBarrier("undefined-resource", use.resource.name)
    if use.family is None:
        raise _TargetBarrier(
            "unrelated-vector",
            f"vector fd {use.resource.name} does not originate from pipe/pipe2",
        )
    if not use.live:
        raise _TargetBarrier("use-after-close", use.resource.name)
    return use.family


def _selected_events(
    analysis: ProgramResourceAnalysis,
    target_event: CallEvent,
    family: int,
) -> Tuple[CallEvent, ...]:
    return tuple(
        event
        for event in analysis.events[: target_event.index + 1]
        if event.touches_family(family)
    )


def _check_barriers(
    retained_events: Tuple[CallEvent, ...],
    target_event: CallEvent,
    family: int,
) -> None:
    for event in retained_events:
        call = event.call
        if call.properties:
            raise _TargetBarrier(
                "call-properties",
                f"line {call.line_number} {call.name} has call properties",
            )
        for use in event.uses:
            if use.family == family and (
                use.resource.divisor is not None or use.resource.addend is not None
            ):
                raise _TargetBarrier(
                    "resource-arithmetic",
                    f"line {call.line_number} uses arithmetic on {use.resource.name}",
                )
        if call.name.startswith("syz_") or call.name not in _LOSSLESS_CALLS:
            raise _TargetBarrier(
                "unsupported-resource-call",
                f"line {call.line_number} {call.name} references the selected pipe",
            )
        if call.name in _DUP_REPLACEMENT_CALLS and event.dup_families is not None:
            source_family, destination_family = event.dup_families
            if family in (source_family, destination_family) and (
                source_family != family or destination_family != family
            ):
                raise _TargetBarrier(
                    "external-dup-resource",
                    f"line {call.line_number} {call.name} crosses a resource family",
                )
    if target_event not in retained_events:
        raise AssertionError("selected vector target was not retained")


def _repair_calls(
    retained_events: Tuple[CallEvent, ...],
    target_event: CallEvent,
    family: int,
) -> Tuple[_ProjectedCall, ...]:
    projected = []
    nonblocking: Dict[int, bool] = {}
    for event in retained_events:
        call = event.call
        repairs: Tuple[str, ...] = ()
        if call.name in _PIPE_CALLS and event.pipe_family == family:
            call, repairs = _repair_pipe(call)
        description = _fd_description(event)
        if (
            description is not None
            and not nonblocking.get(description, True)
            and _is_positive_io(call)
        ):
            restore = SyzCall(
                "fcntl$setstatus",
                (
                    call.arguments[0],
                    SyzInteger(F_SETFL, str(F_SETFL)),
                    SyzInteger(O_NONBLOCK, str(O_NONBLOCK)),
                ),
                None,
                (),
                call.line_number,
            )
            projected.append(
                _ProjectedCall(
                    restore,
                    None,
                    restore.name,
                    "synthesized",
                    before_line=call.line_number,
                )
            )
            nonblocking[description] = True
        projected.append(
            _ProjectedCall(
                call,
                call.line_number,
                event.call.name,
                "source",
                repairs,
            )
        )
        if call.name == "fcntl$setstatus" and description is not None:
            flags = _integer_argument(call, 2)
            if flags is not None:
                nonblocking[description] = bool(flags & O_NONBLOCK)
        if event is target_event:
            break
    return tuple(projected)


def _repair_pipe(call: SyzCall) -> Tuple[SyzCall, Tuple[str, ...]]:
    if not call.arguments:
        raise _TargetBarrier(
            "invalid-arity",
            f"line {call.line_number} {call.name} lacks a pipefd argument",
        )
    pointer, changed = _zero_pipe_output(call.arguments[0])
    if call.name == "pipe":
        flags = O_NONBLOCK
        normalized = True
    else:
        if len(call.arguments) < 2 or not isinstance(call.arguments[1], SyzInteger):
            raise _TargetBarrier(
                "unsupported-argument",
                f"line {call.line_number} pipe2 flags are not an integer",
            )
        original_flags = call.arguments[1].value
        flags = O_NONBLOCK | (original_flags & O_CLOEXEC)
        normalized = flags != original_flags
    repaired = SyzCall(
        "pipe2",
        (pointer, SyzInteger(flags, str(flags))),
        call.assignment,
        call.properties,
        call.line_number,
    )
    reasons = []
    if call.name == "pipe" or normalized:
        reasons.append("normalize-pipe-flags")
    if changed:
        reasons.append("zero-pipe-output")
    return repaired, tuple(reasons)


def _zero_pipe_output(argument: SyzArgument) -> Tuple[SyzArgument, bool]:
    if (
        not isinstance(argument, SyzPointer)
        or not isinstance(argument.value, SyzStruct)
        or len(argument.value.fields) != 2
    ):
        return argument, False
    fields = []
    changed = False
    for field in argument.value.fields:
        if isinstance(field, SyzResultCapture):
            zero = SyzInteger(0, "0")
            changed |= field.value != zero
            fields.append(replace(field, value=zero))
        else:
            zero = SyzInteger(0, "0")
            changed |= field != zero
            fields.append(zero)
    return (
        replace(argument, value=replace(argument.value, fields=tuple(fields))),
        changed,
    )


def _fd_description(event: CallEvent) -> Optional[int]:
    if not event.call.arguments or not isinstance(event.call.arguments[0], SyzResource):
        return None
    return event.uses[0].description if event.uses else None


def _is_positive_io(call: SyzCall) -> bool:
    if call.name in {"read", "write"}:
        count = _integer_argument(call, 2)
        return count is not None and count > 0
    if call.name not in _VECTOR_CALLS or len(call.arguments) != 3:
        return False
    try:
        conversion = (
            convert_readv_arguments(call.arguments[1], call.arguments[2])
            if call.name == "readv"
            else convert_writev_arguments(call.arguments[1], call.arguments[2])
        )
    except (VectorShapeError, VectorPayloadError):
        return False
    return (
        conversion.iov_mode == IovMode.VALID
        and conversion.iovcnt in range(1, 5)
        and sum(segment.length for segment in conversion.segments) > 0
    )


def _successful_diagnostic(
    program: SyzProgram,
    target_event: CallEvent,
    base: Dict[str, object],
    retained_events: Tuple[CallEvent, ...],
    projected_calls: Tuple[_ProjectedCall, ...],
    operation_log: Tuple[Dict[str, object], ...],
) -> Tuple[Dict[str, object], Tuple[Dict[str, object], ...]]:
    if len(projected_calls) != len(operation_log):
        raise _TargetBarrier(
            "conversion-log-shape",
            "projected calls and converted operations have different lengths",
        )
    retained_indices = {event.index for event in retained_events}
    mapped_retained = []
    synthesized = []
    mapped_operations = []
    for projected, operation in zip(projected_calls, operation_log):
        mapping = {
            "line": projected.source_line,
            "origin": projected.origin,
            "pipe_operation": operation["pipe_operation"],
            "syz_call": projected.source_name,
        }
        mapped_operations.append(mapping)
        if projected.origin == "source":
            mapped_retained.append(
                {
                    "line": projected.source_line,
                    "pipe_operation": operation["pipe_operation"],
                    "repair_reasons": list(projected.repair_reasons),
                    "syz_call": projected.source_name,
                }
            )
        else:
            synthesized.append(
                {
                    "before_line": projected.before_line,
                    "pipe_operation": operation["pipe_operation"],
                    "reason": "restore-nonblocking",
                    "syz_call": projected.source_name,
                }
            )
    diagnostic = {
        **base,
        "status": "accepted",
        "rejection_category": None,
        "rejection_detail": None,
        "retained_calls": mapped_retained,
        "dropped_calls": _dropped_calls(program, target_event, retained_indices),
        "synthesized_calls": synthesized,
    }
    return diagnostic, tuple(mapped_operations)


def _rejected_diagnostic(
    program: SyzProgram,
    target_event: CallEvent,
    base: Dict[str, object],
    category: str,
    detail: str,
    retained_events: Tuple[CallEvent, ...],
) -> Dict[str, object]:
    retained_indices = {event.index for event in retained_events}
    return {
        **base,
        "status": "rejected",
        "rejection_category": category,
        "rejection_detail": detail,
        "retained_calls": [
            {
                "line": event.call.line_number,
                "pipe_operation": None,
                "repair_reasons": [],
                "syz_call": event.call.name,
            }
            for event in retained_events
        ],
        "dropped_calls": _dropped_calls(program, target_event, retained_indices),
        "synthesized_calls": [],
    }


def _target_diagnostic(event: CallEvent, target_index: int) -> Dict[str, object]:
    return {
        "target_index": target_index,
        "line": event.call.line_number,
        "syz_call": event.call.name,
        "canonical_scenario_digest": None,
    }


def _dropped_calls(
    program: SyzProgram,
    target_event: CallEvent,
    retained_indices: set[int],
) -> List[Dict[str, object]]:
    dropped = []
    for index, call in enumerate(program.calls):
        if index in retained_indices:
            continue
        dropped.append(
            {
                "line": call.line_number,
                "reason": "after-target" if index > target_event.index else "unrelated-call",
                "syz_call": call.name,
            }
        )
    return dropped


def _conversion_rejection(error: SyzConversionError) -> Dict[str, object]:
    return {
        "line": error.line_number,
        "category": error.category.value,
        "detail": error.detail,
    }


def _integer_argument(call: SyzCall, index: int) -> Optional[int]:
    if index >= len(call.arguments) or not isinstance(call.arguments[index], SyzInteger):
        return None
    return call.arguments[index].value


__all__ = [
    "PROJECTED_IMPORTER_VERSION",
    "ProjectionOutcome",
    "empty_projection_diagnostics",
    "project_vector_slices",
    "projection_summary",
]
