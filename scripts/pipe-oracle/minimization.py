"""Pure minimization policy shared by coverage and semantic mismatch jobs."""

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, FrozenSet, Iterable, Optional, Set, Tuple

from fingerprint import MismatchFingerprint
from corpus import CorpusProvenance
from guest_result import GuestResultCategory
from reducer import (
    OperationOrigin,
    ReductionCandidate,
    ReductionInput,
    StructuredReducer,
)


class PredicateDecision(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    EXCEPTIONAL = "exceptional"


@dataclass(frozen=True)
class MinimizationItem:
    original_digest: str
    reduction_input: ReductionInput
    responsibility_regions: FrozenSet[str] = frozenset()
    critical_origin: Optional[OperationOrigin] = None
    provenance: CorpusProvenance = CorpusProvenance.generated()


@dataclass(frozen=True)
class ScheduledCandidate:
    item_index: int
    candidate: ReductionCandidate


class MinimizationSession:
    """Round-robin candidate scheduling under one shared QEMU budget."""

    def __init__(
        self,
        kind: str,
        items: Tuple[MinimizationItem, ...],
        *,
        max_qemu: int,
    ):
        if kind not in {"coverage", "mismatch"}:
            raise ValueError(f"unsupported minimization kind: {kind}")
        if not items:
            raise ValueError("minimization requires at least one item")
        if not isinstance(max_qemu, int) or isinstance(max_qemu, bool) or max_qemu < 0:
            raise ValueError("max_qemu must be nonnegative")
        if kind == "mismatch" and len(items) != 1:
            raise ValueError("mismatch minimization requires exactly one item")
        self.kind = kind
        self.items = items
        self.max_qemu = max_qemu
        self.candidate_qemu = 0
        self.schedule_cursor = 0
        self.budget_limited = False
        self.reducers = tuple(
            StructuredReducer(item.reduction_input, item.critical_origin)
            for item in items
        )

    def next_candidate(self) -> Optional[ScheduledCandidate]:
        if self.candidate_qemu >= self.max_qemu:
            self.budget_limited = True
            return None
        for offset in range(len(self.items)):
            item_index = (self.schedule_cursor + offset) % len(self.items)
            candidate = self.reducers[item_index].next_candidate()
            if candidate is None:
                continue
            self.schedule_cursor = (item_index + 1) % len(self.items)
            return ScheduledCandidate(item_index, candidate)
        return None

    def record_candidate(
        self,
        scheduled: ScheduledCandidate,
        *,
        accepted: bool,
    ) -> None:
        if self.candidate_qemu >= self.max_qemu:
            raise ValueError("candidate QEMU budget is exhausted")
        if not 0 <= scheduled.item_index < len(self.items):
            raise ValueError("scheduled minimization item is invalid")
        if accepted:
            self.reducers[scheduled.item_index].accept(scheduled.candidate)
        self.candidate_qemu += 1

    def best_inputs(self) -> Tuple[ReductionInput, ...]:
        return tuple(reducer.best for reducer in self.reducers)


def assign_coverage_responsibilities(
    representative_digests: Iterable[str],
    entry_regions: Dict[str, Set[str]],
    historical_regions: Dict[str, Set[str]],
    target_regions: Set[str],
) -> Dict[str, Set[str]]:
    representatives = tuple(sorted(set(representative_digests)))
    if not representatives:
        raise ValueError("coverage minimization requires representatives")
    if not target_regions:
        raise ValueError("coverage minimization requires target regions")
    if set(entry_regions) < set(representatives):
        raise ValueError("coverage attribution is missing representative regions")
    responsibilities = {
        digest: set(historical_regions.get(digest, set()))
        for digest in representatives
    }
    for region in sorted(target_regions):
        owners = [
            digest for digest in representatives if region in entry_regions[digest]
        ]
        if not owners:
            raise ValueError(f"coverage region has no representative: {region}")
        responsibilities[owners[0]].add(region)
    return responsibilities


def coverage_decision(
    category: GuestResultCategory,
    covered_regions: Set[str],
    responsibility_regions: Set[str],
) -> PredicateDecision:
    if category == GuestResultCategory.PASSED:
        return (
            PredicateDecision.ACCEPT
            if responsibility_regions <= covered_regions
            else PredicateDecision.REJECT
        )
    if category == GuestResultCategory.SEMANTIC_MISMATCH:
        return PredicateDecision.EXCEPTIONAL
    return PredicateDecision.EXCEPTIONAL


def mismatch_decision(
    category: GuestResultCategory,
    actual_fingerprint: Optional[MismatchFingerprint],
    expected_fingerprint: MismatchFingerprint,
) -> PredicateDecision:
    if category == GuestResultCategory.PASSED:
        return PredicateDecision.REJECT
    if category == GuestResultCategory.SEMANTIC_MISMATCH:
        return (
            PredicateDecision.ACCEPT
            if actual_fingerprint == expected_fingerprint
            else PredicateDecision.REJECT
        )
    return PredicateDecision.EXCEPTIONAL


def run_final_proof(predicate: Callable[[], bool]) -> bool:
    first = predicate()
    second = predicate()
    return first and second


__all__ = [
    "MinimizationItem",
    "MinimizationSession",
    "PredicateDecision",
    "ScheduledCandidate",
    "assign_coverage_responsibilities",
    "coverage_decision",
    "mismatch_decision",
    "run_final_proof",
]
