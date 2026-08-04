"""Bounded deterministic eventfd reduction with validation and final proofs."""

from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from reducer import (
    OperationOrigin,
    OriginDocument,
    ReductionCandidate,
    complexity_key,
    reduction_candidates,
    with_origins,
)
from scenario import ScenarioDocument


@dataclass(frozen=True)
class MinimizationResult:
    original: OriginDocument
    best: OriginDocument
    mode: str
    candidate_count: int
    accepted_count: int
    validation_passed: bool
    final_proofs: Tuple[bool, bool]


def minimize(
    document: ScenarioDocument,
    predicate: Callable[[OriginDocument], bool],
    *,
    max_candidates: int,
    required_origin: Optional[OperationOrigin] = None,
) -> MinimizationResult:
    if max_candidates < 0:
        raise ValueError("max_candidates must be nonnegative")
    original = with_origins(document)
    if not predicate(original):
        return MinimizationResult(original, original, "unstable", 0, 0, False, (False, False))
    best = original
    candidate_count = 0
    accepted_count = 0
    while candidate_count < max_candidates:
        accepted = None
        for candidate in reduction_candidates(best, required_origin=required_origin):
            if candidate_count >= max_candidates:
                break
            candidate_count += 1
            if predicate(candidate.document):
                accepted = candidate.document
                accepted_count += 1
                break
        if accepted is None:
            break
        best = accepted
    first_proof = predicate(best)
    second_proof = predicate(best) if first_proof else False
    if not first_proof or not second_proof:
        mode = "unstable"
    elif complexity_key(best) == complexity_key(original):
        mode = "already-minimal"
    elif candidate_count >= max_candidates:
        mode = "budget-limited"
    else:
        mode = "minimized"
    return MinimizationResult(
        original,
        best,
        mode,
        candidate_count,
        accepted_count,
        True,
        (first_proof, second_proof),
    )


__all__ = ["MinimizationResult", "minimize"]
