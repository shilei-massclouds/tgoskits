"""Bounded adapter-owned reduction scheduling with final replay proofs."""

from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Tuple


@dataclass(frozen=True)
class MinimizationResult:
    value: object
    attempts: int
    status: str


def minimize(
    initial: object,
    candidates: Callable[[object], Iterable[object]],
    predicate: Callable[[object], bool],
    complexity: Callable[[object], tuple],
    maximum_attempts: int,
) -> MinimizationResult:
    if maximum_attempts < 0:
        raise ValueError("minimization budget must be non-negative")
    if not predicate(initial):
        raise ValueError("initial minimization input does not reproduce")
    current = initial
    attempts = 0
    changed = False
    while attempts < maximum_attempts:
        accepted: Optional[object] = None
        for candidate in candidates(current):
            if attempts >= maximum_attempts:
                break
            attempts += 1
            if complexity(candidate) >= complexity(current):
                continue
            if predicate(candidate):
                accepted = candidate
                break
        if accepted is None:
            break
        current = accepted
        changed = True
    if not predicate(current) or not predicate(current):
        raise RuntimeError("final minimized input is not stable across two replays")
    return MinimizationResult(
        current, attempts, "reduced" if changed else "already-minimal"
    )
