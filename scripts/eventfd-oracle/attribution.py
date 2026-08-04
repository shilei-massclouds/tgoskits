"""Deterministic exact-coverage attribution for eventfd batches."""

from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Set, Tuple


@dataclass(frozen=True)
class AttributionResult:
    target_regions: Tuple[str, ...]
    entry_regions: Dict[str, Tuple[str, ...]]
    representatives: Tuple[str, ...]


def attribute_regions(
    entry_regions: Mapping[str, Iterable[str]], target_regions: Iterable[str]
) -> AttributionResult:
    """Select a deterministic inclusion-minimal cover or fail closed."""
    target = set(target_regions)
    mapping = {
        digest: tuple(sorted(set(regions) & target))
        for digest, regions in sorted(entry_regions.items())
    }
    uncovered = set(target)
    selected = []
    while uncovered:
        choices = [
            (len(uncovered & set(regions)), digest)
            for digest, regions in mapping.items()
            if uncovered & set(regions)
        ]
        if not choices:
            missing = ", ".join(sorted(uncovered)[:4])
            raise ValueError(f"target regions are not attributable: {missing}")
        gain, digest = min(choices, key=lambda item: (-item[0], item[1]))
        if gain <= 0:
            raise AssertionError("positive attribution gain is required")
        selected.append(digest)
        uncovered -= set(mapping[digest])

    for digest in tuple(reversed(selected)):
        remaining = [item for item in selected if item != digest]
        covered = set().union(*(set(mapping[item]) for item in remaining)) if remaining else set()
        if target <= covered:
            selected.remove(digest)
    return AttributionResult(
        tuple(sorted(target)),
        mapping,
        tuple(sorted(selected)),
    )


def assigned_responsibilities(result: AttributionResult) -> Dict[str, Tuple[str, ...]]:
    """Assign each target region to its first canonical representative."""
    assignments: Dict[str, Set[str]] = {digest: set() for digest in result.representatives}
    for region in result.target_regions:
        owners = [
            digest
            for digest in result.representatives
            if region in result.entry_regions[digest]
        ]
        if not owners:
            raise ValueError(f"representative cover lost region: {region}")
        assignments[min(owners)].add(region)
    return {digest: tuple(sorted(regions)) for digest, regions in assignments.items()}


__all__ = ["AttributionResult", "assigned_responsibilities", "attribute_regions"]
