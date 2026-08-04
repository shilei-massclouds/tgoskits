"""Scenario-neutral exact coverage attribution helpers."""

from typing import Dict, Iterable, Mapping, Set, Tuple


def representative_cover(
    targets: Iterable[str], observations: Mapping[str, Iterable[str]]
) -> Dict[str, Tuple[str, ...]]:
    """Choose a deterministic inclusion-minimal cover and assign each target."""
    target_set = set(targets)
    mapping = {
        digest: set(regions) & target_set
        for digest, regions in sorted(observations.items())
    }
    uncovered = set(target_set)
    representatives = []
    while uncovered:
        choices = [
            (len(uncovered & regions), digest)
            for digest, regions in mapping.items()
            if uncovered & regions
        ]
        if not choices:
            missing = ", ".join(sorted(uncovered)[:4])
            raise ValueError(f"target regions are not attributable: {missing}")
        gain, digest = min(choices, key=lambda item: (-item[0], item[1]))
        if gain <= 0:
            raise AssertionError("positive attribution gain is required")
        representatives.append(digest)
        uncovered -= mapping[digest]

    for digest in tuple(reversed(representatives)):
        remaining = [item for item in representatives if item != digest]
        covered = set().union(*(mapping[item] for item in remaining)) if remaining else set()
        if target_set <= covered:
            representatives.remove(digest)

    responsibilities: Dict[str, Set[str]] = {
        digest: set() for digest in representatives
    }
    for region in sorted(target_set):
        owners = [digest for digest in representatives if region in mapping[digest]]
        if not owners:
            raise ValueError(f"representative cover lost region: {region}")
        responsibilities[min(owners)].add(region)
    return {
        digest: tuple(sorted(regions))
        for digest, regions in sorted(responsibilities.items())
    }


def exact_cover(
    targets: Iterable[str], observations: Mapping[str, Iterable[str]]
) -> Dict[str, Tuple[str, ...]]:
    target_set = set(targets)
    owners: Dict[str, list[str]] = {target: [] for target in sorted(target_set)}
    for digest in sorted(observations):
        for region in set(observations[digest]) & target_set:
            owners[region].append(digest)
    return {region: tuple(digests) for region, digests in owners.items()}


def uniquely_attributed(
    targets: Iterable[str], observations: Mapping[str, Iterable[str]]
) -> Dict[str, Set[str]]:
    result: Dict[str, Set[str]] = {}
    for region, owners in exact_cover(targets, observations).items():
        if len(owners) == 1:
            result.setdefault(owners[0], set()).add(region)
    return result
