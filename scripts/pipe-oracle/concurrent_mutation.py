"""Lifecycle-preserving mutation for concurrent pipe stories."""

from dataclasses import dataclass
from enum import Enum

import concurrent_generator
from concurrent_scenario import (
    ScenarioDocument,
    canonical_digest,
    serialize_document,
    validate_entry_limits,
)


MUTATION_KINDS = ("replace-story", "append-donor", "regenerate")


class CandidateClassification(str, Enum):
    EXECUTABLE = "executable"
    REJECTED = "rejected"


@dataclass(frozen=True)
class MutationCandidate:
    classification: CandidateClassification
    document: ScenarioDocument
    encoded: bytes
    digest: str
    kind: str


def mutate_document(rng, parent, donor, *, requested_kind=None):
    kind = requested_kind or rng.choice(MUTATION_KINDS)
    if kind not in MUTATION_KINDS:
        raise ValueError(f"unknown concurrent mutation kind: {kind}")
    if kind == "replace-story":
        scenarios = list(parent.scenarios)
        scenarios[rng.range(0, len(scenarios))] = concurrent_generator.generate_scenario(rng)
    elif kind == "append-donor":
        scenarios = list(parent.scenarios)
        scenarios.append(donor.scenarios[rng.range(0, len(donor.scenarios))])
        scenarios = scenarios[:8]
    else:
        scenarios = list(concurrent_generator.generate_document(rng).scenarios)
    document = ScenarioDocument(scenarios, version=7)
    validate_entry_limits(document)
    encoded = serialize_document(document).encode("utf-8")
    digest = canonical_digest(document)
    if digest == canonical_digest(parent):
        document = ScenarioDocument((concurrent_generator.generate_scenario(rng),), version=7)
        validate_entry_limits(document)
        encoded = serialize_document(document).encode("utf-8")
        digest = canonical_digest(document)
    classification = (
        CandidateClassification.EXECUTABLE
        if digest != canonical_digest(parent)
        else CandidateClassification.REJECTED
    )
    return MutationCandidate(classification, document, encoded, digest, kind)


__all__ = [
    "CandidateClassification",
    "MUTATION_KINDS",
    "MutationCandidate",
    "mutate_document",
]
