"""Lifecycle-aware mutation for the controlled pipe poll model."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

import poll_generator
from poll_scenario import (
    CORPUS_VERSION,
    MAX_SCENARIOS_PER_ENTRY,
    ScenarioCodecError,
    ScenarioDocument,
    ScenarioEntryLimitError,
    canonical_digest,
    serialize_document,
    validate_entry_limits,
)


MUTATION_KINDS = (
    "lifecycle-replace",
    "scenario-insert",
    "scenario-delete",
    "scenario-swap",
    "donor-splice",
    "parameter",
)


class CandidateClassification(Enum):
    EXECUTABLE = "executable"
    MALFORMED = "malformed"


@dataclass(frozen=True)
class MutationProvenance:
    source: str
    parent_digest: Optional[str]
    donor_digest: Optional[str]
    mutation_type: Optional[str]


@dataclass(frozen=True)
class MutationCandidate:
    document: Optional[ScenarioDocument]
    encoded: bytes
    digest: str
    classification: CandidateClassification
    provenance: MutationProvenance
    rejection: Optional[str] = None


def mutate_document(
    rng: poll_generator.CampaignRng,
    parent: ScenarioDocument,
    donor: Optional[ScenarioDocument] = None,
    *,
    requested_kind: Optional[str] = None,
) -> MutationCandidate:
    kind = requested_kind or MUTATION_KINDS[rng.range(0, len(MUTATION_KINDS))]
    if kind not in MUTATION_KINDS:
        raise ValueError(f"unknown mutation kind: {kind}")
    parent_digest = canonical_digest(parent)
    provenance = MutationProvenance(
        "mutation",
        parent_digest,
        canonical_digest(donor) if donor is not None else None,
        kind,
    )
    for attempt in range(64):
        try:
            candidate = _apply_mutation(rng, parent, donor, kind, attempt)
            validate_entry_limits(candidate)
            digest = canonical_digest(candidate)
            if digest == parent_digest:
                continue
            return MutationCandidate(
                candidate,
                serialize_document(candidate).encode("utf-8"),
                digest,
                CandidateClassification.EXECUTABLE,
                provenance,
            )
        except (ScenarioCodecError, ScenarioEntryLimitError):
            continue
    return MutationCandidate(
        None,
        b"",
        "",
        CandidateClassification.MALFORMED,
        provenance,
        "mutation-exhausted",
    )


def _apply_mutation(
    rng: poll_generator.CampaignRng,
    parent: ScenarioDocument,
    donor: Optional[ScenarioDocument],
    kind: str,
    attempt: int,
) -> ScenarioDocument:
    scenarios = list(parent.scenarios)
    index = rng.range(0, len(scenarios))
    generated = poll_generator.generate_scenario(
        rng,
        story=(MUTATION_KINDS.index(kind) + attempt) % poll_generator.STORY_COUNT,
    )
    if kind in ("lifecycle-replace", "parameter"):
        scenarios[index] = generated
    elif kind == "scenario-insert" and len(scenarios) < MAX_SCENARIOS_PER_ENTRY:
        scenarios.insert(rng.range(0, len(scenarios) + 1), generated)
    elif kind == "scenario-delete" and len(scenarios) > 1:
        del scenarios[index]
    elif kind == "scenario-swap" and len(scenarios) > 1:
        other = (index + 1) % len(scenarios)
        scenarios[index], scenarios[other] = scenarios[other], scenarios[index]
    elif kind == "donor-splice" and donor is not None:
        scenarios[index] = donor.scenarios[rng.range(0, len(donor.scenarios))]
    else:
        scenarios[index] = generated
    return ScenarioDocument(scenarios, version=CORPUS_VERSION)


__all__ = [
    "CandidateClassification",
    "MUTATION_KINDS",
    "MutationCandidate",
    "MutationProvenance",
    "mutate_document",
]
