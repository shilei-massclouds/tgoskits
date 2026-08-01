"""Typed canonical-corpus origins and external import evidence."""

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple


_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class ExternalSource:
    program_sha256: str
    syzkaller_revision: str
    importer_version: str
    conversion_log_sha256: str

    def as_metadata(self) -> Dict[str, str]:
        validate_external_source(self)
        return {
            "program_sha256": self.program_sha256,
            "syzkaller_revision": self.syzkaller_revision,
            "importer_version": self.importer_version,
            "conversion_log_sha256": self.conversion_log_sha256,
        }

    @classmethod
    def from_metadata(cls, metadata: Any) -> "ExternalSource":
        if not isinstance(metadata, dict):
            raise ValueError("external source is not a JSON object")
        expected = {
            "program_sha256",
            "syzkaller_revision",
            "importer_version",
            "conversion_log_sha256",
        }
        if set(metadata) != expected:
            raise ValueError("external source keys mismatch")
        source = cls(
            metadata["program_sha256"],
            metadata["syzkaller_revision"],
            metadata["importer_version"],
            metadata["conversion_log_sha256"],
        )
        validate_external_source(source)
        return source


@dataclass(frozen=True)
class CorpusProvenance:
    source: str
    parent_digest: Optional[str] = None
    donor_digest: Optional[str] = None
    mutation_type: Optional[str] = None
    external_sources: Tuple[ExternalSource, ...] = ()

    @classmethod
    def generated(cls) -> "CorpusProvenance":
        return cls("generated")

    @classmethod
    def mutated(
        cls,
        parent_digest: str,
        donor_digest: Optional[str],
        mutation_type: str,
    ) -> "CorpusProvenance":
        return cls("mutation", parent_digest, donor_digest, mutation_type)

    @classmethod
    def imported(
        cls,
        external_sources: Iterable[ExternalSource],
    ) -> "CorpusProvenance":
        return cls(
            "syzkaller-import",
            external_sources=normalize_external_sources(external_sources),
        )

    @classmethod
    def from_metadata(cls, metadata: Any) -> "CorpusProvenance":
        if not isinstance(metadata, dict):
            raise ValueError("corpus origin is not a JSON object")
        legacy_keys = {"source", "parent_digest", "donor_digest", "mutation_type"}
        current_keys = legacy_keys | {"external_sources"}
        if set(metadata) == legacy_keys:
            external_sources: Tuple[ExternalSource, ...] = ()
        elif set(metadata) == current_keys:
            raw_sources = metadata["external_sources"]
            if not isinstance(raw_sources, list):
                raise ValueError("external_sources must be a list")
            external_sources = tuple(
                ExternalSource.from_metadata(source) for source in raw_sources
            )
        else:
            raise ValueError("corpus origin keys mismatch")
        provenance = cls(
            metadata["source"],
            metadata["parent_digest"],
            metadata["donor_digest"],
            metadata["mutation_type"],
            external_sources,
        )
        validate_provenance(provenance)
        return provenance

    def with_external_sources(
        self,
        external_sources: Iterable[ExternalSource],
    ) -> "CorpusProvenance":
        return CorpusProvenance(
            self.source,
            self.parent_digest,
            self.donor_digest,
            self.mutation_type,
            normalize_external_sources((*self.external_sources, *external_sources)),
        )

    def as_metadata(self, *, include_external_sources: bool = True) -> Dict[str, Any]:
        validate_provenance(self)
        metadata = {
            "source": self.source,
            "parent_digest": self.parent_digest,
            "donor_digest": self.donor_digest,
            "mutation_type": self.mutation_type,
        }
        if include_external_sources:
            metadata["external_sources"] = [
                source.as_metadata() for source in self.external_sources
            ]
        elif self.external_sources or self.source == "syzkaller-import":
            raise ValueError("legacy corpus origin cannot retain external sources")
        return metadata


def validate_provenance(provenance: CorpusProvenance) -> None:
    if (
        not isinstance(provenance.external_sources, tuple)
        or provenance.external_sources
        != normalize_external_sources(provenance.external_sources)
    ):
        raise ValueError("external sources must be sorted and unique")
    if provenance.source == "syzkaller-import":
        if any(
            value is not None
            for value in (
                provenance.parent_digest,
                provenance.donor_digest,
                provenance.mutation_type,
            )
        ):
            raise ValueError("syzkaller import cannot have mutation ancestry")
        if not provenance.external_sources:
            raise ValueError("syzkaller import requires external sources")
        return
    if provenance.source == "generated":
        if any(
            value is not None
            for value in (
                provenance.parent_digest,
                provenance.donor_digest,
                provenance.mutation_type,
            )
        ):
            raise ValueError("generated provenance cannot have mutation ancestry")
        return
    if provenance.source != "mutation":
        raise ValueError(f"unknown corpus source: {provenance.source}")
    if not _is_digest(provenance.parent_digest):
        raise ValueError("mutation provenance requires a parent digest")
    if provenance.donor_digest is not None and not _is_digest(
        provenance.donor_digest
    ):
        raise ValueError("mutation donor digest is invalid")
    if not provenance.mutation_type:
        raise ValueError("mutation provenance requires a mutation type")


def validate_external_source(source: ExternalSource) -> None:
    if not _is_digest(source.program_sha256):
        raise ValueError("external program digest is invalid")
    if (
        not isinstance(source.syzkaller_revision, str)
        or _REVISION_PATTERN.fullmatch(source.syzkaller_revision) is None
    ):
        raise ValueError("external syzkaller revision is invalid")
    if not isinstance(source.importer_version, str) or not source.importer_version:
        raise ValueError("external importer version is invalid")
    if not _is_digest(source.conversion_log_sha256):
        raise ValueError("external conversion log digest is invalid")


def normalize_external_sources(
    sources: Iterable[ExternalSource],
) -> Tuple[ExternalSource, ...]:
    materialized = tuple(sources)
    for source in materialized:
        if not isinstance(source, ExternalSource):
            raise ValueError("external source has the wrong type")
        validate_external_source(source)
    return tuple(
        sorted(
            set(materialized),
            key=lambda source: (
                source.program_sha256,
                source.syzkaller_revision,
                source.importer_version,
                source.conversion_log_sha256,
            ),
        )
    )


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST_PATTERN.fullmatch(value) is not None


__all__ = [
    "CorpusProvenance",
    "ExternalSource",
    "normalize_external_sources",
    "validate_provenance",
]
