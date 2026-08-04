"""Canonical-byte validation shared by campaign and background execution."""

from .spec import AdapterSpec


def canonical_entry(spec: AdapterSpec, encoded: bytes) -> bytes:
    if not isinstance(encoded, bytes):
        raise TypeError("campaign candidates must be bytes")
    document = spec.codec.parse(encoded)
    spec.codec.validate_entry(document)
    canonical = spec.codec.serialize(document)
    if canonical != encoded:
        raise ValueError("campaign candidate is not canonical")
    return canonical


__all__ = ["canonical_entry"]
