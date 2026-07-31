"""Typed failures shared by pipe-oracle persistent campaign modules."""

from pathlib import Path


class CorpusStorageError(RuntimeError):
    """Base error for persistent campaign state."""


class CorpusValidationError(CorpusStorageError):
    """A persisted entry, job, or coverage state failed closed validation."""

    def __init__(self, path: Path, reason: str):
        self.path = path
        self.reason = reason
        super().__init__(f"invalid persistent state at {path}: {reason}")


class CampaignLockError(CorpusStorageError):
    """Another campaign already owns the workspace persistence lock."""


__all__ = [
    "CampaignLockError",
    "CorpusStorageError",
    "CorpusValidationError",
]
