"""Exclusive workspace lock for one persistent pipe-oracle campaign."""

import fcntl
import os
from pathlib import Path

from corpus_errors import CampaignLockError


class CampaignLock:
    def __init__(self, path: Path):
        self.path = path
        self._file = None

    def __enter__(self) -> "CampaignLock":
        self._file = self.path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            self._file.close()
            self._file = None
            raise CampaignLockError(
                f"another pipe-oracle campaign holds {self.path}"
            ) from error
        self._file.seek(0)
        self._file.truncate()
        self._file.write(f"pid={os.getpid()}\n")
        self._file.flush()
        return self

    def __exit__(self, _error_type, _error, _traceback) -> None:
        if self._file is not None:
            fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            self._file.close()
            self._file = None


__all__ = ["CampaignLock"]
