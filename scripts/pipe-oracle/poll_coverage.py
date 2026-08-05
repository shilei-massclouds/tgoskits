"""Coverage target for pipe blocking poll and wakeup paths."""

from pathlib import Path
from typing import Iterable, Tuple


TARGET_SET_ID = "pipe-blocking-v2"

TARGET_SOURCE_PATHS = (
    "components/axpoll/src/lib.rs",
    "os/StarryOS/kernel/src/file/pipe.rs",
    "os/StarryOS/kernel/src/syscall/fs/io.rs",
    "os/StarryOS/kernel/src/syscall/io_mpx/poll.rs",
    "os/arceos/modules/axtask/src/future/poll.rs",
)


def resolve_target_sources(workspace: Path) -> Tuple[Path, ...]:
    sources = tuple(workspace / relative for relative in TARGET_SOURCE_PATHS)
    missing = [str(path) for path in sources if not path.is_file()]
    if missing:
        raise FileNotFoundError(
            "pipe blocking poll coverage target source is missing: "
            + ", ".join(missing)
        )
    return sources


def target_source_paths() -> Iterable[str]:
    return TARGET_SOURCE_PATHS


__all__ = ["TARGET_SET_ID", "TARGET_SOURCE_PATHS", "resolve_target_sources"]
