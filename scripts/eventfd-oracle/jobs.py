"""Eventfd compatibility binding for common resumable task storage."""

import sys
from pathlib import Path
from typing import Iterable, Mapping, Optional, Tuple

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from adapter import SPEC
from linux_oracle.tasks import Task
from linux_oracle.tasks import TaskStore as _TaskStore


class TaskStore(_TaskStore):
    def __init__(self, campaign_root: Path, kind: str):
        super().__init__(SPEC, campaign_root, kind)

    def create(
        self,
        task_id: str,
        inputs: Iterable[bytes],
        context: Optional[Mapping[str, object]] = None,
    ) -> Task:
        return super().create(task_id, inputs, context)

    def pending(self) -> Tuple[Task, ...]:
        return self.recoverable()


__all__ = ["Task", "TaskStore"]
