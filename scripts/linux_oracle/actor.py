"""Controlled single-worker lifecycle shared by blocking oracle adapters."""

from dataclasses import dataclass, replace
from enum import Enum
from typing import Callable, Generic, Optional, TypeVar


CONTROLLER_ACTOR = 0
WORKER_ACTOR = 1

OperationT = TypeVar("OperationT")
ResourceT = TypeVar("ResourceT")


class WorkerLifecycleErrorKind(str, Enum):
    """Adapter-neutral categories for controlled-worker validation errors."""

    LIFECYCLE = "lifecycle"
    BLOCKING_PROOF = "blocking-proof"


class WorkerLifecycleError(ValueError):
    """A stable controlled-worker error translated by each scenario codec."""

    def __init__(self, kind: WorkerLifecycleErrorKind, detail: str):
        self.kind = kind
        self.detail = detail
        super().__init__(f"{kind.value}: {detail}")


@dataclass(frozen=True)
class WorkerCall(Generic[OperationT, ResourceT]):
    """One immutable worker call plus its lifecycle proof state."""

    operation: OperationT
    resource: ResourceT
    pending_confirmed: bool = False
    completable: bool = False


class SingleWorkerLifecycle(Generic[OperationT, ResourceT]):
    """Enforce the shared start, pending, trigger, and join state machine."""

    def __init__(self) -> None:
        self._worker: Optional[WorkerCall[OperationT, ResourceT]] = None

    @property
    def worker(self) -> Optional[WorkerCall[OperationT, ResourceT]]:
        return self._worker

    def start(
        self,
        operation: OperationT,
        identify_resource: Callable[[], ResourceT],
    ) -> None:
        """Start one worker after the adapter proves and identifies its resource."""
        if self._worker is not None:
            raise WorkerLifecycleError(
                WorkerLifecycleErrorKind.LIFECYCLE,
                "only one worker call may be active",
            )
        self._worker = WorkerCall(operation, identify_resource())

    def assert_pending(self) -> None:
        worker = self._worker
        if worker is None:
            raise WorkerLifecycleError(
                WorkerLifecycleErrorKind.LIFECYCLE,
                "assert-pending requires an active worker",
            )
        if worker.completable:
            raise WorkerLifecycleError(
                WorkerLifecycleErrorKind.BLOCKING_PROOF,
                "worker may complete before assert-pending",
            )
        self._worker = replace(worker, pending_confirmed=True)

    def before_trigger(self) -> WorkerCall[OperationT, ResourceT]:
        worker = self._worker
        if worker is None:
            raise AssertionError("active worker is required")
        if worker.completable:
            raise WorkerLifecycleError(
                WorkerLifecycleErrorKind.LIFECYCLE,
                "join must immediately follow a completing trigger",
            )
        if not worker.pending_confirmed:
            raise WorkerLifecycleError(
                WorkerLifecycleErrorKind.LIFECYCLE,
                "worker pending state was not confirmed",
            )
        return worker

    def update_completable(self, completable: bool) -> None:
        worker = self._worker
        if worker is None:
            raise AssertionError("active worker is required")
        self._worker = replace(worker, completable=completable)

    def join(
        self,
        complete: Callable[[WorkerCall[OperationT, ResourceT]], None],
    ) -> None:
        """Apply the adapter-owned completion transition and clear the worker."""
        worker = self._worker
        if worker is None:
            raise WorkerLifecycleError(
                WorkerLifecycleErrorKind.LIFECYCLE,
                "join requires an active worker",
            )
        if not worker.pending_confirmed or not worker.completable:
            raise WorkerLifecycleError(
                WorkerLifecycleErrorKind.BLOCKING_PROOF,
                "worker is not proven completable before join",
            )
        complete(worker)
        self._worker = None

    def finish_scenario(self) -> None:
        if self._worker is not None:
            raise WorkerLifecycleError(
                WorkerLifecycleErrorKind.LIFECYCLE,
                "scenario ends with an unfinished worker",
            )


__all__ = [
    "CONTROLLER_ACTOR",
    "SingleWorkerLifecycle",
    "WORKER_ACTOR",
    "WorkerCall",
    "WorkerLifecycleError",
    "WorkerLifecycleErrorKind",
]
