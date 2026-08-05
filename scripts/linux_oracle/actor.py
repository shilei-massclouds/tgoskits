"""Controlled worker lifecycles shared by blocking oracle adapters."""

from dataclasses import dataclass, replace
from enum import Enum
from typing import Callable, Dict, Generic, Optional, Sequence, Tuple, TypeVar


CONTROLLER_ACTOR = 0
WORKER_ACTOR = 1
WORKER_ACTORS = (1, 2)

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


@dataclass(frozen=True)
class ControlledWorkerCall(Generic[OperationT, ResourceT]):
    """One of two worker calls and its independently published proof state."""

    operation: OperationT
    resource: ResourceT
    pending_confirmed: bool = False
    completable: bool = False
    completed: bool = False
    completion_ordinal: int = 0


class ControlledWorkers(Generic[OperationT, ResourceT]):
    """Enforce two independent worker lifecycles and atomic grouped joins."""

    def __init__(self) -> None:
        self._workers: Dict[
            int, ControlledWorkerCall[OperationT, ResourceT]
        ] = {}
        self._completion_ordinals = set()

    def worker(
        self, actor: int
    ) -> Optional[ControlledWorkerCall[OperationT, ResourceT]]:
        self._require_actor(actor)
        return self._workers.get(actor)

    @property
    def active_actors(self) -> Tuple[int, ...]:
        return tuple(actor for actor in WORKER_ACTORS if actor in self._workers)

    def start(
        self,
        actor: int,
        operation: OperationT,
        identify_resource: Callable[[], ResourceT],
    ) -> None:
        self._require_actor(actor)
        if actor in self._workers:
            self._raise_lifecycle(f"worker actor {actor} is already active")
        self._workers[actor] = ControlledWorkerCall(
            operation, identify_resource()
        )

    def assert_pending(self, actor: int) -> None:
        worker = self._require_active(actor, "assert-pending")
        if worker.completable or worker.completed:
            raise WorkerLifecycleError(
                WorkerLifecycleErrorKind.BLOCKING_PROOF,
                f"worker actor {actor} may complete before assert-pending",
            )
        self._workers[actor] = replace(worker, pending_confirmed=True)

    def assert_all_pending(self) -> None:
        if self.active_actors != WORKER_ACTORS:
            self._raise_lifecycle(
                "assert-all-pending requires active workers 1 and 2"
            )
        for actor in WORKER_ACTORS:
            self.assert_pending(actor)

    def before_trigger(
        self, actors: Optional[Sequence[int]] = None
    ) -> Tuple[ControlledWorkerCall[OperationT, ResourceT], ...]:
        selected = self._selected_actors(actors)
        calls = []
        for actor in selected:
            worker = self._require_active(actor, "trigger")
            if worker.completable or worker.completed:
                self._raise_lifecycle(
                    f"join must follow a completing trigger for actor {actor}"
                )
            if not worker.pending_confirmed:
                self._raise_lifecycle(
                    f"worker actor {actor} pending state was not confirmed"
                )
            calls.append(worker)
        return tuple(calls)

    def update_completable(self, actor: int, completable: bool) -> None:
        worker = self._require_active(actor, "completion update")
        if worker.completed:
            self._raise_lifecycle(f"worker actor {actor} is already completed")
        self._workers[actor] = replace(worker, completable=completable)

    def mark_completed(self, actor: int, completion_ordinal: int) -> None:
        worker = self._require_active(actor, "completion")
        if not worker.pending_confirmed or not worker.completable:
            raise WorkerLifecycleError(
                WorkerLifecycleErrorKind.BLOCKING_PROOF,
                f"worker actor {actor} is not proven completable before completion",
            )
        if worker.completed:
            self._raise_lifecycle(f"worker actor {actor} is already completed")
        if completion_ordinal <= 0:
            self._raise_lifecycle("completion ordinal must be positive")
        if completion_ordinal in self._completion_ordinals:
            self._raise_lifecycle(
                f"completion ordinal {completion_ordinal} is already used"
            )
        self._completion_ordinals.add(completion_ordinal)
        self._workers[actor] = replace(
            worker,
            completed=True,
            completion_ordinal=completion_ordinal,
        )

    def join(
        self,
        actor: int,
        complete: Callable[[ControlledWorkerCall[OperationT, ResourceT]], None],
    ) -> None:
        worker = self._completed_worker(actor, grouped=False)
        complete(worker)
        del self._workers[actor]

    def join_set(
        self,
        actors: Sequence[int],
        complete: Callable[
            [Tuple[ControlledWorkerCall[OperationT, ResourceT], ...]], None
        ],
    ) -> None:
        selected = tuple(actors)
        for actor in selected:
            self._require_actor(actor)
        if len(set(selected)) != len(selected):
            self._raise_lifecycle("join-set actors must be unique")
        if not selected:
            self._raise_lifecycle("join-set requires at least one actor")
        workers = tuple(
            self._completed_worker(actor, grouped=True) for actor in selected
        )
        complete(workers)
        for actor in selected:
            del self._workers[actor]

    def finish_scenario(self) -> None:
        active = self.active_actors
        if active:
            actors = ", ".join(str(actor) for actor in active)
            self._raise_lifecycle(
                f"scenario ends with unfinished workers: {actors}"
            )

    def _completed_worker(
        self, actor: int, *, grouped: bool
    ) -> ControlledWorkerCall[OperationT, ResourceT]:
        worker = self._require_active(actor, "join-set" if grouped else "join")
        if not worker.pending_confirmed or not worker.completable:
            raise WorkerLifecycleError(
                WorkerLifecycleErrorKind.BLOCKING_PROOF,
                f"worker actor {actor} is not proven completable before join",
            )
        if not worker.completed:
            detail = (
                f"worker actor {actor} is not completed before grouped join"
                if grouped
                else f"worker actor {actor} is not completed before join"
            )
            raise WorkerLifecycleError(
                WorkerLifecycleErrorKind.BLOCKING_PROOF, detail
            )
        return worker

    def _require_active(
        self, actor: int, operation: str
    ) -> ControlledWorkerCall[OperationT, ResourceT]:
        self._require_actor(actor)
        worker = self._workers.get(actor)
        if worker is None:
            self._raise_lifecycle(
                f"{operation} actor {actor} requires an active worker"
            )
        return worker

    @staticmethod
    def _selected_actors(actors: Optional[Sequence[int]]) -> Tuple[int, ...]:
        return WORKER_ACTORS if actors is None else tuple(actors)

    @staticmethod
    def _require_actor(actor: int) -> None:
        if actor not in WORKER_ACTORS:
            ControlledWorkers._raise_lifecycle("worker actor must be 1 or 2")

    @staticmethod
    def _raise_lifecycle(detail: str) -> None:
        raise WorkerLifecycleError(WorkerLifecycleErrorKind.LIFECYCLE, detail)


__all__ = [
    "CONTROLLER_ACTOR",
    "ControlledWorkerCall",
    "ControlledWorkers",
    "SingleWorkerLifecycle",
    "WORKER_ACTORS",
    "WORKER_ACTOR",
    "WorkerCall",
    "WorkerLifecycleError",
    "WorkerLifecycleErrorKind",
]
