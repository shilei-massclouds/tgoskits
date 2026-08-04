"""Common deterministic campaign request and QEMU budget accounting."""

from dataclasses import dataclass
from typing import Callable, Iterable, Protocol, Tuple

from .batch import BatchInput
from .tasks import Task, TaskStore


class CampaignBudgetExhausted(RuntimeError):
    pass


class QemuBudget(Protocol):
    @property
    def maximum(self) -> int: ...

    @property
    def used(self) -> int: ...

    def charge(self) -> None: ...


@dataclass(frozen=True)
class CampaignRequest:
    seed: int
    batches: int
    batch_size: int
    max_qemu: int
    max_minimize: int
    minimize_enabled: bool = True

    def __post_init__(self) -> None:
        if self.seed < 0 or self.batches < 0 or self.batch_size <= 0:
            raise ValueError("campaign seed and batch dimensions are invalid")
        if self.max_qemu <= 0 or self.max_minimize < 0:
            raise ValueError("campaign budgets are invalid")
        if not isinstance(self.minimize_enabled, bool):
            raise ValueError("campaign minimization switch is invalid")


@dataclass
class CampaignBudget:
    maximum: int
    used: int = 0

    def charge(self) -> None:
        if self.used >= self.maximum:
            raise CampaignBudgetExhausted("QEMU budget exhausted")
        self.used += 1

    def reserving(self, qemu_count: int) -> "ReservedCampaignBudget":
        if qemu_count < 0 or qemu_count > self.maximum:
            raise ValueError("reserved QEMU count is invalid")
        return ReservedCampaignBudget(self, self.maximum - qemu_count)


@dataclass(frozen=True)
class ReservedCampaignBudget:
    """A shared budget view that protects later foreground executions."""

    campaign: CampaignBudget
    maximum: int

    @property
    def used(self) -> int:
        return self.campaign.used

    def charge(self) -> None:
        if self.used >= self.maximum:
            raise CampaignBudgetExhausted(
                "QEMU budget reserved for requested campaign batches"
            )
        self.campaign.charge()


def recover_tasks(
    stores: Iterable[TaskStore], resume: Callable[[TaskStore, Task], None]
) -> Tuple[Task, ...]:
    """Claim and dispatch all persisted pending/running tasks in path order."""
    recovered = []
    for store in stores:
        for task in store.recoverable():
            claimed = store.claim(task)
            resume(store, claimed)
            recovered.append(claimed)
    return tuple(recovered)


def validate_inputs(inputs: Iterable[BatchInput]) -> Tuple[BatchInput, ...]:
    values = tuple(inputs)
    if not values:
        raise ValueError("campaign batch requires at least one input")
    return tuple(sorted(values, key=lambda item: item.digest))
