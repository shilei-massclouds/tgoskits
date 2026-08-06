"""Exact attribution and bounded minimization for durable background tasks."""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Set, Tuple

from .attribution import representative_cover
from .batch import BatchInput
from .campaign import CampaignBudgetExhausted, QemuBudget
from .canonical import canonical_entry
from .execution import ExecutionObservation, sha256_file
from .minimization import CandidateRejection, RejectCandidate, minimize
from .persistence import CampaignStore, PersistentStateError, is_digest
from .spec import AdapterSpec, CampaignHooks
from .tasks import Task, TaskStore


class CampaignReplayError(RuntimeError):
    """A replay failed before its semantic or coverage predicate was known."""

    def __init__(self, stage: str, category: str, detail: str = ""):
        self.stage = stage
        self.category = category
        self.detail = detail
        message = f"{stage} replay failed: {category}"
        if detail:
            message = f"{message}\n{detail}"
        super().__init__(message)


@dataclass(frozen=True)
class TaskRuntime:
    spec: AdapterSpec
    hooks: CampaignHooks
    workspace: Path
    store: CampaignStore
    host_oracle: Path
    budget: QemuBudget
    batch_index: int
    execute: Callable[..., ExecutionObservation]


def run_attribution_task(
    runtime: TaskRuntime,
    task_store: TaskStore,
    task: Task,
    inputs: Tuple[BatchInput, ...],
    target_regions: Set[str],
    fixed_elf: Path,
    max_minimize: int,
    minimize_enabled: bool,
) -> Tuple[str, ...]:
    progress = _attribution_progress(task)
    mapping = {
        digest: tuple(regions)
        for digest, regions in progress["entry_regions"].items()
    }
    for item in inputs:
        if item.digest in mapping:
            continue
        observation = _execute_one(runtime, (item,), fixed_elf)
        if not observation.passed:
            raise CampaignReplayError(
                "attribution", observation.category, observation.detail
            )
        mapping[item.digest] = observation.regions
        progress["entry_regions"] = {
            digest: list(mapping[digest]) for digest in sorted(mapping)
        }
        task = task_store.transition(task, "running", progress)

    responsibilities = representative_cover(target_regions, mapping)
    input_by_digest = {item.digest: item for item in inputs}
    representatives = tuple(
        input_by_digest[digest] for digest in sorted(responsibilities)
    )
    if not progress["proof_passed"]:
        proof = _execute_one(runtime, representatives, fixed_elf)
        if not proof.passed:
            raise CampaignReplayError("attribution", proof.category, proof.detail)
        if not target_regions <= set(proof.regions):
            if runtime.spec.outcomes is not None:
                proof_regions = target_regions & set(proof.regions)
                missing_regions = target_regions - proof_regions
                task_store.transition(
                    task,
                    "completed",
                    {
                        "category": "unreproducible-coverage",
                        "target_regions": sorted(target_regions),
                        "representatives": sorted(responsibilities),
                        "entry_regions": {
                            digest: list(mapping[digest])
                            for digest in sorted(mapping)
                        },
                        "proof_regions": sorted(proof_regions),
                        "missing_regions": sorted(missing_regions),
                        "proven_regions": [],
                        "admitted_digests": [],
                    },
                )
                print(
                    "attribution: status=unreproducible-coverage "
                    f"missing_regions={len(missing_regions)}",
                    flush=True,
                )
                return ()
            task_store.transition(
                task, "unstable", {"category": "representative-proof"}
            )
            raise RuntimeError("representative coverage proof failed")
        progress["proof_passed"] = True
        task = task_store.transition(task, "running", progress)

    admitted = dict(progress["admitted"])
    for representative in representatives:
        if representative.digest in admitted:
            continue
        regions = set(responsibilities[representative.digest])
        encoded = representative.encoded
        if minimize_enabled:
            encoded = minimize_representative(
                runtime,
                task.metadata["task_id"],
                encoded,
                regions,
                fixed_elf,
                max_minimize,
            )
        entry = runtime.store.save_entry(encoded, regions)
        admitted[representative.digest] = entry.digest
        progress["admitted"] = dict(sorted(admitted.items()))
        task = task_store.transition(task, "running", progress)

    admitted_digests = tuple(sorted(set(admitted.values())))
    task_store.transition(
        task,
        "completed",
        {
            "category": "passed",
            "target_regions": sorted(target_regions),
            "representatives": sorted(responsibilities),
            "proven_regions": sorted(target_regions),
            "missing_regions": [],
            "admitted_digests": list(admitted_digests),
        },
    )
    return admitted_digests


def minimize_representative(
    runtime: TaskRuntime,
    parent_task_id: str,
    encoded: bytes,
    responsibility: Set[str],
    fixed_elf: Path,
    max_candidates: int,
) -> bytes:
    task_store = TaskStore(runtime.spec, runtime.store.root, "minimization")
    digest = hashlib.sha256(encoded).hexdigest()
    task_id = f"{parent_task_id}-min-{digest[:12]}"
    task_path = task_store.root / task_id
    if task_path.exists():
        task = task_store.load(task_path)
        if task.metadata["state"] == "completed":
            return _completed_minimized_input(runtime.store, task)
    else:
        task = task_store.create(
            task_id,
            (encoded,),
            {
                "responsibility": sorted(responsibility),
                "starry_elf_sha256": sha256_file(fixed_elf),
                "max_candidates": max_candidates,
                "batch_index": runtime.batch_index,
            },
        )
    task = task_store.claim(task)
    return run_minimization_task(
        runtime,
        task_store,
        task,
        encoded,
        responsibility,
        fixed_elf,
        max_candidates,
    )


def run_minimization_task(
    runtime: TaskRuntime,
    task_store: TaskStore,
    task: Task,
    encoded: bytes,
    responsibility: Set[str],
    fixed_elf: Path,
    max_candidates: int,
) -> bytes:
    initial = runtime.hooks.reduction.initial(encoded)

    def predicate(value: object) -> bool:
        candidate = canonical_entry(
            runtime.spec, runtime.hooks.reduction.encode(value)
        )
        item = BatchInput(hashlib.sha256(candidate).hexdigest(), candidate)
        observation = _execute_one(runtime, (item,), fixed_elf)
        if not observation.passed:
            if observation.category in {
                "host-schedule-timeout",
                "host-unstable",
            }:
                raise RejectCandidate(
                    CandidateRejection(
                        observation.category,
                        observation.detail,
                        item.digest,
                    )
                )
            raise CampaignReplayError(
                "minimization", observation.category, observation.detail
            )
        return responsibility <= set(observation.regions)

    remaining = max(0, runtime.budget.maximum - runtime.budget.used - 3)
    if runtime.budget.maximum - runtime.budget.used < 3:
        raise CampaignBudgetExhausted(
            "minimization requires three QEMU replays for validation and proofs"
        )
    try:
        result = minimize(
            initial,
            runtime.hooks.reduction.candidates,
            predicate,
            runtime.hooks.reduction.complexity,
            min(max_candidates, remaining),
        )
    except RejectCandidate as error:
        rejection = error.rejection
        raise CampaignReplayError(
            "minimization", rejection.category, rejection.detail
        ) from error
    except (CampaignReplayError, CampaignBudgetExhausted):
        raise
    except (ValueError, RuntimeError) as error:
        task_store.transition(task, "unstable", {"reason": str(error)})
        raise
    best = canonical_entry(runtime.spec, runtime.hooks.reduction.encode(result.value))
    entry = runtime.store.save_entry(best, responsibility)
    task_store.transition(
        task,
        "completed",
        {
            "status": result.status,
            "original_size": len(encoded),
            "best_size": len(best),
            "attempts": result.attempts,
            "best_digest": entry.digest,
            "candidate_rejections": [
                {
                    "category": rejection.category,
                    "detail": rejection.detail,
                    "digest": rejection.digest,
                }
                for rejection in result.candidate_rejections
            ],
        },
    )
    print(
        f"minimization: status={result.status} "
        f"size={len(encoded)}->{len(best)} attempts={result.attempts}",
        flush=True,
    )
    return best


def _execute_one(
    runtime: TaskRuntime,
    inputs: Tuple[BatchInput, ...],
    fixed_elf: Path,
) -> ExecutionObservation:
    return runtime.execute(
        runtime.spec,
        runtime.workspace,
        runtime.store,
        runtime.host_oracle,
        inputs,
        runtime.budget,
        pinned_starry_elf=fixed_elf,
        batch_index=runtime.batch_index,
    )


def _attribution_progress(task: Task) -> Dict:
    result = task.metadata["result"]
    if result is None:
        return {"entry_regions": {}, "proof_passed": False, "admitted": {}}
    expected = {"entry_regions", "proof_passed", "admitted"}
    if not isinstance(result, dict) or set(result) != expected:
        raise PersistentStateError("attribution task progress is invalid")
    entry_regions = result["entry_regions"]
    admitted = result["admitted"]
    if (
        not isinstance(entry_regions, dict)
        or not isinstance(admitted, dict)
        or not isinstance(result["proof_passed"], bool)
        or list(entry_regions) != sorted(entry_regions)
        or list(admitted) != sorted(admitted)
    ):
        raise PersistentStateError("attribution task progress is invalid")
    for digest, regions in entry_regions.items():
        if not is_digest(digest) or not _sorted_string_list(regions):
            raise PersistentStateError("attribution task entry progress is invalid")
    if not all(is_digest(key) and is_digest(value) for key, value in admitted.items()):
        raise PersistentStateError("attribution task admission progress is invalid")
    return {
        "entry_regions": {key: list(value) for key, value in entry_regions.items()},
        "proof_passed": result["proof_passed"],
        "admitted": dict(admitted),
    }


def _completed_minimized_input(store: CampaignStore, task: Task) -> bytes:
    result = task.metadata["result"]
    if not isinstance(result, dict) or not is_digest(result.get("best_digest")):
        raise PersistentStateError("completed minimization result is invalid")
    entries = {entry.digest: entry.encoded for entry in store.load_entries()}
    try:
        return entries[result["best_digest"]]
    except KeyError as error:
        raise PersistentStateError(
            "completed minimization corpus entry is missing"
        ) from error


def _sorted_string_list(value: object) -> bool:
    return (
        isinstance(value, list)
        and value == sorted(set(value))
        and all(isinstance(item, str) and item for item in value)
    )


__all__ = [
    "CampaignReplayError",
    "TaskRuntime",
    "minimize_representative",
    "run_attribution_task",
    "run_minimization_task",
]
