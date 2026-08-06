"""Scenario-neutral deterministic differential campaign state machine."""

import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Mapping, Optional, Sequence, Set, Tuple

from .batch import BatchInput
from .campaign import (
    CampaignBudget,
    CampaignBudgetExhausted,
    CampaignRequest,
    QemuBudget,
)
from .execution import (
    ExecutionObservation,
    execute_inputs as _execute_inputs,
    fixed_elf_from_digest,
    fixed_starry_elf,
    sha256_file,
)
from .canonical import canonical_entry
from .persistence import (
    RUN_SCHEMA_NAME,
    RUN_SCHEMA_VERSION,
    CampaignStore,
    PersistentStateError,
    is_digest,
)
from .qemu import coverage_object
from .spec import AdapterSpec, CampaignHooks
from .task_execution import (
    CampaignReplayError,
    TaskRuntime,
    minimize_representative as _minimize_representative,
    run_attribution_task as _run_attribution_task,
    run_minimization_task as _run_minimization_task,
)
from .tasks import Task, TaskStore


def run_campaign(
    spec: AdapterSpec,
    request: CampaignRequest,
    workspace: Path,
) -> int:
    hooks = _require_hooks(spec)
    workspace = workspace.resolve()
    store = CampaignStore(spec, workspace)
    budget = CampaignBudget(request.max_qemu)
    if request.batches > budget.maximum:
        raise CampaignBudgetExhausted(
            "QEMU budget is smaller than the requested foreground batch count"
        )
    host_oracle = hooks.find_or_build_host(workspace)
    if host_oracle is None:
        raise RuntimeError("cannot build host oracle")
    if hooks.recover_legacy is not None:
        hooks.recover_legacy(workspace, host_oracle)
    _recover_background_with_reserve(
        spec,
        hooks,
        workspace,
        store,
        host_oracle,
        budget,
        request.batches,
    )
    corpus = _load_corpus(spec, hooks, workspace, store)
    rng = hooks.make_rng(request.seed)
    for batch_index in range(request.batches):
        selected = select_batch(spec, hooks, rng, corpus, request.batch_size)
        observation = execute_inputs(
            spec,
            workspace,
            store,
            host_oracle,
            selected,
            budget,
            batch_index=batch_index,
        )
        if not observation.passed:
            print(
                f"batch={batch_index + 1}/{request.batches} "
                f"qemu={budget.used} result={observation.category}",
                file=sys.stderr,
                flush=True,
            )
            if observation.detail:
                print(observation.detail, file=sys.stderr, flush=True)
            return 1
        baseline = set(store.load_coverage(observation.starry_elf_digest))
        observed_new_regions = set(observation.regions) - baseline
        pending_regions = _pending_attribution_regions(
            spec, store, observation.starry_elf_digest
        )
        new_regions = observed_new_regions - pending_regions
        admitted: Sequence[str] = ()
        result = (
            "unexplained-outcome-saved"
            if observation.category == "unexplained-outcome"
            else "passed-no-new-coverage"
        )
        task: Optional[Task] = None
        if new_regions:
            fixed_elf = fixed_starry_elf(spec, store, coverage_object(spec, workspace))
            task = create_attribution_task(
                spec,
                store,
                selected,
                new_regions,
                fixed_elf,
                request.max_minimize,
                request.minimize_enabled,
                batch_index,
            )
        remaining_batches = request.batches - batch_index - 1
        _recover_background_with_reserve(
            spec,
            hooks,
            workspace,
            store,
            host_oracle,
            budget,
            remaining_batches,
        )
        if task is not None:
            refreshed = TaskStore(spec, store.root, "attribution").load(task.path)
            if refreshed.metadata["state"] == "completed":
                admitted = _completed_attribution_digests(refreshed)
                result = (
                    "passed-unreproducible-coverage"
                    if _completed_attribution_is_unreproducible(refreshed)
                    else "passed-new-coverage"
                )
            else:
                result = "passed-new-coverage-pending-attribution"
        elif set(observation.regions) - set(
            store.load_coverage(observation.starry_elf_digest)
        ):
            result = "passed-pending-attribution"
        for entry in store.load_entries():
            corpus[entry.digest] = entry.encoded
        store.save_run(
            _dated_id("run", batch_index),
            {
                "schema_name": RUN_SCHEMA_NAME,
                "schema_version": RUN_SCHEMA_VERSION,
                "adapter_id": spec.adapter_id,
                "target_set_id": spec.coverage.target_set_id,
                "scenario_sha256": combined_digest(selected),
                "result": result,
                "seed": request.seed,
                "batch_index": batch_index,
                "candidate_count": len(selected),
                "qemu_count": budget.used,
                "new_regions": sorted(new_regions),
                "admitted_digests": sorted(admitted),
            },
        )
        print(
            f"batch={batch_index + 1}/{request.batches} "
            f"candidates={len(selected)} new_regions={len(new_regions)} "
            f"qemu={budget.used} result={result}",
            flush=True,
        )
    pending_count = _pending_task_count(spec, store)
    print(
        f"campaign completed: adapter={spec.adapter_id} "
        f"qemu={budget.used} corpus={len(corpus)} "
        f"background_pending={pending_count}",
        flush=True,
    )
    return 0


def select_batch(
    spec: AdapterSpec,
    hooks: CampaignHooks,
    rng: object,
    corpus: Mapping[str, bytes],
    batch_size: int,
) -> Tuple[BatchInput, ...]:
    candidates: Dict[str, bytes] = {}
    entries = tuple(sorted(corpus.items()))
    attempts = 0
    while len(candidates) < batch_size and attempts < batch_size * 32:
        attempts += 1
        if not entries or _rng_range(rng, 0, 10) < 3:
            encoded = hooks.generate(rng)
        else:
            parent = entries[_rng_range(rng, 0, len(entries))][1]
            donor = entries[_rng_range(rng, 0, len(entries))][1]
            encoded = hooks.mutate(rng, parent, donor)
        if encoded is None:
            continue
        canonical = canonical_entry(spec, encoded)
        digest = hashlib.sha256(canonical).hexdigest()
        candidates[digest] = canonical
    if not candidates:
        raise RuntimeError("candidate selection produced no executable input")
    return tuple(
        BatchInput(digest, encoded)
        for digest, encoded in sorted(candidates.items())
    )


def execute_inputs(
    spec: AdapterSpec,
    workspace: Path,
    store: CampaignStore,
    host_oracle: Path,
    inputs: Tuple[BatchInput, ...],
    budget: QemuBudget,
    *,
    pinned_starry_elf: Optional[Path] = None,
    batch_index: int,
) -> ExecutionObservation:
    return _execute_inputs(
        spec,
        workspace,
        store,
        host_oracle,
        inputs,
        budget,
        pinned_starry_elf=pinned_starry_elf,
        batch_index=batch_index,
    )


def attribute_and_minimize(
    spec: AdapterSpec,
    hooks: CampaignHooks,
    workspace: Path,
    store: CampaignStore,
    host_oracle: Path,
    inputs: Tuple[BatchInput, ...],
    target_regions: Set[str],
    fixed_elf: Path,
    budget: QemuBudget,
    max_minimize: int,
    minimize_enabled: bool,
    batch_index: int,
) -> Tuple[str, ...]:
    task = create_attribution_task(
        spec,
        store,
        inputs,
        target_regions,
        fixed_elf,
        max_minimize,
        minimize_enabled,
        batch_index,
    )
    task_store = TaskStore(spec, store.root, "attribution")
    task = task_store.claim(task)
    return run_attribution_task(
        spec,
        hooks,
        workspace,
        store,
        host_oracle,
        task_store,
        task,
        inputs,
        target_regions,
        fixed_elf,
        budget,
        max_minimize,
        minimize_enabled,
        batch_index,
    )


def create_attribution_task(
    spec: AdapterSpec,
    store: CampaignStore,
    inputs: Tuple[BatchInput, ...],
    target_regions: Set[str],
    fixed_elf: Path,
    max_minimize: int,
    minimize_enabled: bool,
    batch_index: int,
) -> Task:
    return TaskStore(spec, store.root, "attribution").create(
        _dated_id("attribution", batch_index),
        tuple(item.encoded for item in inputs),
        {
            "target_regions": sorted(target_regions),
            "starry_elf_sha256": sha256_file(fixed_elf),
            "max_minimize": max_minimize,
            "minimize_enabled": minimize_enabled,
            "batch_index": batch_index,
        },
    )


def run_attribution_task(
    spec: AdapterSpec,
    hooks: CampaignHooks,
    workspace: Path,
    store: CampaignStore,
    host_oracle: Path,
    task_store: TaskStore,
    task: Task,
    inputs: Tuple[BatchInput, ...],
    target_regions: Set[str],
    fixed_elf: Path,
    budget: QemuBudget,
    max_minimize: int,
    minimize_enabled: bool,
    batch_index: int,
) -> Tuple[str, ...]:
    runtime = TaskRuntime(
        spec,
        hooks,
        workspace,
        store,
        host_oracle,
        budget,
        batch_index,
        execute_inputs,
    )
    return _run_attribution_task(
        runtime,
        task_store,
        task,
        inputs,
        target_regions,
        fixed_elf,
        max_minimize,
        minimize_enabled,
    )


def minimize_representative(
    spec: AdapterSpec,
    hooks: CampaignHooks,
    workspace: Path,
    store: CampaignStore,
    host_oracle: Path,
    parent_task_id: str,
    encoded: bytes,
    responsibility: Set[str],
    fixed_elf: Path,
    budget: QemuBudget,
    max_candidates: int,
    batch_index: int,
) -> bytes:
    runtime = TaskRuntime(
        spec,
        hooks,
        workspace,
        store,
        host_oracle,
        budget,
        batch_index,
        execute_inputs,
    )
    return _minimize_representative(
        runtime,
        parent_task_id,
        encoded,
        responsibility,
        fixed_elf,
        max_candidates,
    )


def run_minimization_task(
    spec: AdapterSpec,
    hooks: CampaignHooks,
    workspace: Path,
    store: CampaignStore,
    host_oracle: Path,
    task_store: TaskStore,
    task: Task,
    encoded: bytes,
    responsibility: Set[str],
    fixed_elf: Path,
    budget: QemuBudget,
    max_candidates: int,
    batch_index: int,
) -> bytes:
    runtime = TaskRuntime(
        spec,
        hooks,
        workspace,
        store,
        host_oracle,
        budget,
        batch_index,
        execute_inputs,
    )
    return _run_minimization_task(
        runtime,
        task_store,
        task,
        encoded,
        responsibility,
        fixed_elf,
        max_candidates,
    )


def recover_pending_tasks(
    spec: AdapterSpec,
    hooks: CampaignHooks,
    workspace: Path,
    store: CampaignStore,
    host_oracle: Path,
    budget: QemuBudget,
) -> None:
    for kind in ("minimization", "attribution"):
        task_store = TaskStore(spec, store.root, kind)
        for task in task_store.recoverable():
            task = task_store.claim(task)
            context = task.metadata["context"]
            elf_digest = _context_digest(context, "starry_elf_sha256")
            fixed_elf = fixed_elf_from_digest(spec, store, elf_digest)
            batch_index = _context_nonnegative_integer(context, "batch_index")
            inputs = tuple(
                BatchInput(hashlib.sha256(encoded).hexdigest(), encoded)
                for encoded in task.inputs
            )
            print(
                f"resuming {spec.adapter_id} {kind} task: "
                f"{task.metadata['task_id']}",
                flush=True,
            )
            if kind == "minimization":
                if len(inputs) != 1:
                    raise PersistentStateError(
                        "minimization task must contain exactly one input"
                    )
                responsibility = _context_string_set(context, "responsibility")
                maximum = _context_nonnegative_integer(
                    context, "max_candidates"
                )
                run_minimization_task(
                    spec,
                    hooks,
                    workspace,
                    store,
                    host_oracle,
                    task_store,
                    task,
                    inputs[0].encoded,
                    responsibility,
                    fixed_elf,
                    budget,
                    maximum,
                    batch_index,
                )
                continue
            targets = _context_string_set(context, "target_regions")
            maximum = _context_nonnegative_integer(context, "max_minimize")
            minimize_enabled = context.get("minimize_enabled")
            if not isinstance(minimize_enabled, bool):
                raise PersistentStateError(
                    "task minimize_enabled context is invalid"
                )
            run_attribution_task(
                spec,
                hooks,
                workspace,
                store,
                host_oracle,
                task_store,
                task,
                inputs,
                targets,
                fixed_elf,
                budget,
                maximum,
                minimize_enabled,
                batch_index,
            )
            completed = task_store.load(task.path)
            baseline = set(store.load_coverage(elf_digest))
            store.save_coverage(
                elf_digest,
                baseline | _completed_attribution_regions(completed),
            )


def _recover_background_with_reserve(
    spec: AdapterSpec,
    hooks: CampaignHooks,
    workspace: Path,
    store: CampaignStore,
    host_oracle: Path,
    budget: CampaignBudget,
    reserved_batches: int,
) -> bool:
    try:
        recover_pending_tasks(
            spec,
            hooks,
            workspace,
            store,
            host_oracle,
            budget.reserving(reserved_batches),
        )
    except CampaignBudgetExhausted as error:
        print(f"background work deferred: {error}", flush=True)
        return False
    return True


def _pending_attribution_regions(
    spec: AdapterSpec, store: CampaignStore, elf_digest: str
) -> Set[str]:
    regions: Set[str] = set()
    task_store = TaskStore(spec, store.root, "attribution")
    for task in task_store.recoverable():
        context = task.metadata["context"]
        if _context_digest(context, "starry_elf_sha256") == elf_digest:
            regions.update(_context_string_set(context, "target_regions"))
    return regions


def _pending_task_count(spec: AdapterSpec, store: CampaignStore) -> int:
    return sum(
        len(TaskStore(spec, store.root, kind).recoverable())
        for kind in ("minimization", "attribution")
    )


def _completed_attribution_digests(task: Task) -> Tuple[str, ...]:
    result = task.metadata["result"]
    if not isinstance(result, dict):
        raise PersistentStateError("completed attribution result is invalid")
    values = result.get("admitted_digests")
    if (
        not isinstance(values, list)
        or values != sorted(set(values))
        or not all(is_digest(value) for value in values)
    ):
        raise PersistentStateError("completed attribution digests are invalid")
    return tuple(values)


def _completed_attribution_regions(task: Task) -> Set[str]:
    result = task.metadata["result"]
    if not isinstance(result, dict):
        raise PersistentStateError("completed attribution result is invalid")
    values = result.get("proven_regions")
    if values is None:
        return _context_string_set(task.metadata["context"], "target_regions")
    if (
        not isinstance(values, list)
        or values != sorted(set(values))
        or not all(isinstance(value, str) and value for value in values)
    ):
        raise PersistentStateError("completed attribution regions are invalid")
    targets = _context_string_set(task.metadata["context"], "target_regions")
    regions = set(values)
    if not regions <= targets:
        raise PersistentStateError("completed attribution regions exceed targets")
    return regions


def _completed_attribution_is_unreproducible(task: Task) -> bool:
    result = task.metadata["result"]
    return (
        isinstance(result, dict)
        and result.get("category") == "unreproducible-coverage"
    )


def combined_digest(inputs: Iterable[BatchInput]) -> str:
    return hashlib.sha256(
        "".join(sorted(item.digest for item in inputs)).encode("ascii")
    ).hexdigest()


def _load_corpus(
    spec: AdapterSpec,
    hooks: CampaignHooks,
    workspace: Path,
    store: CampaignStore,
) -> Dict[str, bytes]:
    corpus: Dict[str, bytes] = {}
    for encoded in hooks.seed_inputs(workspace):
        canonical = canonical_entry(spec, encoded)
        corpus[hashlib.sha256(canonical).hexdigest()] = canonical
    for entry in store.load_entries():
        corpus[entry.digest] = entry.encoded
    if not corpus:
        raise RuntimeError("campaign has no seed inputs")
    return dict(sorted(corpus.items()))


def _require_hooks(spec: AdapterSpec) -> CampaignHooks:
    if spec.campaign_hooks is None:
        raise ValueError("adapter does not provide campaign hooks")
    return spec.campaign_hooks


def _rng_range(rng: object, start: int, stop: int) -> int:
    method = getattr(rng, "range", None)
    if method is None:
        raise TypeError("campaign RNG must provide range(start, stop)")
    value = method(start, stop)
    if not isinstance(value, int) or isinstance(value, bool) or not start <= value < stop:
        raise ValueError("campaign RNG returned an out-of-range value")
    return value


def _context_digest(context: Dict, key: str) -> str:
    value = context.get(key)
    if not is_digest(value):
        raise PersistentStateError(f"task {key} context is invalid")
    return value


def _context_nonnegative_integer(context: Dict, key: str) -> int:
    value = context.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise PersistentStateError(f"task {key} context is invalid")
    return value


def _context_string_set(context: Dict, key: str) -> Set[str]:
    value = context.get(key)
    if not _sorted_string_list(value):
        raise PersistentStateError(f"task {key} context is invalid")
    return set(value)


def _sorted_string_list(value: object) -> bool:
    return (
        isinstance(value, list)
        and value == sorted(set(value))
        and all(isinstance(item, str) and item for item in value)
    )


def _dated_id(kind: str, batch_index: int) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{kind}-{stamp}-batch-{batch_index + 1:04d}"


__all__ = [
    "CampaignReplayError",
    "ExecutionObservation",
    "attribute_and_minimize",
    "combined_digest",
    "execute_inputs",
    "fixed_elf_from_digest",
    "fixed_starry_elf",
    "minimize_representative",
    "recover_pending_tasks",
    "run_attribution_task",
    "run_campaign",
    "run_minimization_task",
    "select_batch",
]
