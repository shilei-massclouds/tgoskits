"""Scenario-neutral QEMU execution, coverage extraction, and ELF pinning."""

import dataclasses
import hashlib
import shutil
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

from .batch import BatchInput, execute_batch
from .campaign import QemuBudget
from .coverage import covered_region_set, merge_profraws
from .failure import save_failure
from .persistence import (
    CampaignStore,
    PersistentStateError,
    atomic_save_directory,
)
from .qemu import coverage_object, run_guest_compare
from .spec import AdapterSpec


@dataclass(frozen=True)
class ExecutionObservation:
    passed: bool
    category: str
    regions: Tuple[str, ...]
    starry_elf_digest: str


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
    def run_charged_guest(
        guest_workspace: Path,
        artifact_dir: Path,
        guest_pinned_starry_elf: Optional[Path],
    ) -> object:
        budget.charge()
        return run_guest_compare(
            spec,
            guest_workspace,
            artifact_dir,
            pinned_starry_elf=guest_pinned_starry_elf,
        )

    with execute_batch(
        spec,
        workspace,
        inputs,
        host_oracle,
        run_guest=run_charged_guest,
        pinned_starry_elf=pinned_starry_elf,
    ) as execution:
        if not execution.host_record.passed:
            category = (
                "host-parser-rejection"
                if execution.host_record.parser_rejection
                else "host-record-failure"
            )
            return ExecutionObservation(False, category, (), "")
        guest = execution.guest_result
        if guest is None:
            return ExecutionObservation(False, "missing-guest-result", (), "")
        starry_elf = coverage_object(spec, workspace)
        category = _category_value(guest.category)
        if not guest.passed:
            _save_execution_failure(
                spec, store, execution, starry_elf, category, batch_index
            )
            return ExecutionObservation(False, category, (), "")
        if not guest.profraw_paths or not starry_elf.is_file():
            _save_execution_failure(
                spec,
                store,
                execution,
                starry_elf,
                "coverage-missing",
                batch_index,
            )
            return ExecutionObservation(False, "coverage-missing", (), "")
        elf_digest = sha256_file(starry_elf)
        if pinned_starry_elf is not None and elf_digest != sha256_file(
            pinned_starry_elf
        ):
            return ExecutionObservation(False, "starry-elf-changed", (), elf_digest)
        with tempfile.TemporaryDirectory() as temporary_directory:
            profdata = Path(temporary_directory) / "campaign.profdata"
            merge_profraws(guest.profraw_paths, profdata)
            regions = covered_region_set(spec.coverage, profdata, starry_elf)
        return ExecutionObservation(
            True, "passed", tuple(sorted(regions)), elf_digest
        )


def fixed_starry_elf(
    spec: AdapterSpec, store: CampaignStore, active_elf: Path
) -> Path:
    digest = sha256_file(active_elf)
    root = store.root / spec.campaign.elf_directory / digest
    fixed = root / spec.artifacts.starry_elf_filename
    if fixed.exists():
        if fixed.is_symlink() or not fixed.is_file() or sha256_file(fixed) != digest:
            raise PersistentStateError("fixed kernel ELF digest mismatch")
        return fixed

    def save(temporary: Path) -> None:
        shutil.copy2(active_elf, temporary / spec.artifacts.starry_elf_filename)

    atomic_save_directory(root, save)
    return fixed


def fixed_elf_from_digest(
    spec: AdapterSpec, store: CampaignStore, digest: str
) -> Path:
    fixed = (
        store.root
        / spec.campaign.elf_directory
        / digest
        / spec.artifacts.starry_elf_filename
    )
    if fixed.is_symlink() or not fixed.is_file() or sha256_file(fixed) != digest:
        raise PersistentStateError("resumable task fixed kernel ELF is unavailable")
    return fixed


def sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError(f"ELF is not a regular file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _save_execution_failure(
    spec: AdapterSpec,
    store: CampaignStore,
    execution: object,
    starry_elf: Path,
    category: str,
    batch_index: int,
) -> None:
    guest = execution.guest_result
    if guest is None or not starry_elf.is_file() or not execution.trace_path.is_file():
        return
    difference = getattr(guest, "difference", None)
    if difference is None:
        mismatch = None
    elif dataclasses.is_dataclass(difference):
        mismatch = dataclasses.asdict(difference)
    elif isinstance(difference, dict):
        mismatch = difference
    else:
        mismatch = vars(difference)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = store.failures_root / (
        f"failure-{category}-{stamp}-batch-{batch_index + 1:04d}"
    )
    save_failure(
        spec,
        destination,
        scenario_path=execution.scenario_path,
        trace_path=execution.trace_path,
        host_elf_path=execution.host_oracle_path,
        starry_elf_path=starry_elf,
        guest_log=guest.log,
        profraw_paths=guest.profraw_paths,
        result_category=category,
        mismatch=mismatch,
    )
    print(f"failure saved: {destination}", file=sys.stderr, flush=True)


def _category_value(category: object) -> str:
    value = getattr(category, "value", category)
    if not isinstance(value, str) or not value:
        raise TypeError("guest result category must be a non-empty string")
    return value


__all__ = [
    "ExecutionObservation",
    "execute_inputs",
    "fixed_elf_from_digest",
    "fixed_starry_elf",
    "sha256_file",
]
