#!/usr/bin/env python3
"""Compatibility CLI for the common deterministic differential campaign."""

import argparse
import shlex
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_ROOT = SCRIPT_DIR.parent
for root in (SCRIPT_DIR, SCRIPTS_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from adapter import SPEC
from attribution import AttributionStore
from batch_execution import HostRecordResult
from corpus import CorpusStorageError, CorpusStore
import legacy_campaign as _legacy
from legacy_campaign import (
    BatchResult,
    CampaignRng,
    CampaignStats,
    _build_run_metadata,
    _extract_regions,
    _find_or_build_host_oracle,
    _load_active_corpus,
    _minimization_summary,
    _record_host,
    _resume_attribution_job,
    _resume_minimization_work,
    _resume_saved_jobs,
    _run_batch,
    _run_campaign,
    _run_guest_compare,
    _save_batch_failure,
    _select_batch,
    coverage_object,
    run_guest_compare,
)
from linux_oracle.campaign import CampaignRequest
from linux_oracle.driver import run_campaign
from linux_oracle.persistence import PersistentStateError
from minimization_store import MinimizationStore


DEFAULT_SEED = 42
DEFAULT_BATCHES = 4
DEFAULT_BATCH_SIZE = 32
WORKSPACE_ROOT = Path(__file__).resolve().parents[2]

_LEGACY_RUN_BATCH = _legacy._run_batch
_LEGACY_RUN_CAMPAIGN = _legacy._run_campaign
_LEGACY_RESUME_ATTRIBUTION = _legacy._resume_attribution_job


def _sync_legacy_hooks() -> None:
    _legacy.CampaignRng = CampaignRng
    _legacy._find_or_build_host_oracle = _find_or_build_host_oracle
    _legacy._load_active_corpus = _load_active_corpus
    _legacy._record_host = _record_host
    _legacy._resume_minimization_work = _resume_minimization_work
    _legacy._resume_saved_jobs = _resume_saved_jobs
    _legacy._run_guest_compare = _run_guest_compare
    _legacy._save_batch_failure = _save_batch_failure
    _legacy.run_guest_compare = run_guest_compare
    _legacy.coverage_object = coverage_object
    _legacy._extract_regions = _extract_regions


def _run_guest_compare(workspace, artifact_dir, pinned_starry_elf=None):
    return run_guest_compare(workspace, artifact_dir, pinned_starry_elf)


def _run_batch(*args, **kwargs):
    _sync_legacy_hooks()
    return _LEGACY_RUN_BATCH(*args, **kwargs)


def _resume_attribution_job(*args, **kwargs):
    _sync_legacy_hooks()
    return _LEGACY_RESUME_ATTRIBUTION(*args, **kwargs)


def _run_campaign(*args, **kwargs):
    _sync_legacy_hooks()
    _legacy._run_batch = _run_batch
    _legacy._resume_attribution_job = _resume_attribution_job
    return _LEGACY_RUN_CAMPAIGN(*args, **kwargs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--batches", type=int, default=DEFAULT_BATCHES)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--workspace", type=Path, default=WORKSPACE_ROOT)
    parser.add_argument("--max-qemu", type=int, default=64)
    parser.add_argument("--max-minimize", type=int, default=8)
    parser.add_argument("--no-minimize", action="store_true")
    args = parser.parse_args()
    try:
        request = CampaignRequest(
            args.seed,
            args.batches,
            args.batch_size,
            args.max_qemu,
            args.max_minimize,
            not args.no_minimize,
        )
        workspace = args.workspace.resolve()
        legacy_store = CorpusStore(workspace)
        with legacy_store.campaign_lock():
            if _recover_legacy(
                workspace,
                legacy_store,
                shlex.join(sys.argv),
                args.max_qemu,
                request.minimize_enabled,
            ):
                return 1
            return run_campaign(SPEC, request, workspace)
    except (CorpusStorageError, OSError, PersistentStateError, RuntimeError, ValueError) as error:
        print(f"{SPEC.adapter_id} campaign failed: {error}", file=sys.stderr)
        return 1


def _recover_legacy(
    workspace: Path,
    store: CorpusStore,
    command: str,
    max_qemu: int,
    minimize_enabled: bool,
) -> bool:
    attribution_store = AttributionStore(workspace, store.generator_version)
    corpus, _built_in, _disk = _load_active_corpus(store)
    if _resume_saved_jobs(workspace, store, attribution_store, corpus, command):
        return True
    if not minimize_enabled:
        return False
    return _resume_minimization_work(
        workspace,
        store,
        attribution_store,
        MinimizationStore(workspace, store.generator_version),
        command,
        max_qemu,
    )


if __name__ == "__main__":
    raise SystemExit(main())
    _minimization_summary,
    _record_host,
    _save_batch_failure,
