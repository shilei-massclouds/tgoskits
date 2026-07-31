#!/usr/bin/env python3
"""Minimize a pipe failure artifact or completed attribution job."""

import argparse
import shlex
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from corpus import CorpusStorageError, CorpusStore
from fuzz import (
    WORKSPACE_ROOT,
    _extract_regions,
    _minimization_summary,
    _record_host,
    _run_guest_compare,
)
from minimization_campaign import (
    MinimizationRuntime,
    resume_minimization_job,
)
from minimization_source import create_or_load_job_from_source
from minimization_store import MinimizationStore
from runner import coverage_object


DEFAULT_MAX_QEMU = 64


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Minimize pipe coverage representatives or semantic mismatches"
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("--max-qemu", type=int, default=DEFAULT_MAX_QEMU)
    parser.add_argument("--workspace", type=Path, default=WORKSPACE_ROOT)
    args = parser.parse_args()
    if args.max_qemu < 0:
        parser.error("--max-qemu must be nonnegative")
    workspace = args.workspace.resolve()
    corpus_store = CorpusStore(workspace)
    minimization_store = MinimizationStore(
        workspace,
        corpus_store.generator_version,
    )
    runtime = MinimizationRuntime(
        record_host=_record_host,
        run_guest_compare=_run_guest_compare,
        extract_regions=_extract_regions,
        coverage_object=coverage_object,
    )
    try:
        with corpus_store.campaign_lock():
            job = create_or_load_job_from_source(
                workspace,
                args.source,
                corpus_store,
                minimization_store,
                max_qemu=args.max_qemu,
                active_starry_elf=coverage_object(workspace),
            )
            was_resumed = job.metadata["state"] != "validating"
            outcome = resume_minimization_job(
                workspace,
                corpus_store,
                minimization_store,
                job,
                runtime,
            )
            if not outcome.failed:
                completed = minimization_store.load_job(job.job_id)
                run_path = corpus_store.runs_dir / job.job_id
                if not run_path.exists():
                    corpus_store.save_run(
                        job.job_id,
                        {
                            "command": shlex.join(sys.argv),
                            "result": "passed",
                            "minimization": _minimization_summary(
                                outcome,
                                completed,
                            ),
                            "resumed": was_resumed,
                        },
                    )
                minimization_store.mark_run_recorded(completed)
    except (CorpusStorageError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if outcome.failed:
        print(f"MINIMIZATION {outcome.category.upper()}: {outcome.job_id}")
        return 1
    print(
        "MINIMIZATION COMPLETED: "
        f"job={outcome.job_id} mode={outcome.completion} "
        f"candidate-qemu={outcome.candidate_qemu} proof-qemu={outcome.proof_qemu}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
