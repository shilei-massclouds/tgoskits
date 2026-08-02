#!/usr/bin/env python3
"""Import a restricted syzkaller program subset into the pipe oracle."""

import argparse
import json
import re
import shlex
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from corpus import CorpusStore
from corpus_errors import CorpusStorageError
from syz_admission import run_admission
from syz_converter import SUPPORTED_SYZKALLER_REVISION
from syz_import import InputDiscoveryError, build_check_report, write_json_report


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse and classify restricted syzkaller pipe programs"
    )
    parser.add_argument("--syzkaller-revision", required=True)
    parser.add_argument("--workspace", type=Path, default=WORKSPACE_ROOT)
    parser.add_argument("--report", type=Path)
    parser.add_argument(
        "--admit",
        action="store_true",
        help="Run host stability, Starry comparison, attribution, and minimization",
    )
    parser.add_argument(
        "--project-vector-slices",
        action="store_true",
        help="Project audited pipe/vector scenarios after lossless conversion fails",
    )
    parser.add_argument("--host-repetitions", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--max-qemu", type=int, default=64)
    parser.add_argument(
        "--max-admit-unique",
        type=int,
        metavar="N",
        help="Admit only the first N unique canonical digests",
    )
    parser.add_argument("paths", metavar="PATH", type=Path, nargs="+")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.syzkaller_revision):
        parser.error("--syzkaller-revision must be a lowercase 40-character commit")
    if args.syzkaller_revision != SUPPORTED_SYZKALLER_REVISION:
        parser.error(
            "unsupported syzkaller revision; this importer is pinned to "
            + SUPPORTED_SYZKALLER_REVISION
        )
    if args.host_repetitions <= 0:
        parser.error("--host-repetitions must be positive")
    if args.batch_size <= 0:
        parser.error("--batch-size must be positive")
    if args.max_qemu < 0:
        parser.error("--max-qemu must be nonnegative")
    if args.max_admit_unique is not None and not args.admit:
        parser.error("--max-admit-unique requires --admit")
    if args.max_admit_unique is not None and args.max_admit_unique <= 0:
        parser.error("--max-admit-unique must be positive")

    try:
        report, infrastructure_failed = build_check_report(
            args.paths,
            args.syzkaller_revision,
            max_admit_unique=args.max_admit_unique,
            project_vector_slices=args.project_vector_slices,
        )
        admission_failed = False
        if args.admit and not infrastructure_failed:
            workspace = args.workspace.resolve()
            corpus_store = CorpusStore(workspace)
            with corpus_store.campaign_lock():
                admission = run_admission(
                    workspace,
                    report,
                    command=shlex.join(sys.argv),
                    host_repetitions=args.host_repetitions,
                    batch_size=args.batch_size,
                    max_qemu=args.max_qemu,
                )
            report["mode"] = "admit"
            report["admission"] = admission
            admission_failed = admission["summary"]["failed"] != 0
        if args.report is not None:
            write_json_report(args.report, report)
    except (InputDiscoveryError, CorpusStorageError, OSError, RuntimeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if infrastructure_failed or admission_failed else 0


if __name__ == "__main__":
    sys.exit(main())
