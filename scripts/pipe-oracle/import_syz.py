#!/usr/bin/env python3
"""Import a restricted syzkaller program subset into the pipe oracle."""

import argparse
import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

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
    parser.add_argument("paths", metavar="PATH", type=Path, nargs="+")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.syzkaller_revision):
        parser.error("--syzkaller-revision must be a lowercase 40-character commit")
    if args.syzkaller_revision != SUPPORTED_SYZKALLER_REVISION:
        parser.error(
            "unsupported syzkaller revision; this importer is pinned to "
            + SUPPORTED_SYZKALLER_REVISION
        )

    try:
        report, infrastructure_failed = build_check_report(
            args.paths,
            args.syzkaller_revision,
        )
        if args.report is not None:
            write_json_report(args.report, report)
    except (InputDiscoveryError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if infrastructure_failed else 0


if __name__ == "__main__":
    sys.exit(main())
