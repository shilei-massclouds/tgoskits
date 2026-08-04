#!/usr/bin/env python3
"""Compatibility CLI for the common deterministic differential campaign."""

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from linux_oracle.campaign import CampaignRequest
from linux_oracle.driver import run_campaign as _run_common_campaign
from linux_oracle.persistence import PersistentStateError
from models import DEFAULT_MODEL, MODEL_NAMES, spec_for_model


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--batches", type=int, default=4)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--max-qemu", type=int, default=64)
    parser.add_argument("--max-minimize", type=int, default=8)
    parser.add_argument("--no-minimize", action="store_true")
    parser.add_argument("--model", choices=MODEL_NAMES, default=DEFAULT_MODEL)
    parser.add_argument(
        "--workspace", type=Path, default=Path(__file__).resolve().parents[2]
    )
    args = parser.parse_args(argv)
    spec = spec_for_model(args.model)
    try:
        request = CampaignRequest(
            args.seed,
            args.batches,
            args.batch_size,
            args.max_qemu,
            args.max_minimize,
            not args.no_minimize,
        )
        return _run_common_campaign(spec, request, args.workspace)
    except (OSError, PersistentStateError, RuntimeError, ValueError) as error:
        print(f"{spec.adapter_id} campaign failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
