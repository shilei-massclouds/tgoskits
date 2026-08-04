"""Eventfd compatibility binding for common strict campaign persistence."""

import sys
from pathlib import Path

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from adapter import SPEC
from linux_oracle.persistence import (
    CORPUS_SCHEMA_NAME,
    CORPUS_SCHEMA_VERSION,
    COVERAGE_SCHEMA_NAME,
    COVERAGE_SCHEMA_VERSION,
    RUN_SCHEMA_NAME,
    RUN_SCHEMA_VERSION,
    CampaignStore,
    CorpusEntry,
    PersistentStateError,
    atomic_replace_file,
    atomic_save_directory,
)


ADAPTER_ID = SPEC.adapter_id
CAMPAIGN_ROOT = SPEC.campaign.root


class CorpusStore(CampaignStore):
    def __init__(self, workspace: Path):
        super().__init__(SPEC, workspace)


__all__ = [
    "ADAPTER_ID",
    "CAMPAIGN_ROOT",
    "CORPUS_SCHEMA_NAME",
    "CORPUS_SCHEMA_VERSION",
    "COVERAGE_SCHEMA_NAME",
    "COVERAGE_SCHEMA_VERSION",
    "CorpusEntry",
    "CorpusStore",
    "PersistentStateError",
    "RUN_SCHEMA_NAME",
    "RUN_SCHEMA_VERSION",
    "atomic_replace_file",
    "atomic_save_directory",
]
