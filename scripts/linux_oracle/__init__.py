"""Scenario-neutral infrastructure for Linux/Starry differential adapters."""

from .spec import (
    AdapterSpec,
    ArtifactLayout,
    CampaignLayout,
    CodecSpec,
    CoverageTarget,
    QemuSpec,
)

__all__ = [
    "AdapterSpec",
    "ArtifactLayout",
    "CampaignLayout",
    "CodecSpec",
    "CoverageTarget",
    "QemuSpec",
]
