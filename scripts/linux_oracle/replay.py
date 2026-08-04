"""Replay parameter construction from a validated adapter artifact."""

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Tuple

from .qemu import qemu_command
from .spec import AdapterSpec


@dataclass(frozen=True)
class ReplayInvocation:
    command: Tuple[str, ...]
    environment: Mapping[str, str]
    artifact_directory: Path
    pinned_starry_elf: Path


def build_replay_invocation(
    spec: AdapterSpec, artifact_directory: Path, pinned_starry_elf: Path
) -> ReplayInvocation:
    artifact_directory = artifact_directory.resolve()
    pinned_starry_elf = pinned_starry_elf.resolve()
    return ReplayInvocation(
        tuple(qemu_command(spec)),
        {
            spec.qemu.artifact_environment: str(artifact_directory),
            spec.qemu.pinned_elf_environment: str(pinned_starry_elf),
        },
        artifact_directory,
        pinned_starry_elf,
    )
