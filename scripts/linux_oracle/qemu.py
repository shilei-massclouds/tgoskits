"""QEMU lifecycle shared by synchronous differential adapters."""

import os
import subprocess
from pathlib import Path
from typing import Optional

from .spec import AdapterSpec


PINNED_STARRY_ELF_ENV_DEFAULT = "AXBUILD_STARRY_KALLSYMS_SOURCE_ELF"


def run_guest_compare(
    spec: AdapterSpec,
    workspace: Path,
    artifact_dir: Path,
    *,
    pinned_starry_elf: Optional[Path] = None,
) -> object:
    workspace = workspace.resolve()
    artifact_dir = artifact_dir.resolve()
    validate_artifact_directory(spec, artifact_dir)
    environment = os.environ.copy()
    environment[spec.qemu.artifact_environment] = str(artifact_dir)
    environment.pop(spec.qemu.pinned_elf_environment, None)
    if pinned_starry_elf is not None:
        pinned_starry_elf = pinned_starry_elf.resolve()
        if pinned_starry_elf.is_symlink() or not pinned_starry_elf.is_file():
            raise FileNotFoundError(
                f"pinned StarryOS ELF does not exist: {pinned_starry_elf}"
            )
        environment[spec.qemu.pinned_elf_environment] = str(pinned_starry_elf)
    profraw = workspace / spec.qemu.profraw_path
    profraw.unlink(missing_ok=True)
    try:
        completed = subprocess.run(
            qemu_command(spec),
            cwd=str(workspace),
            env=environment,
            capture_output=True,
            text=True,
            timeout=spec.qemu.timeout_seconds,
        )
        log = completed.stdout + "\n" + completed.stderr
        return spec.classify_guest(
            log,
            completed.returncode,
            (profraw,) if profraw.is_file() else (),
        )
    except subprocess.TimeoutExpired as error:
        log = (
            _decode_timeout_stream(error.stdout)
            + "\n"
            + _decode_timeout_stream(error.stderr)
            + "\nQEMU command timed out\n"
        )
        return spec.classify_guest(log, None, (), timed_out=True)
    except OSError as error:
        return spec.classify_guest(
            f"QEMU command failed to start: {error}\n", None, ()
        )


def qemu_command(spec: AdapterSpec) -> list[str]:
    return [
        "cargo",
        "xtask",
        "starry",
        "test",
        "qemu",
        "--arch",
        spec.qemu.architecture,
        "-c",
        spec.qemu.case,
    ]


def coverage_object(spec: AdapterSpec, workspace: Path) -> Path:
    return workspace.resolve() / spec.qemu.coverage_object_path


def validate_artifact_directory(spec: AdapterSpec, artifact_dir: Path) -> None:
    if artifact_dir.is_symlink() or not artifact_dir.is_dir():
        raise FileNotFoundError(
            f"oracle artifact directory does not exist: {artifact_dir}"
        )
    missing = [
        name
        for name in spec.artifacts.required_execution_files
        if (artifact_dir / name).is_symlink() or not (artifact_dir / name).is_file()
    ]
    if missing:
        raise FileNotFoundError(
            f"oracle artifact directory {artifact_dir} is missing: {', '.join(missing)}"
        )


def _decode_timeout_stream(stream: Optional[object]) -> str:
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode(errors="replace")
    return str(stream)
