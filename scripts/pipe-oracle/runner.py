import os
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple


ARTIFACT_DIR_ENV = "STARRY_PIPE_ORACLE_ARTIFACT_DIR"
PINNED_STARRY_ELF_ENV = "AXBUILD_STARRY_KALLSYMS_SOURCE_ELF"
REQUIRED_ARTIFACTS = ("pipe-linux-oracle", "pipe.ops", "linux.trace")
STARRY_PROFRAW = Path("coverage/starryos-x86_64-unknown-none.profraw")
STARRY_COVERAGE_OBJECT = Path("target/x86_64-unknown-none/release/starryos")


def run_guest_compare(
    workspace: Path,
    artifact_dir: Path,
    pinned_starry_elf: Optional[Path] = None,
) -> Tuple[str, List[Path], bool]:
    workspace = workspace.resolve()
    artifact_dir = artifact_dir.resolve()
    _validate_artifact_dir(artifact_dir)
    env = os.environ.copy()
    env[ARTIFACT_DIR_ENV] = str(artifact_dir)
    env.pop(PINNED_STARRY_ELF_ENV, None)
    if pinned_starry_elf is not None:
        pinned_starry_elf = pinned_starry_elf.resolve()
        if not pinned_starry_elf.is_file():
            raise FileNotFoundError(
                f"pinned StarryOS ELF does not exist: {pinned_starry_elf}"
            )
        env[PINNED_STARRY_ELF_ENV] = str(pinned_starry_elf)
    profraw_path = workspace / STARRY_PROFRAW
    profraw_path.unlink(missing_ok=True)

    try:
        result = subprocess.run(
            [
                "cargo",
                "xtask",
                "starry",
                "test",
                "qemu",
                "--arch",
                "x86_64",
                "-c",
                "qemu/pipe-linux-oracle",
            ],
            cwd=str(workspace),
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
        )
        guest_log = result.stdout + "\n" + result.stderr
        passed = result.returncode == 0
    except subprocess.TimeoutExpired as error:
        guest_log = _timeout_output(error) + "\nQEMU command timed out\n"
        passed = False

    profraws = [profraw_path] if profraw_path.is_file() else []
    return guest_log, profraws, passed


def coverage_object(workspace: Path) -> Path:
    return workspace.resolve() / STARRY_COVERAGE_OBJECT


def _validate_artifact_dir(artifact_dir: Path) -> None:
    if not artifact_dir.is_dir():
        raise FileNotFoundError(f"pipe oracle artifact directory does not exist: {artifact_dir}")
    missing = [name for name in REQUIRED_ARTIFACTS if not (artifact_dir / name).is_file()]
    if missing:
        raise FileNotFoundError(
            f"pipe oracle artifact directory {artifact_dir} is missing: {', '.join(missing)}"
        )


def _timeout_output(error: subprocess.TimeoutExpired) -> str:
    stdout = _decode_timeout_stream(error.stdout)
    stderr = _decode_timeout_stream(error.stderr)
    return stdout + "\n" + stderr


def _decode_timeout_stream(stream: Optional[object]) -> str:
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode(errors="replace")
    return str(stream)
