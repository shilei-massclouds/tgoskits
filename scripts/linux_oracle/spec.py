"""Immutable adapter contracts consumed by the common execution layer."""

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional, Protocol, Sequence, Tuple


class HostRecordResultLike(Protocol):
    passed: bool
    parser_rejection: bool
    log: str


class GuestResultLike(Protocol):
    passed: bool
    log: str
    profraw_paths: Tuple[Path, ...]
    category: object


@dataclass(frozen=True)
class ReductionHooks:
    """Adapter-owned structured reduction across a canonical-byte boundary."""

    initial: Callable[[bytes], object]
    candidates: Callable[[object], Iterable[object]]
    encode: Callable[[object], bytes]
    complexity: Callable[[object], tuple]


@dataclass(frozen=True)
class CampaignHooks:
    """Scenario semantics required by the common campaign state machine."""

    find_or_build_host: Callable[[Path], Optional[Path]]
    seed_inputs: Callable[[Path], Iterable[bytes]]
    make_rng: Callable[[int], object]
    generate: Callable[[object], Optional[bytes]]
    mutate: Callable[[object, bytes, bytes], Optional[bytes]]
    reduction: ReductionHooks
    recover_legacy: Optional[Callable[[Path, Path], None]] = None


@dataclass(frozen=True)
class ArtifactLayout:
    scenario_filename: str
    trace_filename: str
    host_executable_filename: str
    guest_log_filename: str = "guest.log"
    starry_elf_filename: str = "starryos"
    profraw_directory: str = "profraws"

    def __post_init__(self) -> None:
        values = (
            self.scenario_filename,
            self.trace_filename,
            self.host_executable_filename,
            self.guest_log_filename,
            self.starry_elf_filename,
            self.profraw_directory,
        )
        if len(set(values)) != len(values):
            raise ValueError("artifact names must be unique")
        for value in values:
            _require_filename(value)

    @property
    def required_execution_files(self) -> Tuple[str, str, str]:
        return (
            self.host_executable_filename,
            self.scenario_filename,
            self.trace_filename,
        )


@dataclass(frozen=True)
class CampaignLayout:
    root: Path
    corpus_directory: str = "corpus"
    run_directory: str = "runs"
    coverage_directory: str = "coverage-state"
    failure_directory: str = "failures"
    attribution_task_directory: str = "attribution-jobs"
    minimization_task_directory: str = "minimization-jobs"
    elf_directory: str = "elfs"

    def __post_init__(self) -> None:
        if self.root.is_absolute() or not self.root.parts:
            raise ValueError("campaign root must be a non-empty relative path")
        for value in (
            self.corpus_directory,
            self.run_directory,
            self.coverage_directory,
            self.failure_directory,
            self.attribution_task_directory,
            self.minimization_task_directory,
            self.elf_directory,
        ):
            _require_filename(value)


@dataclass(frozen=True)
class QemuSpec:
    case: str
    artifact_environment: str
    pinned_elf_environment: str
    architecture: str
    profraw_path: Path
    coverage_object_path: Path
    timeout_seconds: int = 600

    def __post_init__(self) -> None:
        if not self.case or self.case.startswith("/") or ".." in Path(self.case).parts:
            raise ValueError("QEMU case must be a safe relative selector")
        if not self.artifact_environment or not self.pinned_elf_environment:
            raise ValueError("QEMU environment names must be non-empty")
        if not self.architecture or self.timeout_seconds <= 0:
            raise ValueError("QEMU architecture and timeout must be valid")
        if self.profraw_path.is_absolute() or self.coverage_object_path.is_absolute():
            raise ValueError("QEMU output paths must be workspace relative")


@dataclass(frozen=True)
class CoverageTarget:
    target_set_id: str
    source_paths: Tuple[str, ...]

    def __post_init__(self) -> None:
        _require_identifier(self.target_set_id, "target set id")
        if not self.source_paths or len(set(self.source_paths)) != len(self.source_paths):
            raise ValueError("coverage sources must be non-empty and unique")
        if tuple(sorted(self.source_paths)) != self.source_paths:
            raise ValueError("coverage sources must be sorted")
        for source in self.source_paths:
            if not source or source.startswith("/") or ".." in Path(source).parts:
                raise ValueError(f"invalid coverage source: {source}")


@dataclass(frozen=True)
class CodecSpec:
    parse: Callable[[bytes], object]
    serialize: Callable[[object], bytes]
    combine: Callable[[Sequence[object]], object]
    validate_entry: Callable[[object], None]
    scenario_count: Callable[[object], int]


@dataclass(frozen=True)
class AdapterSpec:
    """Complete scenario-neutral dependency injection for one adapter."""

    adapter_id: str
    adapter_version: int
    corpus_version: int
    generator_version: str
    artifacts: ArtifactLayout
    campaign: CampaignLayout
    qemu: QemuSpec
    coverage: CoverageTarget
    codec: CodecSpec
    host_record: Callable[[Path, Path, Path], HostRecordResultLike]
    classify_guest: Callable[..., object]
    normalize_guest: Callable[[object], object]
    campaign_hooks: Optional[CampaignHooks] = None
    generate: Optional[Callable[..., object]] = None
    mutate: Optional[Callable[..., object]] = None
    reduce: Optional[Callable[..., object]] = None

    def __post_init__(self) -> None:
        _require_identifier(self.adapter_id, "adapter id")
        if self.adapter_version <= 0 or self.corpus_version <= 0:
            raise ValueError("adapter and corpus versions must be positive")
        if not self.generator_version:
            raise ValueError("generator version must be non-empty")


def _require_filename(value: str) -> None:
    if not value or value in (".", "..") or Path(value).name != value:
        raise ValueError(f"artifact name must be a single filename: {value}")


def _require_identifier(value: str, label: str) -> None:
    if not value or any(character.isspace() for character in value) or "/" in value:
        raise ValueError(f"{label} must be a non-empty path-free identifier")
