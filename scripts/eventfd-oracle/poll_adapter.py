"""Adapter specification for controlled eventfd blocking poll scenarios."""

import sys
from pathlib import Path

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

import poll_coverage
import poll_generator
import poll_mutation
import poll_reducer
import poll_scenario
from guest_result import classify_guest_execution, normalize_guest_execution
from host_runtime import find_or_build_host_oracle
from host_runtime import record_host as record_host_once
from linux_oracle.batch import HostRecordResult
from linux_oracle.host_record import record_stable_host
from linux_oracle.spec import (
    AdapterSpec,
    ArtifactLayout,
    CampaignHooks,
    CampaignLayout,
    CodecSpec,
    CoverageTarget,
    QemuSpec,
    ReductionHooks,
)


def record_host_stable(
    elf: Path, scenario_path: Path, trace_path: Path
) -> HostRecordResult:
    """Accept a v3 candidate only after three identical host recordings."""
    return record_stable_host(
        record_host_once,
        elf,
        scenario_path,
        trace_path,
        temporary_prefix=".eventfd-blocking-v2-host-",
    )


def _serialize(document: object) -> bytes:
    return poll_scenario.serialize_document(document).encode("utf-8")


def _scenario_count(document: object) -> int:
    return len(document.scenarios)


def _seed_inputs(workspace: Path):
    checked = (
        workspace
        / "test-suit/starryos/qemu/eventfd-linux-oracle/c/corpus/eventfd-blocking-poll.ops"
    )
    yield checked.read_bytes()
    for seed in range(5):
        yield poll_generator.canonicalize_seed(seed).encoded


def _generate(rng: object):
    return poll_generator.generate_input(rng).encoded


def _mutate(rng: object, parent: bytes, donor: bytes):
    candidate = poll_mutation.mutate_document(
        rng,
        poll_scenario.parse_document(parent),
        poll_scenario.parse_document(donor),
    )
    if candidate.classification is not poll_mutation.CandidateClassification.EXECUTABLE:
        return None
    return candidate.encoded


def _reduction_initial(encoded: bytes):
    return poll_reducer.with_origins(poll_scenario.parse_document(encoded))


def _reduction_candidates(document: object):
    return (
        candidate.document
        for candidate in poll_reducer.reduction_candidates(document)
    )


def _reduction_encode(document: object) -> bytes:
    return poll_scenario.serialize_document(document.plain()).encode("utf-8")


SPEC = AdapterSpec(
    adapter_id="eventfd-blocking-v2",
    adapter_version=2,
    corpus_version=3,
    generator_version=poll_generator.GENERATOR_VERSION,
    artifacts=ArtifactLayout(
        "eventfd.ops", "linux.trace", "eventfd-linux-oracle"
    ),
    campaign=CampaignLayout(Path("coverage/eventfd-blocking-v2-oracle-fuzz")),
    qemu=QemuSpec(
        case="qemu/eventfd-linux-oracle",
        artifact_environment="STARRY_EVENTFD_ORACLE_ARTIFACT_DIR",
        pinned_elf_environment="AXBUILD_STARRY_KALLSYMS_SOURCE_ELF",
        architecture="x86_64",
        profraw_path=Path("coverage/starryos-x86_64-unknown-none.profraw"),
        coverage_object_path=Path("target/x86_64-unknown-none/release/starryos"),
    ),
    coverage=CoverageTarget(
        poll_coverage.TARGET_SET_ID,
        poll_coverage.TARGET_SOURCE_PATHS,
    ),
    codec=CodecSpec(
        poll_scenario.parse_document,
        _serialize,
        poll_scenario.combine_documents,
        poll_scenario.validate_entry_limits,
        _scenario_count,
    ),
    host_record=record_host_stable,
    classify_guest=classify_guest_execution,
    normalize_guest=normalize_guest_execution,
    campaign_hooks=CampaignHooks(
        find_or_build_host=find_or_build_host_oracle,
        seed_inputs=_seed_inputs,
        make_rng=poll_generator.CampaignRng,
        generate=_generate,
        mutate=_mutate,
        reduction=ReductionHooks(
            initial=_reduction_initial,
            candidates=_reduction_candidates,
            encode=_reduction_encode,
            complexity=poll_reducer.complexity_key,
        ),
    ),
    generate=poll_generator.generate_input,
    mutate=poll_mutation.mutate_document,
    reduce=poll_reducer.reduction_candidates,
)


__all__ = [
    "HostRecordResult",
    "SPEC",
    "record_host_once",
    "record_host_stable",
]
