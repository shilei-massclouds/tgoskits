"""Eventfd semantic capabilities injected into the common oracle framework."""

import sys
from pathlib import Path

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

import coverage as eventfd_coverage
import generator
import mutation
import reducer
from guest_result import classify_guest_execution, normalize_guest_execution
from host_runtime import find_or_build_host_oracle
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
from scenario import (
    combine_documents,
    parse_document,
    serialize_document,
    validate_entry_limits,
)


def _serialize(document: object) -> bytes:
    return serialize_document(document).encode("utf-8")


def _scenario_count(document: object) -> int:
    return len(document.scenarios)


def _record_host(elf: Path, scenario_path: Path, trace_path: Path):
    from host_runtime import record_host

    return record_host(elf, scenario_path, trace_path)


def _seed_inputs(workspace: Path):
    checked = (
        workspace
        / "test-suit/starryos/qemu/eventfd-linux-oracle/c/corpus/eventfd.ops"
    )
    yield checked.read_bytes()
    for seed in range(5):
        yield generator.canonicalize_seed(seed).encoded


def _generate(rng: object):
    return generator.generate_input(rng).encoded


def _mutate(rng: object, parent: bytes, donor: bytes):
    candidate = mutation.mutate_document(
        rng,
        parse_document(parent),
        parse_document(donor),
    )
    if candidate.classification is not mutation.CandidateClassification.EXECUTABLE:
        return None
    return candidate.encoded


def _reduction_initial(encoded: bytes):
    return reducer.with_origins(parse_document(encoded))


def _reduction_candidates(document: object):
    return (
        candidate.document
        for candidate in reducer.reduction_candidates(document)
    )


def _reduction_encode(document: object) -> bytes:
    return serialize_document(document.plain()).encode("utf-8")


SPEC = AdapterSpec(
    adapter_id="eventfd-v1",
    adapter_version=1,
    corpus_version=1,
    generator_version=generator.GENERATOR_VERSION,
    artifacts=ArtifactLayout(
        "eventfd.ops", "linux.trace", "eventfd-linux-oracle"
    ),
    campaign=CampaignLayout(Path("coverage/eventfd-oracle-fuzz")),
    qemu=QemuSpec(
        case="qemu/eventfd-linux-oracle",
        artifact_environment="STARRY_EVENTFD_ORACLE_ARTIFACT_DIR",
        pinned_elf_environment="AXBUILD_STARRY_KALLSYMS_SOURCE_ELF",
        architecture="x86_64",
        profraw_path=Path("coverage/starryos-x86_64-unknown-none.profraw"),
        coverage_object_path=Path("target/x86_64-unknown-none/release/starryos"),
    ),
    coverage=CoverageTarget(
        eventfd_coverage.TARGET_SET_ID,
        tuple(sorted(eventfd_coverage.TARGET_SOURCE_PATHS)),
    ),
    codec=CodecSpec(
        parse_document,
        _serialize,
        combine_documents,
        validate_entry_limits,
        _scenario_count,
    ),
    host_record=_record_host,
    classify_guest=classify_guest_execution,
    normalize_guest=normalize_guest_execution,
    campaign_hooks=CampaignHooks(
        find_or_build_host=find_or_build_host_oracle,
        seed_inputs=_seed_inputs,
        make_rng=generator.CampaignRng,
        generate=_generate,
        mutate=_mutate,
        reduction=ReductionHooks(
            initial=_reduction_initial,
            candidates=_reduction_candidates,
            encode=_reduction_encode,
            complexity=reducer.complexity_key,
        ),
    ),
    generate=generator.generate_input,
    mutate=mutation.mutate_document,
    reduce=reducer.reduction_candidates,
)


__all__ = ["SPEC"]
