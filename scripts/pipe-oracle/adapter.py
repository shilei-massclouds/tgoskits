"""Pipe semantic capabilities injected into the common oracle framework."""

import sys
from pathlib import Path

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

import coverage as pipe_coverage
import generator
import mutation
import reducer
from guest_result import classify_guest_execution, normalize_guest_execution
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


def _find_or_build_host(workspace: Path):
    from host_runtime import find_or_build_host_oracle

    return find_or_build_host_oracle(workspace)


def _seed_inputs(workspace: Path):
    from corpus import CanonicalCorpus, CorpusStore

    seeds = CanonicalCorpus.initial()
    persisted = CorpusStore(workspace).load_corpus()
    for entry in seeds.ordered_entries():
        yield entry.encoded
    for entry in persisted.ordered_entries():
        yield entry.encoded


def _generate(rng: object) -> bytes:
    return serialize_document(generator.generate_document(rng)).encode("utf-8")


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
    return reducer.ReductionInput.initial(parse_document(encoded))


def _reduction_candidates(reduction_input: object):
    structured = reducer.StructuredReducer(reduction_input)
    while candidate := structured.next_candidate():
        yield candidate.reduction_input


def _reduction_encode(reduction_input: object) -> bytes:
    return serialize_document(reduction_input.document).encode("utf-8")


def _reduction_complexity(reduction_input: object) -> tuple:
    return reducer.complexity_key(reduction_input.document)


SPEC = AdapterSpec(
    adapter_id="pipe-v4",
    adapter_version=4,
    corpus_version=4,
    generator_version=generator.GENERATOR_VERSION,
    artifacts=ArtifactLayout("pipe.ops", "linux.trace", "pipe-linux-oracle"),
    campaign=CampaignLayout(
        Path("coverage/pipe-oracle-fuzz"),
        corpus_directory="common-corpus",
        run_directory="common-runs",
        coverage_directory="common-coverage-state",
        failure_directory="common-failures",
        attribution_task_directory="common-attribution-jobs",
        minimization_task_directory="common-minimization-jobs",
        elf_directory="common-elfs",
    ),
    qemu=QemuSpec(
        case="qemu/pipe-linux-oracle",
        artifact_environment="STARRY_PIPE_ORACLE_ARTIFACT_DIR",
        pinned_elf_environment="AXBUILD_STARRY_KALLSYMS_SOURCE_ELF",
        architecture="x86_64",
        profraw_path=Path("coverage/starryos-x86_64-unknown-none.profraw"),
        coverage_object_path=Path("target/x86_64-unknown-none/release/starryos"),
    ),
    coverage=CoverageTarget(
        pipe_coverage.TARGET_SET_ID,
        tuple(sorted(pipe_coverage.TARGET_SOURCE_PATHS[pipe_coverage.TARGET_SET_ID])),
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
        find_or_build_host=_find_or_build_host,
        seed_inputs=_seed_inputs,
        make_rng=generator.CampaignRng,
        generate=_generate,
        mutate=_mutate,
        reduction=ReductionHooks(
            initial=_reduction_initial,
            candidates=_reduction_candidates,
            encode=_reduction_encode,
            complexity=_reduction_complexity,
        ),
    ),
    generate=generator.generate_document,
    mutate=mutation.mutate_document,
    reduce=reducer.StructuredReducer,
)


__all__ = ["SPEC"]
