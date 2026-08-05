"""Adapter specification for pipe concurrent v1 scenarios."""

import sys
from pathlib import Path

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

import concurrent_coverage
import concurrent_generator
import concurrent_mutation
import concurrent_reducer
import concurrent_scenario
from guest_result import classify_guest_execution, normalize_guest_execution
from host_runtime import find_or_build_host_oracle
from host_runtime import record_host as record_host_once
from host_runtime import record_host_scheduled
from linux_oracle.batch import HostRecordResult
from linux_oracle.host_record import record_converged_host
from linux_oracle.outcomes import decode_raw_run_trace, fnv1a64
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


RAW_MAGIC = b"PIPERUN7"
TRACE_MAGIC = b"PIPEORC1"


def record_host_converged(
    elf: Path, scenario_path: Path, trace_path: Path
) -> HostRecordResult:
    corpus_digest = fnv1a64(scenario_path.read_bytes())

    def decode(path: Path):
        return decode_raw_run_trace(
            path.read_bytes(),
            expected_magic=RAW_MAGIC,
            expected_version=7,
            expected_corpus_digest=corpus_digest,
        )

    return record_converged_host(
        record_host_once,
        decode,
        elf,
        scenario_path,
        trace_path,
        magic=TRACE_MAGIC,
        version=7,
        temporary_prefix=".pipe-concurrent-v1-host-",
        indexed_record_once=record_host_scheduled,
    )


def _serialize(document: object) -> bytes:
    return concurrent_scenario.serialize_document(document).encode("utf-8")


def _scenario_count(document: object) -> int:
    return len(document.scenarios)


def _seed_inputs(workspace: Path):
    checked = workspace / "test-suit/starryos/qemu/pipe-linux-oracle/c/corpus/pipe-concurrent.ops"
    yield checked.read_bytes()
    for seed in range(5):
        yield concurrent_generator.canonicalize_seed(seed).encoded


def _generate(rng: object):
    return concurrent_generator.generate_input(rng).encoded


def _mutate(rng: object, parent: bytes, donor: bytes):
    candidate = concurrent_mutation.mutate_document(
        rng,
        concurrent_scenario.parse_document(parent),
        concurrent_scenario.parse_document(donor),
    )
    if candidate.classification is not concurrent_mutation.CandidateClassification.EXECUTABLE:
        return None
    return candidate.encoded


def _reduction_initial(encoded: bytes):
    return concurrent_reducer.with_origins(concurrent_scenario.parse_document(encoded))


def _reduction_candidates(document: object):
    return (candidate.document for candidate in concurrent_reducer.reduction_candidates(document))


def _reduction_encode(document: object) -> bytes:
    return concurrent_scenario.serialize_document(document.plain()).encode("utf-8")


SPEC = AdapterSpec(
    adapter_id="pipe-concurrent-v1",
    adapter_version=1,
    corpus_version=7,
    generator_version=concurrent_generator.GENERATOR_VERSION,
    artifacts=ArtifactLayout("pipe.ops", "linux.trace", "pipe-linux-oracle"),
    campaign=CampaignLayout(Path("coverage/pipe-concurrent-v1-oracle-fuzz")),
    qemu=QemuSpec(
        case="qemu/pipe-linux-oracle",
        artifact_environment="STARRY_PIPE_ORACLE_ARTIFACT_DIR",
        pinned_elf_environment="AXBUILD_STARRY_KALLSYMS_SOURCE_ELF",
        architecture="x86_64",
        profraw_path=Path("coverage/starryos-x86_64-unknown-none.profraw"),
        coverage_object_path=Path("target/x86_64-unknown-none/release/starryos"),
    ),
    coverage=CoverageTarget(
        concurrent_coverage.TARGET_SET_ID,
        concurrent_coverage.TARGET_SOURCE_PATHS,
    ),
    codec=CodecSpec(
        concurrent_scenario.parse_document,
        _serialize,
        concurrent_scenario.combine_documents,
        concurrent_scenario.validate_entry_limits,
        _scenario_count,
    ),
    host_record=record_host_converged,
    classify_guest=classify_guest_execution,
    normalize_guest=normalize_guest_execution,
    campaign_hooks=CampaignHooks(
        find_or_build_host=find_or_build_host_oracle,
        seed_inputs=_seed_inputs,
        make_rng=concurrent_generator.CampaignRng,
        generate=_generate,
        mutate=_mutate,
        reduction=ReductionHooks(
            initial=_reduction_initial,
            candidates=_reduction_candidates,
            encode=_reduction_encode,
            complexity=concurrent_reducer.complexity_key,
        ),
    ),
    generate=concurrent_generator.generate_input,
    mutate=concurrent_mutation.mutate_document,
    reduce=concurrent_reducer.reduction_candidates,
)


__all__ = ["HostRecordResult", "RAW_MAGIC", "SPEC", "TRACE_MAGIC", "record_host_converged"]
