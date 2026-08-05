"""Adapter specification for controlled pipe blocking scenarios."""

import shutil
import sys
import tempfile
from pathlib import Path

_SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

import blocking_coverage
import blocking_generator
import blocking_mutation
import blocking_reducer
import blocking_scenario
from batch_execution import HostRecordResult
from guest_result import classify_guest_execution, normalize_guest_execution
from host_runtime import find_or_build_host_oracle
from host_runtime import record_host as record_host_once
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
    """Accept a candidate only after three byte-identical host recordings."""
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".pipe-blocking-host-", dir=trace_path.parent
    ) as temporary_directory:
        temporary = Path(temporary_directory)
        recorded_traces = []
        logs = []
        for index in range(3):
            candidate_trace = temporary / f"linux-{index}.trace"
            result = record_host_once(elf, scenario_path, candidate_trace)
            logs.append(result.log)
            if not result.passed:
                return HostRecordResult(
                    False, result.parser_rejection, "\n".join(logs)
                )
            recorded_traces.append(candidate_trace.read_bytes())
        if len(set(recorded_traces)) != 1:
            return HostRecordResult(
                False,
                False,
                "blocking host trace is not byte-stable across three recordings",
            )
        shutil.copy2(temporary / "linux-0.trace", trace_path)
    return HostRecordResult(True, False, "\n".join(logs))


def _serialize(document: object) -> bytes:
    return blocking_scenario.serialize_document(document).encode("utf-8")


def _scenario_count(document: object) -> int:
    return len(document.scenarios)


def _seed_inputs(workspace: Path):
    corpus_root = workspace / "test-suit/starryos/qemu/pipe-linux-oracle/c/corpus"
    yield (corpus_root / "pipe-blocking-read.ops").read_bytes()
    yield (corpus_root / "pipe-blocking-write.ops").read_bytes()
    for seed in range(5):
        yield blocking_generator.canonicalize_seed(seed).encoded


def _generate(rng: object):
    return blocking_generator.generate_input(rng).encoded


def _mutate(rng: object, parent: bytes, donor: bytes):
    candidate = blocking_mutation.mutate_document(
        rng,
        blocking_scenario.parse_document(parent),
        blocking_scenario.parse_document(donor),
    )
    if candidate.classification is not blocking_mutation.CandidateClassification.EXECUTABLE:
        return None
    return candidate.encoded


def _reduction_initial(encoded: bytes):
    return blocking_reducer.with_origins(blocking_scenario.parse_document(encoded))


def _reduction_candidates(document: object):
    return (
        candidate.document
        for candidate in blocking_reducer.reduction_candidates(document)
    )


def _reduction_encode(document: object) -> bytes:
    return blocking_scenario.serialize_document(document.plain()).encode("utf-8")


SPEC = AdapterSpec(
    adapter_id="pipe-blocking-v1",
    adapter_version=1,
    corpus_version=5,
    generator_version=blocking_generator.GENERATOR_VERSION,
    artifacts=ArtifactLayout("pipe.ops", "linux.trace", "pipe-linux-oracle"),
    campaign=CampaignLayout(Path("coverage/pipe-blocking-oracle-fuzz")),
    qemu=QemuSpec(
        case="qemu/pipe-linux-oracle",
        artifact_environment="STARRY_PIPE_ORACLE_ARTIFACT_DIR",
        pinned_elf_environment="AXBUILD_STARRY_KALLSYMS_SOURCE_ELF",
        architecture="x86_64",
        profraw_path=Path("coverage/starryos-x86_64-unknown-none.profraw"),
        coverage_object_path=Path("target/x86_64-unknown-none/release/starryos"),
    ),
    coverage=CoverageTarget(
        blocking_coverage.TARGET_SET_ID,
        blocking_coverage.TARGET_SOURCE_PATHS,
    ),
    codec=CodecSpec(
        blocking_scenario.parse_document,
        _serialize,
        blocking_scenario.combine_documents,
        blocking_scenario.validate_entry_limits,
        _scenario_count,
    ),
    host_record=record_host_stable,
    classify_guest=classify_guest_execution,
    normalize_guest=normalize_guest_execution,
    campaign_hooks=CampaignHooks(
        find_or_build_host=find_or_build_host_oracle,
        seed_inputs=_seed_inputs,
        make_rng=blocking_generator.CampaignRng,
        generate=_generate,
        mutate=_mutate,
        reduction=ReductionHooks(
            initial=_reduction_initial,
            candidates=_reduction_candidates,
            encode=_reduction_encode,
            complexity=blocking_reducer.complexity_key,
        ),
    ),
    generate=blocking_generator.generate_input,
    mutate=blocking_mutation.mutate_document,
    reduce=blocking_reducer.reduction_candidates,
)


__all__ = ["SPEC", "record_host_once", "record_host_stable"]
