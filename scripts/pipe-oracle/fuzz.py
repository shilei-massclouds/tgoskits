#!/usr/bin/env python3
"""Coverage-guided pipe campaign over canonical structured corpus entries."""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from common import CORPUS_DIR, FAILURES_DIR, build_metadata, save_metadata
from generator import (
    GENERATOR_VERSION,
    CampaignRng,
    generate_document,
    legacy_document_from_input,
)
from mutation import (
    MUTATION_KINDS,
    CandidateClassification,
    MutationCandidate,
    candidate_from_document,
    mutate_document,
)
from runner import coverage_object, run_guest_compare
from scenario import (
    ScenarioDocument,
    combine_documents,
    parse_document,
    serialize_document,
)


DEFAULT_SEED = 42
DEFAULT_BATCHES = 4
DEFAULT_BATCH_SIZE = 32
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent

LEGACY_INITIAL_SEEDS = (
    bytes(range(256)),
    bytes(reversed(range(256))),
    b"\x00" * 32,
    b"\xff" * 32,
    b"pipe" * 64,
)


@dataclass(frozen=True)
class CorpusEntry:
    digest: str
    encoded: bytes
    document: ScenarioDocument


@dataclass(frozen=True)
class HostRecordResult:
    passed: bool
    parser_rejection: bool
    log: str


class CanonicalCorpus:
    """An in-memory digest map whose observable iteration order is canonical."""

    def __init__(self):
        self._entries: Dict[str, CorpusEntry] = {}

    @classmethod
    def initial(cls):
        corpus = cls()
        for raw_seed in LEGACY_INITIAL_SEEDS:
            corpus.add(legacy_document_from_input(raw_seed))
        return corpus

    def add(self, document: ScenarioDocument) -> bool:
        encoded = serialize_document(document).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        if digest in self._entries:
            return False
        self._entries[digest] = CorpusEntry(digest, encoded, document)
        return True

    def ordered_entries(self) -> List[CorpusEntry]:
        return [self._entries[digest] for digest in sorted(self._entries)]

    def __len__(self):
        return len(self._entries)


class CampaignStats:
    def __init__(self):
        self.classifications = Counter()
        self.mutation_kinds = Counter()
        self.malformed_categories = Counter()
        self.host_parser_rejections = 0

    def record(self, candidate: MutationCandidate) -> None:
        self.classifications[candidate.classification.value] += 1
        self.mutation_kinds[candidate.kind] += 1
        if candidate.error_category:
            self.malformed_categories[candidate.error_category] += 1


def main():
    parser = argparse.ArgumentParser(
        description="Script-driven pipe differential coverage fuzzing"
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--batches", type=int, default=DEFAULT_BATCHES)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--workspace", type=Path, default=WORKSPACE_ROOT)
    args = parser.parse_args()

    workspace = args.workspace.resolve()
    corpus_dir = workspace / CORPUS_DIR
    corpus_dir.mkdir(parents=True, exist_ok=True)
    failures_dir = workspace / FAILURES_DIR
    failures_dir.mkdir(parents=True, exist_ok=True)

    corpus = CanonicalCorpus.initial()
    covered_regions: Set[str] = set()
    rng = CampaignRng(args.seed)
    stats = CampaignStats()

    for batch_index in range(args.batches):
        print(f"=== Batch {batch_index + 1}/{args.batches} ===", flush=True)
        batch_candidates = _select_batch(rng, corpus, args.batch_size, stats)
        batch_failed = _run_batch(
            workspace,
            batch_index,
            batch_candidates,
            covered_regions,
            corpus,
            failures_dir,
            stats,
        )
        if batch_failed:
            print(f"Batch {batch_index + 1} failed, stopping.", flush=True)
            sys.exit(1)
    print(
        "All batches completed: "
        f"executable={stats.classifications['executable']} "
        f"malformed={stats.classifications['malformed']} "
        f"host_parser_rejections={stats.host_parser_rejections}.",
        flush=True,
    )


def _select_batch(
    rng,
    corpus: CanonicalCorpus,
    batch_size: int,
    stats: Optional[CampaignStats] = None,
) -> List[MutationCandidate]:
    parents = corpus.ordered_entries()
    batch = []
    for _ in range(batch_size):
        if not parents or rng.range(0, 10) < 3:
            candidate = candidate_from_document(generate_document(rng), "generate")
        else:
            parent_index = rng.range(0, len(parents))
            parent = parents[parent_index]
            donor = _select_donor(rng, parents, parent_index)
            candidate = mutate_document(
                rng,
                parent.document,
                donor.document if donor is not None else None,
            )
        batch.append(candidate)
        if stats is not None:
            stats.record(candidate)
    return batch


def _select_donor(rng, parents, parent_index):
    if len(parents) < 2:
        return None
    donor_index = rng.range(0, len(parents) - 1)
    if donor_index >= parent_index:
        donor_index += 1
    return parents[donor_index]


def _run_batch(
    workspace: Path,
    batch_index: int,
    candidates: List[MutationCandidate],
    covered_regions: Set[str],
    corpus: CanonicalCorpus,
    failures_dir: Path,
    stats: Optional[CampaignStats] = None,
) -> bool:
    executable = [
        candidate
        for candidate in candidates
        if candidate.classification == CandidateClassification.EXECUTABLE
        and candidate.document is not None
    ]
    malformed_count = len(candidates) - len(executable)
    if not executable:
        print(
            f"  Filtered {malformed_count} malformed candidates; no host/QEMU run.",
            flush=True,
        )
        return False

    input_map = {
        candidate.digest: candidate.encoded
        for candidate in sorted(executable, key=lambda item: item.digest)
    }
    documents = [
        parse_document(input_map[digest])
        for digest in sorted(input_map)
    ]
    batch_document = combine_documents(documents)
    ops_text = serialize_document(batch_document)
    ops_digest = hashlib.sha256(ops_text.encode("utf-8")).hexdigest()
    scenario_count = sum(len(document.scenarios) for document in documents)

    print(
        f"  Prepared {scenario_count} scenario groups from {len(input_map)} "
        f"canonical entries; filtered {malformed_count} malformed candidates",
        flush=True,
    )

    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        ops_path = temporary / "pipe.ops"
        ops_path.write_text(ops_text)
        elf_path = _find_or_build_host_oracle(workspace)
        if elf_path is None:
            print("ERROR: cannot build pipe-linux-oracle ELF", flush=True)
            return True

        trace_path = temporary / "linux.trace"
        host_record = _record_host(elf_path, ops_path, trace_path)
        if not host_record.passed:
            if host_record.parser_rejection:
                if stats is not None:
                    stats.host_parser_rejections += 1
                print(
                    "  Host parser rejected the structured batch; recorded as malformed "
                    "and skipped before QEMU.",
                    flush=True,
                )
                return False
            print(f"ERROR: host record failed\n{host_record.log}", flush=True)
            return True

        artifact_elf = temporary / "pipe-linux-oracle"
        shutil.copy2(elf_path, artifact_elf)
        guest_log, profraws, passed = _run_guest_compare(workspace, temporary)

        if not passed:
            failure_id = f"batch{batch_index}_mismatch_{ops_digest[:12]}"
            failure_path = failures_dir / failure_id
            _save_batch_failure(
                failure_path,
                input_map,
                ops_text,
                artifact_elf,
                trace_path,
                guest_log,
                profraws,
                batch_index,
                "mismatch",
            )
            print(
                f"  MISMATCH saved to {failure_path.relative_to(workspace)}",
                flush=True,
            )
            return True

        try:
            if not profraws:
                raise RuntimeError(
                    "QEMU passed without producing the expected Starry profraw"
                )
            new_regions = _extract_new_regions(
                profraws,
                coverage_object(workspace),
                covered_regions,
            )
        except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
            guest_log += f"\nCoverage analysis failed: {error}\n"
            failure_id = f"batch{batch_index}_coverage_{ops_digest[:12]}"
            failure_path = failures_dir / failure_id
            _save_batch_failure(
                failure_path,
                input_map,
                ops_text,
                artifact_elf,
                trace_path,
                guest_log,
                profraws,
                batch_index,
                "coverage",
            )
            print(
                f"  COVERAGE FAILURE saved to {failure_path.relative_to(workspace)}",
                flush=True,
            )
            return True

        if new_regions:
            for document in documents:
                digest = hashlib.sha256(
                    serialize_document(document).encode("utf-8")
                ).hexdigest()
                if corpus.add(document):
                    print(f"  New corpus entry: {digest[:12]}...", flush=True)

        print(
            f"  Coverage saved: {len(profraws)} profraw(s), "
            f"{len(new_regions)} new pipe regions",
            flush=True,
        )

    return False


def _find_or_build_host_oracle(workspace: Path) -> Optional[Path]:
    source_dir = workspace / "test-suit/starryos/qemu/pipe-linux-oracle/c"
    build_dir = workspace / "target/pipe-oracle-host"
    elf_path = build_dir / "pipe-linux-oracle"
    if elf_path.is_file():
        return elf_path

    build_environment = os.environ.copy()
    build_environment.pop("STARRY_PIPE_ORACLE_ARTIFACT_DIR", None)
    try:
        subprocess.run(
            ["cmake", "-S", str(source_dir), "-B", str(build_dir)],
            cwd=str(workspace),
            env=build_environment,
            check=True,
        )
        subprocess.run(
            ["cmake", "--build", str(build_dir), "--target", "pipe-linux-oracle"],
            cwd=str(workspace),
            env=build_environment,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return elf_path if elf_path.is_file() else None


def _record_host(elf: Path, ops: Path, trace: Path) -> HostRecordResult:
    try:
        result = subprocess.run(
            [str(elf), "--record", str(ops), str(trace)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return HostRecordResult(False, False, str(error))
    log = result.stdout + "\n" + result.stderr
    return HostRecordResult(
        result.returncode == 0,
        result.returncode != 0 and _is_host_parser_rejection(result.stderr),
        log,
    )


def _is_host_parser_rejection(stderr: str) -> bool:
    parser_messages = (
        "corpus line is too long",
        "invalid corpus version",
        "invalid scenario",
        "invalid operation",
        "operation appears before first scenario",
        "operation corpus is incomplete",
    )
    return any(message in stderr for message in parser_messages)


def _run_guest_compare(
    workspace: Path,
    artifact_dir: Path,
) -> Tuple[str, List[Path], bool]:
    return run_guest_compare(workspace, artifact_dir)


def _extract_new_regions(
    profraws: List[Path],
    elf: Path,
    covered_regions: Set[str],
) -> Set[str]:
    if not profraws:
        return set()
    from coverage import merge_profraws, pipe_region_set

    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        profdata = temporary / "merged.profdata"
        merge_profraws(profraws, profdata)
        regions = pipe_region_set(profdata, elf)
        new_regions = regions - covered_regions
        covered_regions.update(new_regions)
        return new_regions


def _save_batch_failure(
    destination: Path,
    input_map: Dict[str, bytes],
    ops_text: str,
    elf: Path,
    trace: Path,
    guest_log: str,
    profraws: List[Path],
    batch_index: int,
    category: str,
):
    from common import atomic_save

    atomic_save(
        destination,
        lambda temporary: _write_failure_parts(
            temporary,
            input_map,
            ops_text,
            elf,
            trace,
            guest_log,
            profraws,
            batch_index,
            category,
        ),
    )


def _write_failure_parts(
    temporary: Path,
    input_map: Dict[str, bytes],
    ops_text: str,
    elf_path: Path,
    trace_path: Path,
    guest_log: str,
    profraws: List[Path],
    batch_index: int,
    category: str,
):
    if len(input_map) == 1:
        key = next(iter(sorted(input_map)))
        (temporary / "input.bin").write_bytes(input_map[key])
    else:
        input_directory = temporary / "inputs"
        input_directory.mkdir()
        for digest in sorted(input_map):
            (input_directory / f"{digest[:16]}.bin").write_bytes(input_map[digest])
    (temporary / "pipe.ops").write_text(ops_text)
    shutil.copy2(elf_path, temporary / "pipe-linux-oracle")
    shutil.copy2(trace_path, temporary / "linux.trace")
    (temporary / "guest.log").write_text(guest_log)
    profraw_directory = temporary / "profraws"
    profraw_directory.mkdir()
    for profraw in profraws:
        if profraw.exists():
            shutil.copy2(profraw, profraw_directory / profraw.name)
    metadata = build_metadata(
        seed=None,
        batch_index=batch_index,
        generator_version=GENERATOR_VERSION,
        input_path=(
            temporary / "input.bin"
            if (temporary / "input.bin").exists()
            else None
        ),
        elf_path=temporary / "pipe-linux-oracle",
        ops_path=temporary / "pipe.ops",
        trace_path=temporary / "linux.trace",
        guest_log_path=temporary / "guest.log",
        profraw_paths=list(profraw_directory.iterdir()),
        command=" ".join(sys.argv),
        result_category=category,
    )
    save_metadata(temporary, metadata)


_Rng = CampaignRng


if __name__ == "__main__":
    main()
