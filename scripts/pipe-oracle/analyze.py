#!/usr/bin/env python3
"""Offline effectiveness analysis for structured pipe generation and mutation."""

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, MutableMapping, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(SCRIPT_DIR))

import generator
import mutation
from scenario import (
    Close,
    Dup,
    Fionread,
    GetSize,
    Pipe2,
    Poll,
    Read,
    ReadNull,
    ScenarioDocument,
    SetSize,
    Write,
    WriteNull,
    operation_name,
    serialize_document,
)


DEFAULT_SEED = 42
DEFAULT_SAMPLES = 10_000
DEFAULT_MUTATIONS = 20_000
DEFAULT_TOP = 10

OPERATION_NAMES = (
    "pipe2",
    "read",
    "read-null",
    "write",
    "write-null",
    "dup",
    "close",
    "poll",
    "set-size",
    "get-size",
    "fionread",
)
LENGTH_BUCKETS = (
    "0",
    "1",
    "2",
    "3-4094",
    "4095",
    "4096",
    "4097",
    "4098-8190",
    "8191",
    "8192",
)
PIPE_SIZE_BUCKETS = (
    "0",
    "1",
    "2",
    "3-4094",
    "4095",
    "4096",
    "4097",
    "4098-8190",
    "8191",
    "8192",
    "8193",
    "8194-2147483646",
    "2147483647",
)
POLL_MASK_BUCKETS = (
    "0",
    "1",
    "4",
    "5",
    "4095",
    "4096",
    "4097",
    "8191",
    "8192",
    "8193",
    "16384",
    "32767",
    "other",
)
RESOURCE_CATEGORIES = (
    "read-null",
    "write-null",
    "idle-slot",
    "closed-slot",
    "wrong-endpoint",
    "duplicate-close",
    "query-read-end",
    "query-write-end",
)

FREE = 0
READER = 1
WRITER = 2
CLOSED = 3


def main(argv=None):
    args = _parse_args(argv)
    report = analyze(args.seed, args.samples, args.mutations, args.top)
    if args.format == "json":
        output = json.dumps(report, indent=2, sort_keys=True)
    else:
        output = format_text(report)
    print(output)


def analyze(seed: int, samples: int, mutations: int, top: int) -> Dict:
    source_specs = (
        (
            "campaign_rng",
            "SHA-256 counter stream v2 with rejection sampling",
            generator.CampaignRng,
        ),
        (
            "legacy_lcg",
            "version-1 64-bit LCG analysis contrast",
            generator.LegacyLcgRng,
        ),
    )
    sources = {
        source_name: _analyze_source(
            algorithm,
            rng_factory,
            seed,
            samples,
            mutations,
            top,
        )
        for source_name, algorithm, rng_factory in source_specs
    }
    report = {
        "schema_version": 2,
        "config": {
            "seed": seed,
            "samples_per_source": samples,
            "mutations_per_source": mutations,
            "top": top,
        },
        "sources": sources,
    }
    _validate_report(report)
    return report


def format_text(report: Dict) -> str:
    config = report["config"]
    lines = [
        "Pipe oracle structured generator and mutation analysis",
        (
            f"seed={config['seed']} "
            f"samples/source={config['samples_per_source']} "
            f"mutations/source={config['mutations_per_source']} "
            f"top={config['top']}"
        ),
    ]
    for source_name, source in report["sources"].items():
        generation = source["generation"]
        mutations = source["mutation"]
        lines.extend(
            [
                "",
                f"[{source_name}] {source['algorithm']}",
                (
                    "generation: "
                    f"samples={generation['samples']} "
                    f"unique={generation['unique_canonical_scenarios']} "
                    f"duplicates={generation['duplicate_samples']} "
                    f"duplicate_rate={_percent(generation['duplicate_rate'])}"
                ),
                (
                    "mutation: "
                    f"attempts={mutations['attempts']} "
                    f"executable={mutations['classifications']['executable']} "
                    f"malformed={mutations['classifications']['malformed']} "
                    "executable_encoded_changed_canonical_unchanged="
                    f"{mutations['executable_encoded_changed_canonical_unchanged']}"
                ),
                "mutation kinds:",
            ]
        )
        for kind, counts in mutations["by_kind"].items():
            lines.append(
                f"  {kind}: attempts={counts['attempts']} "
                f"executable={counts['executable']} "
                f"malformed={counts['malformed']} "
                f"canonical_changed={counts['canonical_changed']}"
            )
        lines.extend(
            [
                "malformed categories:",
                f"  {_format_counts(mutations['malformed_categories'])}",
                "operation counts:",
                f"  {_format_counts(generation['operation_counts'])}",
                "length buckets (read/write):",
                f"  {_format_counts(generation['parameter_buckets']['length'])}",
                "pipe size buckets (set-size):",
                f"  {_format_counts(generation['parameter_buckets']['pipe_size'])}",
                "poll mask buckets:",
                f"  {_format_counts(generation['parameter_buckets']['poll_mask'])}",
                "resource categories:",
                f"  {_format_counts(generation['resource_categories'])}",
                "top canonical scenarios:",
            ]
        )
        for scenario in generation["top_scenarios"]:
            lines.append(
                f"  {scenario['digest']} count={scenario['count']} "
                f"rate={_percent(scenario['rate'])}"
            )
            lines.extend(
                f"    {canonical_line}"
                for canonical_line in scenario["canonical_text"].splitlines()
            )
    return "\n".join(lines)


def _parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Analyze pipe oracle generation and mutation offline"
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--samples", type=_positive_int, default=DEFAULT_SAMPLES)
    parser.add_argument(
        "--mutations",
        type=_non_negative_int,
        default=DEFAULT_MUTATIONS,
    )
    parser.add_argument("--top", type=_non_negative_int, default=DEFAULT_TOP)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser.parse_args(argv)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return parsed


def _analyze_source(
    algorithm,
    rng_factory,
    seed,
    sample_count,
    mutation_count,
    top,
):
    rng = rng_factory(seed)
    documents = [generator.generate_document(rng) for _ in range(sample_count)]
    canonical_counts = Counter()
    canonical_texts = {}
    distributions = _new_distributions()

    for document in documents:
        canonical_text = serialize_document(document)
        digest = hashlib.sha256(canonical_text.encode("utf-8")).hexdigest()
        canonical_counts[digest] += 1
        canonical_texts.setdefault(digest, canonical_text)
        _record_document(document, distributions)

    mutation_counts = _new_mutation_counts()
    for _ in range(mutation_count):
        parent_index = rng.range(0, len(documents))
        donor_index = rng.range(0, len(documents))
        if len(documents) > 1 and donor_index == parent_index:
            donor_index = (donor_index + 1) % len(documents)
        parent = documents[parent_index]
        donor = documents[donor_index]
        candidate = mutation.mutate_document(rng, parent, donor)
        _record_mutation(mutation_counts, parent, candidate)

    unique_count = len(canonical_counts)
    duplicate_count = sample_count - unique_count
    return {
        "algorithm": algorithm,
        "generation": {
            "samples": sample_count,
            "unique_canonical_scenarios": unique_count,
            "duplicate_samples": duplicate_count,
            "duplicate_rate": _rate(duplicate_count, sample_count),
            "top_scenarios": _top_scenarios(
                canonical_counts,
                canonical_texts,
                sample_count,
                top,
            ),
            "operation_counts": _complete_counts(
                OPERATION_NAMES,
                distributions["operation_counts"],
            ),
            "parameter_buckets": {
                "length": _complete_counts(
                    LENGTH_BUCKETS,
                    distributions["length_buckets"],
                ),
                "pipe_size": _complete_counts(
                    PIPE_SIZE_BUCKETS,
                    distributions["pipe_size_buckets"],
                ),
                "poll_mask": _complete_counts(
                    POLL_MASK_BUCKETS,
                    distributions["poll_mask_buckets"],
                ),
            },
            "resource_categories": _complete_counts(
                RESOURCE_CATEGORIES,
                distributions["resource_categories"],
            ),
            "endpoint_counts_before_operation": {
                operation: dict(
                    sorted(distributions["endpoint_counts"][operation].items())
                )
                for operation in OPERATION_NAMES
            },
        },
        "mutation": _finalize_mutations(mutation_counts),
    }


def _new_distributions():
    return {
        "operation_counts": Counter(),
        "length_buckets": Counter(),
        "pipe_size_buckets": Counter(),
        "poll_mask_buckets": Counter(),
        "resource_categories": Counter(),
        "endpoint_counts": defaultdict(Counter),
    }


def _record_document(document: ScenarioDocument, distributions: MutableMapping):
    for scenario in document.scenarios:
        slots = [FREE] * generator.MAX_LOGICAL_SLOTS
        for operation in scenario.operations:
            name = operation_name(operation)
            distributions["operation_counts"][name] += 1
            readers = slots.count(READER)
            writers = slots.count(WRITER)
            state_bucket = f"readers={readers},writers={writers}"
            distributions["endpoint_counts"][name][state_bucket] += 1
            _record_parameters(operation, distributions)
            _record_resource_category(operation, slots, distributions)
            _apply_resource_transition(operation, slots)


def _record_parameters(operation, distributions):
    if isinstance(operation, (Read, Write)):
        distributions["length_buckets"][_length_bucket(operation.length)] += 1
    elif isinstance(operation, SetSize):
        distributions["pipe_size_buckets"][_pipe_size_bucket(operation.size)] += 1
    elif isinstance(operation, Poll):
        distributions["poll_mask_buckets"][_poll_mask_bucket(operation.events)] += 1


def _record_resource_category(operation, slots, distributions):
    categories = distributions["resource_categories"]
    if isinstance(operation, ReadNull):
        categories["read-null"] += 1
    if isinstance(operation, WriteNull):
        categories["write-null"] += 1
    if isinstance(operation, Pipe2):
        return

    slot = operation.source_slot if isinstance(operation, Dup) else operation.slot
    slot_state = slots[slot]
    if slot_state == FREE:
        categories["idle-slot"] += 1
    elif slot_state == CLOSED:
        categories["closed-slot"] += 1
    if isinstance(operation, Close) and slot_state == CLOSED:
        categories["duplicate-close"] += 1
    if isinstance(operation, (Read, ReadNull)) and slot_state == WRITER:
        categories["wrong-endpoint"] += 1
    if isinstance(operation, (Write, WriteNull)) and slot_state == READER:
        categories["wrong-endpoint"] += 1
    if isinstance(operation, (SetSize, GetSize, Fionread)):
        if slot_state == READER:
            categories["query-read-end"] += 1
        elif slot_state == WRITER:
            categories["query-write-end"] += 1


def _apply_resource_transition(operation, slots):
    if isinstance(operation, Pipe2):
        slots[operation.read_slot] = READER
        slots[operation.write_slot] = WRITER
    elif isinstance(operation, Dup):
        source_state = slots[operation.source_slot]
        if source_state in (READER, WRITER):
            slots[operation.destination_slot] = source_state
    elif isinstance(operation, Close):
        if slots[operation.slot] in (READER, WRITER):
            slots[operation.slot] = CLOSED


def _length_bucket(value):
    if value in (0, 1, 2, 4095, 4096, 4097, 8191, 8192):
        return str(value)
    if 3 <= value <= 4094:
        return "3-4094"
    return "4098-8190"


def _pipe_size_bucket(value):
    if value in (0, 1, 2, 4095, 4096, 4097, 8191, 8192, 8193, 2147483647):
        return str(value)
    if 3 <= value <= 4094:
        return "3-4094"
    if 4098 <= value <= 8190:
        return "4098-8190"
    return "8194-2147483646"


def _poll_mask_bucket(value):
    if value in (0, 1, 4, 5, 4095, 4096, 4097, 8191, 8192, 8193, 16384, 32767):
        return str(value)
    return "other"


def _new_mutation_counts():
    return {
        "attempts": 0,
        "encoded_changed": 0,
        "canonical_changed": 0,
        "executable_encoded_changed_canonical_unchanged": 0,
        "classifications": Counter(),
        "malformed_categories": Counter(),
        "by_kind": {
            kind: {
                "attempts": 0,
                "encoded_changed": 0,
                "canonical_changed": 0,
                "executable": 0,
                "malformed": 0,
            }
            for kind in mutation.MUTATION_KINDS
        },
    }


def _record_mutation(counts, parent, candidate):
    parent_encoded = serialize_document(parent).encode("utf-8")
    encoded_changed = parent_encoded != candidate.encoded
    executable = (
        candidate.classification == mutation.CandidateClassification.EXECUTABLE
    )
    canonical_changed = executable and hashlib.sha256(parent_encoded).hexdigest() != (
        candidate.digest
    )
    counts["attempts"] += 1
    counts["encoded_changed"] += int(encoded_changed)
    counts["canonical_changed"] += int(canonical_changed)
    counts["executable_encoded_changed_canonical_unchanged"] += int(
        executable and encoded_changed and not canonical_changed
    )
    counts["classifications"][candidate.classification.value] += 1
    if candidate.error_category:
        counts["malformed_categories"][candidate.error_category] += 1

    kind_counts = counts["by_kind"][candidate.kind]
    kind_counts["attempts"] += 1
    kind_counts["encoded_changed"] += int(encoded_changed)
    kind_counts["canonical_changed"] += int(canonical_changed)
    kind_counts[candidate.classification.value] += 1


def _finalize_mutations(counts):
    attempts = counts["attempts"]
    by_kind = {}
    for kind, kind_counts in counts["by_kind"].items():
        kind_attempts = kind_counts["attempts"]
        by_kind[kind] = {
            **kind_counts,
            "encoded_change_rate": _rate(
                kind_counts["encoded_changed"],
                kind_attempts,
            ),
            "canonical_change_rate": _rate(
                kind_counts["canonical_changed"],
                kind_attempts,
            ),
        }
    return {
        "attempts": attempts,
        "encoded_changed": counts["encoded_changed"],
        "encoded_change_rate": _rate(counts["encoded_changed"], attempts),
        "canonical_changed": counts["canonical_changed"],
        "canonical_change_rate": _rate(counts["canonical_changed"], attempts),
        "executable_encoded_changed_canonical_unchanged": counts[
            "executable_encoded_changed_canonical_unchanged"
        ],
        "classifications": {
            classification.value: counts["classifications"][classification.value]
            for classification in mutation.CandidateClassification
        },
        "malformed_categories": dict(sorted(counts["malformed_categories"].items())),
        "by_kind": by_kind,
    }


def _top_scenarios(counts, texts, sample_count, top):
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [
        {
            "digest": digest,
            "count": count,
            "rate": _rate(count, sample_count),
            "canonical_text": texts[digest],
        }
        for digest, count in ranked[:top]
    ]


def _complete_counts(keys: Tuple[str, ...], counts: Counter):
    return {key: counts[key] for key in keys}


def _rate(numerator, denominator):
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 6)


def _percent(rate):
    return f"{rate * 100:.2f}%"


def _format_counts(counts):
    return ", ".join(f"{key}={value}" for key, value in counts.items())


def _validate_report(report):
    for source in report["sources"].values():
        generation = source["generation"]
        mutations = source["mutation"]
        assert generation["samples"] == (
            generation["unique_canonical_scenarios"]
            + generation["duplicate_samples"]
        )
        for field in ("attempts", "encoded_changed", "canonical_changed"):
            assert mutations[field] == sum(
                kind_counts[field]
                for kind_counts in mutations["by_kind"].values()
            )
        assert mutations["attempts"] == sum(mutations["classifications"].values())
        assert mutations["encoded_changed"] == mutations["attempts"]
        assert mutations["executable_encoded_changed_canonical_unchanged"] == 0
        assert sum(generation["operation_counts"].values()) == sum(
            sum(buckets.values())
            for buckets in generation["endpoint_counts_before_operation"].values()
        )


if __name__ == "__main__":
    main()
