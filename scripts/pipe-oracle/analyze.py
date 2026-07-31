#!/usr/bin/env python3
import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable, Dict, List, MutableMapping, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(SCRIPT_DIR))

import fuzz
import generator


DEFAULT_SEED = 42
DEFAULT_SAMPLES = 10_000
DEFAULT_MUTATIONS = 20_000
DEFAULT_TOP = 10

OPERATION_NAMES = (
    "pipe2",
    "read",
    "write",
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
    "2-4095",
    "4096",
    "4097-8191",
    "8192",
    "other",
)
PIPE_SIZE_BUCKETS = (
    "1",
    "2-4095",
    "4096",
    "4097-65535",
    "65536",
    "65537-1048575",
    "1048576",
    "other",
)
POLL_MASK_BUCKETS = ("0", "1", "4", "5", "other")


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
            "fuzz._Rng (64-bit LCG)",
            fuzz._Rng,
        ),
        (
            "independent_rng",
            "SHA-256 counter stream",
            _IndependentRng,
        ),
    )
    sources = {}
    for source_name, algorithm, rng_factory in source_specs:
        sources[source_name] = _analyze_source(
            algorithm,
            rng_factory,
            seed,
            samples,
            mutations,
            top,
        )

    report = {
        "schema_version": 1,
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
        "Pipe oracle generator and mutation analysis",
        (
            f"seed={config['seed']} "
            f"samples/source={config['samples_per_source']} "
            f"mutations/source={config['mutations_per_source']} "
            f"top={config['top']}"
        ),
    ]
    for source_name, source in report["sources"].items():
        generation = source["generation"]
        mutation = source["mutation"]
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
                    f"attempts={mutation['attempts']} "
                    f"raw_changed={mutation['raw_changed']} "
                    f"raw_change_rate={_percent(mutation['raw_change_rate'])} "
                    f"scenario_changed={mutation['scenario_changed']} "
                    f"scenario_change_rate={_percent(mutation['scenario_change_rate'])} "
                    "raw_changed_scenario_unchanged="
                    f"{mutation['raw_changed_scenario_unchanged']}"
                ),
                "mutation kinds:",
            ]
        )
        for kind, counts in mutation["by_kind"].items():
            lines.append(
                f"  {kind}: attempts={counts['attempts']} "
                f"raw_changed={counts['raw_changed']} "
                f"scenario_changed={counts['scenario_changed']}"
            )
        lines.extend(
            [
                "operation counts:",
                f"  {_format_counts(generation['operation_counts'])}",
                "length buckets (read/write):",
                f"  {_format_counts(generation['parameter_buckets']['length'])}",
                "pipe size buckets (set-size):",
                f"  {_format_counts(generation['parameter_buckets']['pipe_size'])}",
                "poll mask buckets:",
                f"  {_format_counts(generation['parameter_buckets']['poll_mask'])}",
                "reader/writer counts before each operation:",
            ]
        )
        for operation, buckets in generation[
            "endpoint_counts_before_operation"
        ].items():
            lines.append(f"  {operation}: {_format_counts(buckets)}")
        lines.append("top canonical scenarios:")
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
        "--mutations", type=_non_negative_int, default=DEFAULT_MUTATIONS
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
    algorithm: str,
    rng_factory: Callable[[int], object],
    seed: int,
    sample_count: int,
    mutation_count: int,
    top: int,
) -> Dict:
    rng = rng_factory(seed)
    raw_inputs = [_generate_raw_input(rng) for _ in range(sample_count)]
    canonical_digests = {}
    canonical_counts = Counter()
    canonical_texts = {}
    distributions = _new_distributions()

    for raw_input in raw_inputs:
        canonical_text, digest = generator.canonicalize_input(raw_input)
        canonical_digests[raw_input] = digest
        canonical_counts[digest] += 1
        canonical_texts.setdefault(digest, canonical_text)
        _record_operations(canonical_text, distributions)

    mutation_counts = _new_mutation_counts()
    for _ in range(mutation_count):
        parent = raw_inputs[rng.range(0, len(raw_inputs))]
        child, kind = fuzz._mutate_with_kind(rng, parent)
        parent_digest = canonical_digests[parent]
        child_digest = canonical_digests.get(child)
        if child_digest is None:
            _canonical_text, child_digest = generator.canonicalize_input(child)
            canonical_digests[child] = child_digest
        _record_mutation(mutation_counts, kind, parent, child, parent_digest, child_digest)

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
                canonical_counts, canonical_texts, sample_count, top
            ),
            "operation_counts": _complete_counts(
                OPERATION_NAMES, distributions["operation_counts"]
            ),
            "parameter_buckets": {
                "length": _complete_counts(
                    LENGTH_BUCKETS, distributions["length_buckets"]
                ),
                "pipe_size": _complete_counts(
                    PIPE_SIZE_BUCKETS, distributions["pipe_size_buckets"]
                ),
                "poll_mask": _complete_counts(
                    POLL_MASK_BUCKETS, distributions["poll_mask_buckets"]
                ),
            },
            "endpoint_counts_before_operation": {
                operation: dict(
                    sorted(distributions["endpoint_counts"][operation].items())
                )
                for operation in OPERATION_NAMES
            },
        },
        "mutation": _finalize_mutations(mutation_counts),
    }


def _generate_raw_input(rng) -> bytes:
    length = rng.range(1, 129)
    return bytes(rng.next() % 256 for _ in range(length))


def _new_distributions() -> Dict:
    return {
        "operation_counts": Counter(),
        "length_buckets": Counter(),
        "pipe_size_buckets": Counter(),
        "poll_mask_buckets": Counter(),
        "endpoint_counts": defaultdict(Counter),
    }


def _record_operations(canonical_text: str, distributions: MutableMapping) -> None:
    slots = [0] * generator.MAX_LOGICAL_SLOTS
    for line in canonical_text.splitlines():
        fields = line.split()
        if not fields or fields[0] == "version":
            continue
        if fields[0] == "scenario":
            slots = [0] * generator.MAX_LOGICAL_SLOTS
            continue

        operation = fields[0]
        distributions["operation_counts"][operation] += 1
        readers = slots.count(1)
        writers = slots.count(2)
        state_bucket = f"readers={readers},writers={writers}"
        distributions["endpoint_counts"][operation][state_bucket] += 1

        if operation in ("read", "write"):
            distributions["length_buckets"][_length_bucket(int(fields[2]))] += 1
        elif operation == "set-size":
            distributions["pipe_size_buckets"][_pipe_size_bucket(int(fields[2]))] += 1
        elif operation == "poll":
            distributions["poll_mask_buckets"][_poll_mask_bucket(int(fields[2]))] += 1

        _apply_resource_transition(operation, fields, slots)


def _apply_resource_transition(operation: str, fields: List[str], slots: List[int]) -> None:
    if operation == "pipe2":
        slots[int(fields[1])] = 1
        slots[int(fields[2])] = 2
    elif operation == "dup":
        slots[int(fields[2])] = slots[int(fields[1])]
    elif operation == "close":
        slots[int(fields[1])] = 0


def _length_bucket(length: int) -> str:
    if length in (0, 1, 4096, 8192):
        return str(length)
    if 2 <= length <= 4095:
        return "2-4095"
    if 4097 <= length <= 8191:
        return "4097-8191"
    return "other"


def _pipe_size_bucket(pipe_size: int) -> str:
    if pipe_size in (1, 4096, 65536, 1048576):
        return str(pipe_size)
    if 2 <= pipe_size <= 4095:
        return "2-4095"
    if 4097 <= pipe_size <= 65535:
        return "4097-65535"
    if 65537 <= pipe_size <= 1048575:
        return "65537-1048575"
    return "other"


def _poll_mask_bucket(mask: int) -> str:
    if mask in (0, 1, 4, 5):
        return str(mask)
    return "other"


def _new_mutation_counts() -> Dict:
    return {
        "attempts": 0,
        "raw_changed": 0,
        "scenario_changed": 0,
        "raw_changed_scenario_unchanged": 0,
        "by_kind": {
            kind: {
                "attempts": 0,
                "raw_changed": 0,
                "scenario_changed": 0,
            }
            for kind in fuzz.MUTATION_KINDS
        },
    }


def _record_mutation(
    counts: MutableMapping,
    kind: str,
    parent: bytes,
    child: bytes,
    parent_digest: str,
    child_digest: str,
) -> None:
    raw_changed = parent != child
    scenario_changed = parent_digest != child_digest
    counts["attempts"] += 1
    counts["raw_changed"] += int(raw_changed)
    counts["scenario_changed"] += int(scenario_changed)
    counts["raw_changed_scenario_unchanged"] += int(
        raw_changed and not scenario_changed
    )
    kind_counts = counts["by_kind"][kind]
    kind_counts["attempts"] += 1
    kind_counts["raw_changed"] += int(raw_changed)
    kind_counts["scenario_changed"] += int(scenario_changed)


def _finalize_mutations(counts: Dict) -> Dict:
    attempts = counts["attempts"]
    by_kind = {}
    for kind, kind_counts in counts["by_kind"].items():
        kind_attempts = kind_counts["attempts"]
        by_kind[kind] = {
            **kind_counts,
            "raw_change_rate": _rate(kind_counts["raw_changed"], kind_attempts),
            "scenario_change_rate": _rate(
                kind_counts["scenario_changed"], kind_attempts
            ),
        }
    return {
        "attempts": attempts,
        "raw_changed": counts["raw_changed"],
        "raw_change_rate": _rate(counts["raw_changed"], attempts),
        "scenario_changed": counts["scenario_changed"],
        "scenario_change_rate": _rate(counts["scenario_changed"], attempts),
        "raw_changed_scenario_unchanged": counts[
            "raw_changed_scenario_unchanged"
        ],
        "by_kind": by_kind,
    }


def _top_scenarios(
    counts: Counter,
    texts: Dict[str, str],
    sample_count: int,
    top: int,
) -> List[Dict]:
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


def _complete_counts(keys: Tuple[str, ...], counts: Counter) -> Dict[str, int]:
    return {key: counts[key] for key in keys}


def _rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 6)


def _percent(rate: float) -> str:
    return f"{rate * 100:.2f}%"


def _format_counts(counts: Dict[str, int]) -> str:
    return ", ".join(f"{key}={value}" for key, value in counts.items())


def _validate_report(report: Dict) -> None:
    for source in report["sources"].values():
        generation = source["generation"]
        mutation = source["mutation"]
        assert generation["samples"] == (
            generation["unique_canonical_scenarios"]
            + generation["duplicate_samples"]
        )
        for field in ("attempts", "raw_changed", "scenario_changed"):
            assert mutation[field] == sum(
                kind_counts[field]
                for kind_counts in mutation["by_kind"].values()
            )
        assert mutation["scenario_changed"] <= mutation["raw_changed"]
        assert mutation["raw_changed_scenario_unchanged"] == (
            mutation["raw_changed"] - mutation["scenario_changed"]
        )
        assert sum(generation["operation_counts"].values()) == sum(
            sum(buckets.values())
            for buckets in generation["endpoint_counts_before_operation"].values()
        )


class _IndependentRng:
    def __init__(self, seed: int):
        self.seed = seed & 0xFFFFFFFFFFFFFFFF
        self.counter = 0

    def next(self) -> int:
        payload = self.seed.to_bytes(8, "little") + self.counter.to_bytes(8, "little")
        self.counter += 1
        digest = hashlib.sha256(b"pipe-oracle-analysis\x00" + payload).digest()
        return int.from_bytes(digest[:8], "little")

    def range(self, lo: int, hi: int) -> int:
        if lo >= hi:
            return lo
        return lo + (self.next() % (hi - lo))


if __name__ == "__main__":
    main()
