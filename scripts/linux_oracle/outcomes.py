"""Canonical complete-scenario allowed sets for concurrent adapters."""

import hashlib
import struct
from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Sequence, Tuple


MAX_ALTERNATIVES = 4
MIN_ALTERNATIVE_OBSERVATIONS = 3
CONVERGENCE_RUNS = 8

_TRACE_HEADER = struct.Struct("<8sIIQ32s")
_SCENARIO_HEADER = struct.Struct("<III32s")
_ALTERNATIVE_HEADER = struct.Struct("<I")


def fnv1a64(encoded: bytes) -> int:
    """Return the corpus digest used by the C oracle harnesses."""
    value = 14695981039346656037
    for byte in encoded:
        value ^= byte
        value = value * 1099511628211 & ((1 << 64) - 1)
    return value


class AllowedOutcomeError(ValueError):
    """A concurrent host set is unstable or its trace is malformed."""


@dataclass(frozen=True)
class ScenarioRun:
    """One raw host result vector for one scenario."""

    scenario_index: int
    operation_count: int
    payload: bytes

    def __post_init__(self) -> None:
        if self.scenario_index < 0 or self.operation_count <= 0 or not self.payload:
            raise AllowedOutcomeError("scenario run identity is invalid")


@dataclass(frozen=True)
class AllowedAlternative:
    """One exact complete-scenario result vector."""

    payload: bytes

    def __post_init__(self) -> None:
        if not self.payload:
            raise AllowedOutcomeError("allowed alternative is empty")


@dataclass(frozen=True)
class AllowedScenario:
    """Canonical alternatives for one scenario."""

    scenario_index: int
    operation_count: int
    alternatives: Tuple[AllowedAlternative, ...]

    def __post_init__(self) -> None:
        payloads = tuple(alternative.payload for alternative in self.alternatives)
        if (
            self.scenario_index < 0
            or self.operation_count <= 0
            or not payloads
            or len(payloads) > MAX_ALTERNATIVES
            or payloads != tuple(sorted(set(payloads)))
        ):
            raise AllowedOutcomeError("allowed scenario is not canonical")

    @property
    def set_digest(self) -> bytes:
        digest = hashlib.sha256()
        digest.update(struct.pack("<II", self.scenario_index, self.operation_count))
        for alternative in self.alternatives:
            digest.update(_ALTERNATIVE_HEADER.pack(len(alternative.payload)))
            digest.update(alternative.payload)
        return digest.digest()


@dataclass(frozen=True)
class AllowedTrace:
    """Versioned aggregate trace containing complete correlated alternatives."""

    version: int
    corpus_digest: int
    scenarios: Tuple[AllowedScenario, ...]

    def __post_init__(self) -> None:
        if self.version <= 0 or not 0 <= self.corpus_digest <= (1 << 64) - 1:
            raise AllowedOutcomeError("allowed trace identity is invalid")
        indexes = tuple(scenario.scenario_index for scenario in self.scenarios)
        if not indexes or indexes != tuple(range(len(indexes))):
            raise AllowedOutcomeError("allowed trace scenarios are not canonical")

    @property
    def aggregate_digest(self) -> bytes:
        return hashlib.sha256(self.body_bytes()).digest()

    def body_bytes(self) -> bytes:
        encoded = bytearray()
        for scenario in self.scenarios:
            encoded.extend(
                _SCENARIO_HEADER.pack(
                    scenario.scenario_index,
                    scenario.operation_count,
                    len(scenario.alternatives),
                    scenario.set_digest,
                )
            )
            for alternative in scenario.alternatives:
                encoded.extend(_ALTERNATIVE_HEADER.pack(len(alternative.payload)))
                encoded.extend(alternative.payload)
        return bytes(encoded)

    def to_bytes(self, magic: bytes) -> bytes:
        if len(magic) != 8:
            raise AllowedOutcomeError("trace magic must contain eight bytes")
        body = self.body_bytes()
        return _TRACE_HEADER.pack(
            magic,
            self.version,
            len(self.scenarios),
            self.corpus_digest,
            hashlib.sha256(body).digest(),
        ) + body

    @classmethod
    def from_bytes(
        cls,
        encoded: bytes,
        *,
        expected_magic: bytes,
        expected_version: int,
        expected_corpus_digest: int,
    ) -> "AllowedTrace":
        if len(encoded) < _TRACE_HEADER.size:
            raise AllowedOutcomeError("allowed trace is truncated")
        magic, version, scenario_count, corpus_digest, aggregate_digest = (
            _TRACE_HEADER.unpack_from(encoded)
        )
        if (
            magic != expected_magic
            or version != expected_version
            or corpus_digest != expected_corpus_digest
            or scenario_count == 0
        ):
            raise AllowedOutcomeError("trace identity is invalid")
        body = encoded[_TRACE_HEADER.size :]
        if hashlib.sha256(body).digest() != aggregate_digest:
            raise AllowedOutcomeError("allowed trace aggregate digest is invalid")
        offset = _TRACE_HEADER.size
        scenarios = []
        for expected_index in range(scenario_count):
            if offset + _SCENARIO_HEADER.size > len(encoded):
                raise AllowedOutcomeError("allowed scenario header is truncated")
            scenario_index, operation_count, count, set_digest = (
                _SCENARIO_HEADER.unpack_from(encoded, offset)
            )
            offset += _SCENARIO_HEADER.size
            if scenario_index != expected_index or not 1 <= count <= MAX_ALTERNATIVES:
                raise AllowedOutcomeError("allowed scenario identity is invalid")
            alternatives = []
            for _alternative_index in range(count):
                if offset + _ALTERNATIVE_HEADER.size > len(encoded):
                    raise AllowedOutcomeError("allowed alternative header is truncated")
                (length,) = _ALTERNATIVE_HEADER.unpack_from(encoded, offset)
                offset += _ALTERNATIVE_HEADER.size
                if length == 0 or offset + length > len(encoded):
                    raise AllowedOutcomeError("allowed alternative is truncated")
                alternatives.append(AllowedAlternative(encoded[offset : offset + length]))
                offset += length
            scenario = AllowedScenario(
                scenario_index, operation_count, tuple(alternatives)
            )
            if scenario.set_digest != set_digest:
                raise AllowedOutcomeError("allowed scenario set digest is invalid")
            scenarios.append(scenario)
        if offset != len(encoded):
            raise AllowedOutcomeError("allowed trace has trailing bytes")
        return cls(version, corpus_digest, tuple(scenarios))


class AllowedOutcomeRecorder:
    """Collect repeated host runs and enforce the bounded convergence policy."""

    def __init__(
        self,
        *,
        expected_runs: int = 32,
        deterministic: Iterable[int] = (),
    ) -> None:
        if expected_runs < CONVERGENCE_RUNS:
            raise AllowedOutcomeError("expected host run count is too small")
        self.expected_runs = expected_runs
        self.deterministic = frozenset(deterministic)
        self._runs = 0
        self._operation_counts: Optional[Tuple[int, ...]] = None
        self._counts: Tuple[Dict[bytes, int], ...] = ()
        self._first_seen: Tuple[Dict[bytes, int], ...] = ()

    def add_run(self, scenarios: Sequence[ScenarioRun]) -> None:
        if self._runs >= self.expected_runs:
            raise AllowedOutcomeError("too many host runs")
        current = tuple(scenarios)
        indexes = tuple(scenario.scenario_index for scenario in current)
        if not current or indexes != tuple(range(len(current))):
            raise AllowedOutcomeError("host run scenario identity changed")
        operation_counts = tuple(scenario.operation_count for scenario in current)
        if self._operation_counts is None:
            self._operation_counts = operation_counts
            self._counts = tuple({} for _scenario in current)
            self._first_seen = tuple({} for _scenario in current)
        elif operation_counts != self._operation_counts:
            raise AllowedOutcomeError("host run operation count changed")
        for index, scenario in enumerate(current):
            counts = self._counts[index]
            first_seen = self._first_seen[index]
            if scenario.payload not in counts:
                counts[scenario.payload] = 0
                first_seen[scenario.payload] = self._runs
            counts[scenario.payload] += 1
        self._runs += 1

    def finish(self, *, version: int, corpus_digest: int) -> AllowedTrace:
        if self._runs != self.expected_runs or self._operation_counts is None:
            raise AllowedOutcomeError("host recording did not run exactly as requested")
        scenarios = []
        convergence_start = self.expected_runs - CONVERGENCE_RUNS
        for index, operation_count in enumerate(self._operation_counts):
            counts = self._counts[index]
            if len(counts) > MAX_ALTERNATIVES:
                raise AllowedOutcomeError(
                    f"scenario {index} produced more than {MAX_ALTERNATIVES} alternatives"
                )
            if any(run >= convergence_start for run in self._first_seen[index].values()):
                raise AllowedOutcomeError(
                    f"scenario {index} added an alternative in the final 8 runs"
                )
            if any(count < MIN_ALTERNATIVE_OBSERVATIONS for count in counts.values()):
                raise AllowedOutcomeError(
                    f"scenario {index} has an alternative observed fewer than 3 times"
                )
            if index in self.deterministic and len(counts) != 1:
                raise AllowedOutcomeError(
                    f"deterministic scenario {index} produced multiple alternatives"
                )
            alternatives = tuple(
                AllowedAlternative(payload) for payload in sorted(counts)
            )
            scenarios.append(AllowedScenario(index, operation_count, alternatives))
        unknown_deterministic = self.deterministic - set(range(len(scenarios)))
        if unknown_deterministic:
            raise AllowedOutcomeError("deterministic scenario index is out of range")
        return AllowedTrace(version, corpus_digest, tuple(scenarios))


__all__ = [
    "AllowedAlternative",
    "AllowedOutcomeError",
    "AllowedOutcomeRecorder",
    "AllowedScenario",
    "AllowedTrace",
    "ScenarioRun",
    "fnv1a64",
]
