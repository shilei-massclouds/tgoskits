"""Fail-first tests for bounded complete-scenario outcome sets."""

import hashlib
import sys
import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from linux_oracle.outcomes import (
    AllowedOutcomeError,
    AllowedOutcomeRecorder,
    AllowedTrace,
    ScenarioRun,
    decode_raw_run_trace,
    encode_raw_run_trace,
)


class AllowedOutcomeRecorderTests(unittest.TestCase):
    def test_complete_alternatives_preserve_cross_operation_correlation(self):
        recorder = AllowedOutcomeRecorder(expected_runs=32)
        first = b"actor1=ready;actor2=pending"
        second = b"actor1=pending;actor2=ready"
        for index in range(32):
            payload = first if index % 2 == 0 else second
            recorder.add_run((ScenarioRun(0, 2, payload),))

        trace = recorder.finish(version=4, corpus_digest=7)

        self.assertEqual(
            tuple(alternative.payload for alternative in trace.scenarios[0].alternatives),
            tuple(sorted((first, second))),
        )
        self.assertNotIn(b"actor1=ready;actor2=ready", trace.to_bytes(b"EVFDORC4"))

    def test_final_run_alternative_is_admitted(self):
        recorder = AllowedOutcomeRecorder(expected_runs=32)
        for index in range(32):
            payload = b"late" if index == 31 else b"stable"
            recorder.add_run((ScenarioRun(0, 1, payload),))

        trace = recorder.finish(version=4, corpus_digest=7)

        self.assertEqual(
            tuple(
                alternative.payload
                for alternative in trace.scenarios[0].alternatives
            ),
            (b"late", b"stable"),
        )

    def test_single_observation_is_admitted(self):
        recorder = AllowedOutcomeRecorder(expected_runs=32)
        for index in range(32):
            recorder.add_run(
                (ScenarioRun(0, 1, b"rare" if index == 0 else b"common"),)
            )

        trace = recorder.finish(version=4, corpus_digest=7)

        self.assertEqual(
            tuple(
                alternative.payload
                for alternative in trace.scenarios[0].alternatives
            ),
            (b"common", b"rare"),
        )

    def test_more_than_four_observed_alternatives_are_preserved(self):
        recorder = AllowedOutcomeRecorder(expected_runs=32)
        for index in range(32):
            recorder.add_run((ScenarioRun(0, 1, bytes((index % 5,))),))

        trace = recorder.finish(version=4, corpus_digest=7)

        self.assertEqual(
            tuple(
                alternative.payload
                for alternative in trace.scenarios[0].alternatives
            ),
            tuple(bytes((index,)) for index in range(5)),
        )

    def test_deterministic_scenario_rejects_a_second_alternative(self):
        recorder = AllowedOutcomeRecorder(expected_runs=32, deterministic=(1,))
        for index in range(32):
            recorder.add_run(
                (
                    ScenarioRun(0, 1, b"variable" + bytes((index % 2,))),
                    ScenarioRun(1, 1, b"fixed" if index < 16 else b"not-fixed"),
                )
            )

        with self.assertRaisesRegex(AllowedOutcomeError, "deterministic scenario 1"):
            recorder.finish(version=7, corpus_digest=11)

    def test_trace_is_canonical_digest_bound_and_strictly_versioned(self):
        recorder = AllowedOutcomeRecorder(expected_runs=32)
        for _index in range(32):
            recorder.add_run((ScenarioRun(0, 3, b"result-vector"),))
        trace = recorder.finish(version=4, corpus_digest=0x1234)
        encoded = trace.to_bytes(b"EVFDORC4")

        decoded = AllowedTrace.from_bytes(
            encoded,
            expected_magic=b"EVFDORC4",
            expected_version=4,
            expected_corpus_digest=0x1234,
        )

        self.assertEqual(decoded, trace)
        self.assertEqual(decoded.aggregate_digest, hashlib.sha256(decoded.body_bytes()).digest())
        with self.assertRaisesRegex(AllowedOutcomeError, "trace identity"):
            AllowedTrace.from_bytes(
                encoded,
                expected_magic=b"PIPEORC1",
                expected_version=4,
                expected_corpus_digest=0x1234,
            )
        with self.assertRaisesRegex(AllowedOutcomeError, "trace identity"):
            AllowedTrace.from_bytes(
                encoded,
                expected_magic=b"EVFDORC4",
                expected_version=3,
                expected_corpus_digest=0x1234,
            )

    def test_trace_rejects_trailing_corruption(self):
        recorder = AllowedOutcomeRecorder(expected_runs=32)
        for _index in range(32):
            recorder.add_run((ScenarioRun(0, 1, b"one"),))
        encoded = recorder.finish(version=4, corpus_digest=9).to_bytes(b"EVFDORC4")

        with self.assertRaises(AllowedOutcomeError):
            AllowedTrace.from_bytes(
                encoded + b"x",
                expected_magic=b"EVFDORC4",
                expected_version=4,
                expected_corpus_digest=9,
            )

    def test_raw_run_trace_round_trip_is_strict(self):
        scenarios = (
            ScenarioRun(0, 2, b"first-vector"),
            ScenarioRun(1, 3, b"second-vector"),
        )
        encoded = encode_raw_run_trace(
            scenarios,
            magic=b"EVFDRUN4",
            version=4,
            corpus_digest=17,
        )

        self.assertEqual(
            decode_raw_run_trace(
                encoded,
                expected_magic=b"EVFDRUN4",
                expected_version=4,
                expected_corpus_digest=17,
            ),
            scenarios,
        )
        with self.assertRaisesRegex(AllowedOutcomeError, "raw trace identity"):
            decode_raw_run_trace(
                encoded,
                expected_magic=b"PIPERUN7",
                expected_version=4,
                expected_corpus_digest=17,
            )


if __name__ == "__main__":
    unittest.main()
