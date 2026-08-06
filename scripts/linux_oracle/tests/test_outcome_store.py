"""Fail-first tests for persistent, monotonically growing Linux outcomes."""

import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from linux_oracle.outcome_store import OutcomeStore
from linux_oracle.outcomes import (
    AllowedAlternative,
    AllowedScenario,
    AllowedTrace,
)


class OutcomeStoreTests(unittest.TestCase):
    def test_later_recordings_monotonically_extend_a_scenario_set(self):
        scenario_key = hashlib.sha256(b"canonical scenario").hexdigest()
        first = AllowedTrace(
            4,
            7,
            (
                AllowedScenario(
                    0,
                    2,
                    (AllowedAlternative(_result_vector(0, b"first")),),
                ),
            ),
        )
        second = AllowedTrace(
            4,
            9,
            (
                AllowedScenario(
                    0,
                    2,
                    (AllowedAlternative(_result_vector(0, b"second")),),
                ),
            ),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            store = OutcomeStore(Path(temporary_directory))
            first_merged = store.merge(
                (scenario_key,), first, kernel_release="linux-a"
            )
            second_merged = store.merge(
                (scenario_key,), second, kernel_release="linux-b"
            )
            reloaded = store.load(scenario_key)

        self.assertEqual(first_merged, first)
        self.assertEqual(second_merged.corpus_digest, 9)
        self.assertEqual(
            tuple(
                alternative.payload
                for alternative in second_merged.scenarios[0].alternatives
            ),
            (_result_vector(0, b"first"), _result_vector(0, b"second")),
        )
        self.assertEqual(
            tuple(alternative.payload for alternative in reloaded.alternatives),
            (_result_vector(0, b"first"), _result_vector(0, b"second")),
        )
        self.assertEqual(reloaded.kernel_releases, ("linux-a", "linux-b"))

    def test_batch_scenario_indexes_do_not_create_semantic_alternatives(self):
        target_key = hashlib.sha256(b"target scenario").hexdigest()
        dummy_key = hashlib.sha256(b"dummy scenario").hexdigest()
        first = AllowedTrace(
            4,
            7,
            (
                AllowedScenario(
                    0,
                    1,
                    (AllowedAlternative(_result_vector(0, b"target")),),
                ),
            ),
        )
        second = AllowedTrace(
            4,
            9,
            (
                AllowedScenario(
                    0,
                    1,
                    (AllowedAlternative(_result_vector(0, b"dummy")),),
                ),
                AllowedScenario(
                    1,
                    1,
                    (AllowedAlternative(_result_vector(1, b"target")),),
                ),
            ),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            store = OutcomeStore(Path(temporary_directory))
            store.merge((target_key,), first, kernel_release="linux-a")
            merged = store.merge(
                (dummy_key, target_key), second, kernel_release="linux-a"
            )
            stored = store.load(target_key)

        self.assertEqual(len(merged.scenarios[1].alternatives), 1)
        self.assertEqual(
            struct.unpack_from("<I", merged.scenarios[1].alternatives[0].payload)[0],
            1,
        )
        self.assertEqual(
            struct.unpack_from("<I", stored.alternatives[0].payload)[0],
            0,
        )


def _result_vector(scenario_index: int, label: bytes) -> bytes:
    encoded = bytearray(112)
    struct.pack_into("<I", encoded, 0, scenario_index)
    encoded[48 : 48 + len(label)] = label
    return bytes(encoded)


if __name__ == "__main__":
    unittest.main()
