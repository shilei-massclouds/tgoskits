"""Fail-first tests for persistent, monotonically growing Linux outcomes."""

import hashlib
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
                    (AllowedAlternative(b"first"),),
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
                    (AllowedAlternative(b"second"),),
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
            (b"first", b"second"),
        )
        self.assertEqual(
            tuple(alternative.payload for alternative in reloaded.alternatives),
            (b"first", b"second"),
        )
        self.assertEqual(reloaded.kernel_releases, ("linux-a", "linux-b"))


if __name__ == "__main__":
    unittest.main()
