"""Unit tests for stable repeated host recording."""

import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from linux_oracle.batch import HostRecordResult
from linux_oracle.host_record import record_converged_host, record_stable_host
from linux_oracle.outcomes import AllowedTrace, ScenarioRun, fnv1a64


class StableHostRecordTests(unittest.TestCase):
    def test_three_identical_recordings_are_accepted(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            trace = Path(temporary_directory) / "artifact/linux.trace"
            calls = []

            def record(_elf, _scenario, destination):
                calls.append(destination.name)
                destination.write_bytes(b"stable trace")
                return HostRecordResult(True, False, f"recorded {len(calls)}")

            result = record_stable_host(
                record,
                Path("oracle"),
                Path("scenario.ops"),
                trace,
                temporary_prefix=".test-host-",
            )

            self.assertEqual(
                calls, ["linux-0.trace", "linux-1.trace", "linux-2.trace"]
            )
            self.assertEqual(trace.read_bytes(), b"stable trace")
            self.assertEqual(
                result,
                HostRecordResult(
                    True, False, "recorded 1\nrecorded 2\nrecorded 3"
                ),
            )

    def test_failure_on_any_attempt_stops_and_preserves_parser_category(self):
        for failing_attempt in range(3):
            with self.subTest(
                failing_attempt=failing_attempt
            ), tempfile.TemporaryDirectory() as temporary_directory:
                trace = Path(temporary_directory) / "linux.trace"
                calls = 0

                def record(_elf, _scenario, destination):
                    nonlocal calls
                    attempt = calls
                    calls += 1
                    if attempt == failing_attempt:
                        return HostRecordResult(False, True, f"failed {attempt}")
                    destination.write_bytes(b"stable trace")
                    return HostRecordResult(True, False, f"recorded {attempt}")

                result = record_stable_host(
                    record,
                    Path("oracle"),
                    Path("scenario.ops"),
                    trace,
                    temporary_prefix=".test-host-",
                )

                self.assertFalse(result.passed)
                self.assertTrue(result.parser_rejection)
                self.assertEqual(calls, failing_attempt + 1)
                self.assertFalse(trace.exists())

    def test_any_trace_difference_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            trace = Path(temporary_directory) / "linux.trace"
            calls = 0

            def record(_elf, _scenario, destination):
                nonlocal calls
                destination.write_bytes(f"trace {calls}".encode())
                calls += 1
                return HostRecordResult(True, False, "recorded")

            result = record_stable_host(
                record,
                Path("oracle"),
                Path("scenario.ops"),
                trace,
                temporary_prefix=".test-host-",
            )

            self.assertFalse(result.passed)
            self.assertFalse(result.parser_rejection)
            self.assertEqual(
                result.log,
                "blocking host trace is not byte-stable across three recordings",
            )
            self.assertFalse(trace.exists())


class ConvergedHostRecordTests(unittest.TestCase):
    def test_indexed_recorder_receives_every_run_number(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            scenario = root / "scenario.ops"
            scenario.write_bytes(b"version 7\nscenario checked\n")
            trace = root / "linux.trace"
            indexes = []

            def record_indexed(_elf, _scenario, destination, run_index):
                indexes.append(run_index)
                destination.write_bytes(bytes((run_index % 2,)))
                return HostRecordResult(True, False, f"run {run_index}")

            result = record_converged_host(
                lambda *_args: self.fail("plain recorder must not be called"),
                lambda path: (ScenarioRun(0, 1, path.read_bytes()),),
                Path("oracle"),
                scenario,
                trace,
                magic=b"PIPEORC1",
                version=7,
                temporary_prefix=".test-indexed-concurrent-",
                indexed_record_once=record_indexed,
            )

            self.assertTrue(result.passed)
            self.assertEqual(indexes, list(range(32)))

    def test_records_32_runs_and_writes_one_canonical_allowed_trace(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            scenario = root / "scenario.ops"
            scenario.write_bytes(b"version 4\nscenario checked\n")
            trace = root / "linux.trace"
            calls = 0

            def record(_elf, _scenario, destination):
                nonlocal calls
                destination.write_bytes(bytes((calls % 2,)))
                calls += 1
                return HostRecordResult(True, False, f"run {calls}")

            def decode(path):
                return (ScenarioRun(0, 3, b"vector-" + path.read_bytes()),)

            result = record_converged_host(
                record,
                decode,
                Path("oracle"),
                scenario,
                trace,
                magic=b"EVFDORC4",
                version=4,
                temporary_prefix=".test-concurrent-",
            )

            self.assertTrue(result.passed)
            self.assertEqual(calls, 32)
            decoded = AllowedTrace.from_bytes(
                trace.read_bytes(),
                expected_magic=b"EVFDORC4",
                expected_version=4,
                expected_corpus_digest=fnv1a64(scenario.read_bytes()),
            )
            self.assertEqual(len(decoded.scenarios[0].alternatives), 2)

    def test_unstable_set_is_typed_host_failure_and_not_persisted(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            scenario = root / "scenario.ops"
            scenario.write_bytes(b"version 7\nscenario checked\n")
            trace = root / "linux.trace"
            calls = 0

            def record(_elf, _scenario, destination):
                nonlocal calls
                destination.write_bytes(bytes((calls % 5,)))
                calls += 1
                return HostRecordResult(True, False, "recorded")

            result = record_converged_host(
                record,
                lambda path: (ScenarioRun(0, 1, path.read_bytes()),),
                Path("oracle"),
                scenario,
                trace,
                magic=b"PIPEORC1",
                version=7,
                temporary_prefix=".test-concurrent-",
            )

            self.assertFalse(result.passed)
            self.assertFalse(result.parser_rejection)
            self.assertIn("host-unstable", result.log)
            self.assertFalse(trace.exists())


if __name__ == "__main__":
    unittest.main()
