"""Unit tests for stable repeated host recording."""

import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from linux_oracle.batch import HostRecordResult
from linux_oracle.host_record import record_stable_host


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


if __name__ == "__main__":
    unittest.main()
