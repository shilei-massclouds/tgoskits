import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/eventfd-oracle"
CASE_DIR = WORKSPACE_ROOT / "test-suit/starryos/qemu/eventfd-linux-oracle"
CORPUS_PATH = CASE_DIR / "c/corpus/eventfd-concurrent.ops"
sys.path.insert(0, str(SCRIPT_DIR))

import concurrent_adapter  # noqa: E402
import concurrent_scenario  # noqa: E402
import fuzz  # noqa: E402
import guest_result  # noqa: E402
import models  # noqa: E402
from linux_oracle.outcomes import AllowedTrace, decode_raw_run_trace, fnv1a64  # noqa: E402


class EventFdConcurrentCodecTests(unittest.TestCase):
    def test_v4_round_trip_preserves_two_worker_lifecycle(self):
        encoded = (
            "version 4\n"
            "scenario readers\n"
            "eventfd2 0 0 1\n"
            "dup 0 1\n"
            "start-read 1 0 8\n"
            "start-read 2 1 8\n"
            "assert-all-pending\n"
            "write 0 8 0 2\n"
            "join-set 1 2\n"
        )

        document = concurrent_scenario.parse_document(encoded)
        canonical = concurrent_scenario.serialize_document(document)

        self.assertEqual(concurrent_scenario.parse_document(canonical), document)
        self.assertIn("start-read 2 1 8", canonical)
        self.assertIn("join-set 1 2", canonical)

    def test_v4_rejects_invalid_actor_mask_timeout_and_cross_version(self):
        invalid = (
            "version 4\nscenario x\neventfd 0 0\nstart-read 3 0 8\n"
        )
        with self.assertRaises(concurrent_scenario.ScenarioCodecError):
            concurrent_scenario.parse_document(invalid)
        with self.assertRaises(concurrent_scenario.ScenarioCodecError):
            concurrent_scenario.parse_document(
                "version 3\nscenario x\neventfd 0 0\n"
            )

    def test_checked_corpus_is_canonical_and_bounded(self):
        encoded = CORPUS_PATH.read_bytes()
        document = concurrent_scenario.parse_document(encoded)

        concurrent_scenario.validate_entry_limits(document)
        self.assertEqual(concurrent_scenario.serialize_document(document).encode(), encoded)
        self.assertLessEqual(len(document.scenarios), 8)
        self.assertTrue(
            any(
                isinstance(operation, concurrent_scenario.AssertAllPending)
                for scenario in document.scenarios
                for operation in scenario.operations
            )
        )
        self.assertEqual(
            concurrent_scenario.canonical_digest(document),
            hashlib.sha256(encoded).hexdigest(),
        )


class EventFdConcurrentRoutingTests(unittest.TestCase):
    def test_concurrent_model_is_exact_and_legacy_routes_are_unchanged(self):
        self.assertIs(models.spec_for_model("concurrent"), concurrent_adapter.SPEC)
        self.assertEqual(concurrent_adapter.SPEC.adapter_id, "eventfd-concurrent-v1")
        self.assertEqual(concurrent_adapter.SPEC.corpus_version, 4)
        self.assertEqual(
            concurrent_adapter.SPEC.campaign.root,
            Path("coverage/eventfd-concurrent-v1-oracle-fuzz"),
        )
        self.assertEqual(
            concurrent_adapter.SPEC.coverage.target_set_id,
            "eventfd-concurrent-v1",
        )
        self.assertEqual(models.spec_for_model("simple-single").adapter_id, "eventfd-v1")
        self.assertEqual(
            models.spec_for_model("blocking").adapter_id, "eventfd-blocking-v2"
        )

    def test_cli_routes_concurrent_without_changing_default(self):
        with mock.patch.object(fuzz, "_run_common_campaign", return_value=0) as run:
            self.assertEqual(fuzz.main(["--batches", "0"]), 0)
            self.assertEqual(run.call_args.args[0].adapter_id, "eventfd-v1")
        with mock.patch.object(fuzz, "_run_common_campaign", return_value=0) as run:
            self.assertEqual(
                fuzz.main(["--model", "concurrent", "--batches", "0"]), 0
            )
            self.assertEqual(run.call_args.args[0].adapter_id, "eventfd-concurrent-v1")

    def test_complete_scenario_mismatch_is_typed_and_keeps_actual_vector(self):
        vector = "00" * 112
        vector_digest = hashlib.sha256(bytes.fromhex(vector)).hexdigest()
        log = (
            "STARRY_EVENTFD_CONCURRENT_MISMATCH: scenario=2 alternative=1 "
            "byte_offset=16 expected_length=112 actual_length=112 "
            "expected_byte=8 actual_byte=255 set_digest="
            + "11" * 32
            + " actual_digest="
            + vector_digest
            + " actual_vector="
            + vector
            + "\n"
        )

        result = guest_result.classify_guest_execution(log, 1)

        self.assertIs(
            result.category, guest_result.GuestResultCategory.SEMANTIC_MISMATCH
        )
        self.assertEqual(result.difference.scenario_index, 2)
        self.assertEqual(result.difference.byte_offset, 16)
        self.assertEqual(result.difference.actual_vector, vector)


class EventFdConcurrentHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory()
        cls.build = Path(cls._temporary.name) / "build"
        subprocess.run(
            ["cmake", "-S", str(CASE_DIR / "c"), "-B", str(cls.build)],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["cmake", "--build", str(cls.build), "--target", "eventfd-linux-oracle"],
            check=True,
            capture_output=True,
            text=True,
        )
        cls.oracle = cls.build / "eventfd-linux-oracle"

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def test_v4_raw_record_converges_and_aggregate_self_compares(self):
        corpus_digest = fnv1a64(CORPUS_PATH.read_bytes())
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            raw = root / "raw.trace"
            recorded = subprocess.run(
                [str(self.oracle), "--record", str(CORPUS_PATH), str(raw)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(recorded.returncode, 0, recorded.stderr)
            scenarios = decode_raw_run_trace(
                raw.read_bytes(),
                expected_magic=b"EVFDRUN4",
                expected_version=4,
                expected_corpus_digest=corpus_digest,
            )
            self.assertEqual(len(scenarios), 6)
            self.assertEqual(sum(item.operation_count for item in scenarios), 46)

            aggregate = root / "linux.trace"
            result = concurrent_adapter.record_host_converged(
                self.oracle, CORPUS_PATH, aggregate
            )
            self.assertTrue(result.passed, result.log)
            allowed = AllowedTrace.from_bytes(
                aggregate.read_bytes(),
                expected_magic=b"EVFDORC4",
                expected_version=4,
                expected_corpus_digest=corpus_digest,
            )
            self.assertEqual(len(allowed.scenarios), 6)
            compared = subprocess.run(
                [str(self.oracle), "--compare", str(CORPUS_PATH), str(aggregate)],
                capture_output=True,
                text=True,
            )
        self.assertEqual(compared.returncode, 0, compared.stderr)
        self.assertIn("STARRY_EVENTFD_LINUX_ORACLE_PASSED", compared.stdout)


if __name__ == "__main__":
    unittest.main()
