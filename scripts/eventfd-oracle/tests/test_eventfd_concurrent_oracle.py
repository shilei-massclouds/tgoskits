import hashlib
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/eventfd-oracle"
CASE_DIR = WORKSPACE_ROOT / "test-suit/starryos/qemu/eventfd-linux-oracle"
CORPUS_PATH = CASE_DIR / "c/corpus/eventfd-concurrent.ops"
sys.path.insert(0, str(SCRIPT_DIR))

import concurrent_adapter  # noqa: E402
import concurrent_coverage  # noqa: E402
import concurrent_generator  # noqa: E402
import concurrent_mutation  # noqa: E402
import concurrent_scenario  # noqa: E402
import fuzz  # noqa: E402
import guest_result  # noqa: E402
import models  # noqa: E402
from linux_oracle.outcomes import AllowedTrace, decode_raw_run_trace, fnv1a64  # noqa: E402


class EventFdConcurrentCodecTests(unittest.TestCase):
    def test_signal_restart_and_finite_timeout_story_round_trips(self):
        encoded = (
            "version 4\n"
            "scenario signal-timeout\n"
            "signal-config 10 268435456\n"
            "eventfd 0 0\n"
            "start-read 1 0 8\n"
            "assert-pending 1\n"
            "send-signal 1 10\n"
            "assert-signal-handled 1 1\n"
            "assert-pending 1\n"
            "write 0 8 0 1\n"
            "join 1\n"
            "eventfd 1 0\n"
            "start-poll 2 1 1 200\n"
            "assert-pending 2\n"
            "join 2\n"
        )

        document = concurrent_scenario.parse_document(encoded)
        canonical = concurrent_scenario.serialize_document(document)

        self.assertEqual(concurrent_scenario.parse_document(canonical), document)
        self.assertIn("send-signal 1 10", canonical)
        self.assertIn("start-poll 2 1 1 200", canonical)

    def test_signal_rejects_wrong_signo_flags_and_count(self):
        prefix = "version 4\nscenario x\n"
        for operation in (
            "signal-config 12 0",
            "signal-config 10 1",
            "assert-signal-handled 1 -1",
        ):
            with self.subTest(operation=operation), self.assertRaises(
                concurrent_scenario.ScenarioCodecError
            ):
                concurrent_scenario.parse_document(prefix + operation + "\n")

    def test_ppoll_timeout_and_atomic_mask_round_trip(self):
        encoded = (
            "version 4\n"
            "scenario ppoll-mask\n"
            "signal-config 10 268435456\n"
            "eventfd 0 0\n"
            "start-ppoll 1 0 1 null usr1\n"
            "assert-pending 1\n"
            "send-signal 1 10\n"
            "assert-signal-handled 1 0\n"
            "assert-pending 1\n"
            "write 0 8 0 1\n"
            "join 1\n"
            "assert-signal-handled 1 1\n"
            "eventfd 1 0\n"
            "start-ppoll 2 1 1 200000000 empty\n"
            "assert-pending 2\n"
            "join 2\n"
        )

        document = concurrent_scenario.parse_document(encoded)
        canonical = concurrent_scenario.serialize_document(document)

        self.assertEqual(concurrent_scenario.parse_document(canonical), document)
        self.assertIn("start-ppoll 1 0 1 null usr1", canonical)

    def test_ppoll_rejects_invalid_timeout_and_mask(self):
        prefix = "version 4\nscenario x\neventfd 0 0\n"
        for operation in (
            "start-ppoll 1 0 1 -1 empty",
            "start-ppoll 1 0 1 1000000001 empty",
            "start-ppoll 1 0 1 null all",
        ):
            with self.subTest(operation=operation), self.assertRaises(
                concurrent_scenario.ScenarioCodecError
            ):
                concurrent_scenario.parse_document(prefix + operation + "\n")

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
        self.assertIn(
            "os/StarryOS/kernel/src/task/signal.rs",
            concurrent_coverage.TARGET_SOURCE_PATHS,
        )
        self.assertEqual(models.spec_for_model("simple-single").adapter_id, "eventfd-v1")
        self.assertEqual(
            models.spec_for_model("blocking").adapter_id, "eventfd-blocking-v2"
        )

    def test_generator_and_mutation_cover_signal_and_timeout_stories(self):
        generated = []
        for story in range(9):
            scenario = concurrent_generator.generate_scenario(
                concurrent_generator.CampaignRng(42 + story), story=story
            )
            concurrent_scenario.analyze_scenario(scenario)
            generated.append(scenario)

        self.assertTrue(
            any(
                isinstance(operation, concurrent_scenario.SignalConfig)
                for operation in generated[6].operations
            )
        )
        self.assertTrue(
            any(
                isinstance(operation, concurrent_scenario.StartPoll)
                and operation.timeout_ms >= 100
                for operation in generated[7].operations
            )
        )
        self.assertTrue(
            any(
                isinstance(operation, concurrent_scenario.StartPpoll)
                for operation in generated[8].operations
            )
        )

        parent = concurrent_scenario.ScenarioDocument((generated[0],), version=4)
        donor = concurrent_scenario.ScenarioDocument((generated[6],), version=4)
        for index, kind in enumerate(concurrent_mutation.MUTATION_KINDS):
            with self.subTest(kind=kind):
                candidate = concurrent_mutation.mutate_document(
                    concurrent_generator.CampaignRng(100 + index),
                    parent,
                    donor,
                    requested_kind=kind,
                )
                self.assertIs(
                    candidate.classification,
                    concurrent_mutation.CandidateClassification.EXECUTABLE,
                )
                concurrent_scenario.validate_entry_limits(candidate.document)

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

    def test_syscall_schedule_and_qemu_timeouts_are_distinct(self):
        syscall_timeout = guest_result.classify_guest_execution(
            "STARRY_EVENTFD_LINUX_ORACLE_SYSCALL_TIMEOUT: line=1", 1
        )
        schedule_timeout = guest_result.classify_guest_execution(
            "STARRY_EVENTFD_LINUX_ORACLE_SCHEDULE_TIMEOUT: line=1", 1
        )
        qemu_timeout = guest_result.classify_guest_execution("", None, timed_out=True)

        self.assertIs(
            syscall_timeout.category, guest_result.GuestResultCategory.SYSCALL_TIMEOUT
        )
        self.assertIs(
            schedule_timeout.category, guest_result.GuestResultCategory.SCHEDULE_TIMEOUT
        )
        self.assertIs(qemu_timeout.category, guest_result.GuestResultCategory.TIMEOUT)


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
            self.assertEqual(len(scenarios), 8)
            self.assertEqual(sum(item.operation_count for item in scenarios), 121)

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
            self.assertEqual(len(allowed.scenarios), 8)
            self.assertEqual(len(allowed.scenarios[6].alternatives), 1)
            self.assertEqual(len(allowed.scenarios[7].alternatives), 1)
            compared = subprocess.run(
                [str(self.oracle), "--compare", str(CORPUS_PATH), str(aggregate)],
                capture_output=True,
                text=True,
            )
        self.assertEqual(compared.returncode, 0, compared.stderr)
        self.assertIn("STARRY_EVENTFD_LINUX_ORACLE_PASSED", compared.stdout)

    def test_cleanup_joins_restarted_and_masked_workers(self):
        corpora = (
            "version 4\nscenario cleanup\nsignal-config 10 268435456\n"
            "eventfd 0 0\nstart-read 1 0 8\nassert-pending 1\n"
            "send-signal 1 10\nassert-signal-handled 1 1\ninvalid\n",
            "version 4\nscenario cleanup\nsignal-config 10 268435456\n"
            "eventfd 0 0\nstart-ppoll 1 0 1 null usr1\nassert-pending 1\n"
            "send-signal 1 10\nassert-signal-handled 1 0\ninvalid\n",
        )
        for index, encoded in enumerate(corpora):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                corpus = root / "cleanup.ops"
                trace = root / "cleanup.trace"
                corpus.write_text(encoded)
                started = time.monotonic()
                result = subprocess.run(
                    [str(self.oracle), "--record", str(corpus), str(trace)],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                self.assertLess(time.monotonic() - started, 3)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('operation="invalid" invalid operation', result.stderr)


if __name__ == "__main__":
    unittest.main()
