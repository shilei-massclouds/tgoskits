import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/eventfd-oracle"
CASE_DIR = WORKSPACE_ROOT / "test-suit/starryos/qemu/eventfd-linux-oracle"
CORPUS_PATH = CASE_DIR / "c/corpus/eventfd-blocking.ops"
sys.path.insert(0, str(SCRIPT_DIR))

import blocking_adapter  # noqa: E402
import blocking_generator  # noqa: E402
import blocking_mutation  # noqa: E402
import blocking_reducer  # noqa: E402
import blocking_scenario  # noqa: E402
import fuzz  # noqa: E402
import models  # noqa: E402
import fingerprint  # noqa: E402
import guest_result  # noqa: E402
from linux_oracle.persistence import CampaignStore, PersistentStateError  # noqa: E402
from linux_oracle.failure import load_failure, save_failure  # noqa: E402


class EventFdBlockingCodecTests(unittest.TestCase):
    def test_codec_round_trip_covers_controlled_worker_operations(self):
        encoded = (
            "version 0x2\n"
            "scenario arbitrary\n"
            "eventfd 0 0\n"
            "start-read 1 0\n"
            "assert-pending 1\n"
            "write 0 8 0 1\n"
            "join 1\n"
        )

        document = blocking_scenario.parse_document(encoded)
        canonical = blocking_scenario.serialize_document(document)

        self.assertEqual(blocking_scenario.parse_document(canonical), document)
        self.assertNotIn("0x", canonical)
        self.assertIn("start-read 1 0", canonical)
        self.assertIn("assert-pending 1", canonical)
        self.assertIn("join 1", canonical)
        self.assertEqual(
            blocking_scenario.analyze_scenario(document.scenarios[0]).event(0).count,
            0,
        )

    def test_codec_rejects_invalid_actor_lifecycles_and_blocking_proofs(self):
        invalid_documents = {
            "wrong-actor": (
                "version 2\nscenario x\neventfd 0 0\nstart-read 2 0\n"
            ),
            "nonblocking-start": (
                "version 2\nscenario x\neventfd2 0 0 2048\nstart-read 1 0\n"
            ),
            "read-cannot-block": (
                "version 2\nscenario x\neventfd 0 1\nstart-read 1 0\n"
            ),
            "write-cannot-block": (
                "version 2\nscenario x\neventfd 0 0\nstart-write 1 0 1\n"
            ),
            "missing-pending": (
                "version 2\nscenario x\neventfd 0 0\nstart-read 1 0\n"
                "write 0 8 0 1\njoin 1\n"
            ),
            "different-event": (
                "version 2\nscenario x\neventfd 0 0\neventfd 1 0\n"
                "start-read 1 0\nassert-pending 1\nwrite 1 8 0 1\njoin 1\n"
            ),
            "lifetime-race": (
                "version 2\nscenario x\neventfd 0 0\nstart-read 1 0\n"
                "assert-pending 1\nclose 0\n"
            ),
            "join-before-completable": (
                "version 2\nscenario x\neventfd 0 0\nstart-read 1 0\n"
                "assert-pending 1\nwrite 0 8 0 0\njoin 1\n"
            ),
            "unfinished-worker": (
                "version 2\nscenario x\neventfd 0 0\nstart-read 1 0\n"
                "assert-pending 1\n"
            ),
        }
        for label, encoded in invalid_documents.items():
            with self.subTest(label=label), self.assertRaises(
                blocking_scenario.ScenarioCodecError
            ):
                blocking_scenario.parse_document(encoded)

    def test_alias_zero_write_and_shared_nonblocking_complete_read(self):
        document = blocking_scenario.parse_document(
            "version 2\nscenario x\n"
            "eventfd2 0 0 2048\n"
            "dup 0 1\n"
            "set-status-flags 1 0\n"
            "start-read 1 0\n"
            "assert-pending 1\n"
            "write 1 8 0 0\n"
            "assert-pending 1\n"
            "write 1 8 0 3\n"
            "join 1\n"
        )

        state = blocking_scenario.analyze_scenario(document.scenarios[0])

        self.assertEqual(state.event(0).count, 0)
        self.assertEqual(
            state.descriptor(0).description_id, state.descriptor(1).description_id
        )
        self.assertFalse(state.description(0).nonblocking)

    def test_semaphore_phased_release_stays_pending_until_enough_space(self):
        document = blocking_scenario.parse_document(
            "version 2\nscenario x\n"
            "eventfd2 0 4294967295 1\n"
            "write 0 8 0 18446744069414584319\n"
            "start-write 1 0 2\n"
            "assert-pending 1\n"
            "read 0 8 0\n"
            "assert-pending 1\n"
            "read 0 8 0\n"
            "join 1\n"
        )

        state = blocking_scenario.analyze_scenario(document.scenarios[0])

        self.assertEqual(state.event(0).count, blocking_scenario.MAX_COUNTER)

    def test_checked_corpus_is_canonical_and_covers_every_blocking_story(self):
        encoded = CORPUS_PATH.read_bytes()
        document = blocking_scenario.parse_document(encoded)

        blocking_scenario.validate_entry_limits(document)

        self.assertEqual(blocking_scenario.serialize_document(document).encode(), encoded)
        operations = [
            operation
            for scenario in document.scenarios
            for operation in scenario.operations
        ]
        self.assertTrue(
            any(isinstance(operation, blocking_scenario.StartRead) for operation in operations)
        )
        self.assertTrue(
            any(isinstance(operation, blocking_scenario.StartWrite) for operation in operations)
        )
        self.assertGreaterEqual(
            sum(
                isinstance(operation, blocking_scenario.AssertPending)
                for operation in operations
            ),
            len(document.scenarios),
        )


class EventFdBlockingCampaignTests(unittest.TestCase):
    def test_model_selection_keeps_simple_default_and_separate_adapter_identity(self):
        self.assertIs(models.spec_for_model("simple-single"), models.DEFAULT_SPEC)
        self.assertEqual(models.DEFAULT_SPEC.adapter_id, "eventfd-v1")
        self.assertEqual(
            models.spec_for_model("blocking").adapter_id, "eventfd-blocking-v1"
        )
        self.assertIs(
            models.spec_for_adapter_id("eventfd-blocking-v1"),
            blocking_adapter.SPEC,
        )
        with self.assertRaises(ValueError):
            models.spec_for_model("blocking-v2")
        with self.assertRaises(ValueError):
            models.spec_for_adapter_id("unknown")

    def test_fuzz_cli_selects_models_explicitly_and_keeps_simple_default(self):
        with mock.patch.object(fuzz, "_run_common_campaign", return_value=0) as run:
            self.assertEqual(fuzz.main(["--batches", "1", "--batch-size", "1"]), 0)
            self.assertEqual(run.call_args.args[0].adapter_id, "eventfd-v1")
        with mock.patch.object(fuzz, "_run_common_campaign", return_value=0) as run:
            self.assertEqual(
                fuzz.main(
                    [
                        "--model",
                        "blocking",
                        "--batches",
                        "1",
                        "--batch-size",
                        "1",
                    ]
                ),
                0,
            )
            self.assertEqual(run.call_args.args[0].adapter_id, "eventfd-blocking-v1")

    def test_blocking_adapter_has_isolated_campaign_and_wait_coverage(self):
        spec = blocking_adapter.SPEC
        self.assertEqual(spec.campaign.root, Path("coverage/eventfd-blocking-oracle-fuzz"))
        self.assertEqual(spec.coverage.target_set_id, "eventfd-blocking-v1")
        self.assertIn("os/arceos/modules/axtask/src/future/poll.rs", spec.coverage.source_paths)
        self.assertIn("components/axpoll/src/lib.rs", spec.coverage.source_paths)
        for source in spec.coverage.source_paths:
            self.assertTrue((WORKSPACE_ROOT / source).is_file(), source)

    def test_generation_mutation_and_reduction_remain_canonical_and_deterministic(self):
        first = [blocking_generator.canonicalize_seed(seed) for seed in range(8)]
        second = [blocking_generator.canonicalize_seed(seed) for seed in range(8)]
        self.assertEqual(
            [(item.digest, item.encoded) for item in first],
            [(item.digest, item.encoded) for item in second],
        )
        parent = first[0].document
        donor = first[1].document
        parent_digest = blocking_scenario.canonical_digest(parent)
        for index, kind in enumerate(blocking_mutation.MUTATION_KINDS):
            with self.subTest(kind=kind):
                candidate = blocking_mutation.mutate_document(
                    blocking_generator.CampaignRng(100 + index),
                    parent,
                    donor,
                    requested_kind=kind,
                )
                self.assertIs(
                    candidate.classification,
                    blocking_mutation.CandidateClassification.EXECUTABLE,
                )
                self.assertNotEqual(candidate.digest, parent_digest)
                blocking_scenario.validate_entry_limits(candidate.document)

        origin = blocking_reducer.with_origins(first[2].document)
        candidates = list(blocking_reducer.reduction_candidates(origin))
        self.assertTrue(candidates)
        for candidate in candidates:
            blocking_scenario.validate_entry_limits(candidate.document.plain())
            self.assertLess(
                candidate.complexity, blocking_reducer.complexity_key(origin)
            )

    def test_stable_host_recorder_requires_three_identical_traces(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            trace = root / "linux.trace"

            def stable_record(_elf, _ops, destination):
                destination.write_bytes(b"stable trace")
                return blocking_adapter.HostRecordResult(True, False, "recorded")

            with mock.patch.object(
                blocking_adapter, "record_host_once", side_effect=stable_record
            ) as recorder:
                result = blocking_adapter.record_host_stable(
                    Path("oracle"), Path("eventfd.ops"), trace
                )
            self.assertTrue(result.passed)
            self.assertEqual(recorder.call_count, 3)
            self.assertEqual(trace.read_bytes(), b"stable trace")

            calls = 0

            def unstable_record(_elf, _ops, destination):
                nonlocal calls
                destination.write_bytes(f"trace {calls}".encode())
                calls += 1
                return blocking_adapter.HostRecordResult(True, False, "recorded")

            with mock.patch.object(
                blocking_adapter, "record_host_once", side_effect=unstable_record
            ):
                result = blocking_adapter.record_host_stable(
                    Path("oracle"), Path("eventfd.ops"), trace
                )
            self.assertFalse(result.passed)
            self.assertIn("not byte-stable", result.log)

    def test_simple_and_blocking_persistence_fail_closed_across_models(self):
        simple = models.spec_for_model("simple-single")
        blocking = models.spec_for_model("blocking")
        generated = blocking_generator.canonicalize_seed(4)
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            blocking_store = CampaignStore(blocking, workspace)
            entry = blocking_store.save_entry(generated.encoded, {"region:1:1"})
            metadata_path = entry.path / "metadata.json"
            metadata = json.loads(metadata_path.read_text())
            self.assertEqual(metadata["adapter_id"], "eventfd-blocking-v1")
            self.assertNotEqual(simple.campaign.root, blocking.campaign.root)

            metadata["adapter_id"] = simple.adapter_id
            metadata_path.write_text(json.dumps(metadata))
            with self.assertRaises(PersistentStateError):
                blocking_store.load_entries()

    def test_blocking_failure_dispatch_and_artifacts_fail_closed_on_tampering(self):
        spec = blocking_adapter.SPEC
        generated = blocking_generator.canonicalize_seed(3)
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            scenario_path = root / "eventfd.ops"
            trace_path = root / "linux.trace"
            host_path = root / "eventfd-linux-oracle"
            starry_path = root / "starryos"
            scenario_path.write_bytes(generated.encoded)
            trace_path.write_bytes(b"blocking trace")
            host_path.write_bytes(b"host elf")
            starry_path.write_bytes(b"starry elf")
            saved = save_failure(
                spec,
                root / "failure",
                scenario_path=scenario_path,
                trace_path=trace_path,
                host_elf_path=host_path,
                starry_elf_path=starry_path,
                guest_log="schedule-timeout",
                profraw_paths=(),
                result_category="schedule-timeout",
                mismatch=None,
            )
            self.assertIs(models.spec_for_failure(saved.path), spec)
            self.assertEqual(load_failure(spec, saved.path).metadata["adapter_id"], spec.adapter_id)

            for target in (
                "eventfd.ops",
                "linux.trace",
                "eventfd-linux-oracle",
                "starryos",
            ):
                with self.subTest(target=target):
                    original = (saved.path / target).read_bytes()
                    (saved.path / target).write_bytes(b"tampered")
                    with self.assertRaises(PersistentStateError):
                        load_failure(spec, saved.path)
                    (saved.path / target).write_bytes(original)

            metadata_path = saved.path / "metadata.json"
            metadata = json.loads(metadata_path.read_text())
            metadata["adapter_id"] = "unknown-eventfd-model"
            metadata_path.write_text(json.dumps(metadata))
            with self.assertRaises(PersistentStateError):
                models.spec_for_failure(saved.path)

    def test_timeout_harness_error_and_early_completion_have_stable_categories(self):
        schedule = guest_result.classify_guest_execution(
            "STARRY_EVENTFD_LINUX_ORACLE_SCHEDULE_TIMEOUT: line=5", 1
        )
        harness = guest_result.classify_guest_execution(
            "STARRY_EVENTFD_LINUX_ORACLE_HARNESS_ERROR: line=5", 1
        )
        self.assertIs(
            schedule.category, guest_result.GuestResultCategory.SCHEDULE_TIMEOUT
        )
        self.assertIs(
            harness.category, guest_result.GuestResultCategory.HARNESS_ERROR
        )

        log = (
            "STARRY_EVENTFD_LINUX_ORACLE_FAILED: host=linux/x86_64 line=5 "
            'scenario=0 operation=3 text="assert-pending 1" '
            "difference_mask=0x00000008 "
            "expected={kind=16,result=0,errno=0,value=0,data_len=0} "
            "actual={kind=16,result=1,errno=0,value=0,data_len=0}\n"
        )
        difference = guest_result.parse_operation_difference(log)
        self.assertIsNotNone(difference)
        first = fingerprint.MismatchFingerprint.from_difference(
            difference, blocking_reducer.OperationOrigin(0, 3)
        )
        second = fingerprint.MismatchFingerprint.from_difference(
            difference, blocking_reducer.OperationOrigin(0, 3)
        )
        self.assertEqual(first, second)
        self.assertEqual(first.operation_kind, "assert-pending")


class EventFdBlockingHarnessTests(unittest.TestCase):
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

    def test_checked_corpus_records_identically_three_times_and_compares(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            traces = []
            for index in range(3):
                trace = root / f"trace-{index}"
                result = subprocess.run(
                    [str(self.oracle), "--record", str(CORPUS_PATH), str(trace)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                traces.append(trace.read_bytes())
            self.assertEqual(traces[0], traces[1])
            self.assertEqual(traces[1], traces[2])
            compared = subprocess.run(
                [str(self.oracle), "--compare", str(CORPUS_PATH), str(root / "trace-0")],
                capture_output=True,
                text=True,
            )
        self.assertEqual(compared.returncode, 0, compared.stderr)
        self.assertIn("STARRY_EVENTFD_LINUX_ORACLE_PASSED", compared.stdout)


if __name__ == "__main__":
    unittest.main()
