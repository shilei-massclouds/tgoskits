import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/pipe-oracle"
CASE_DIR = WORKSPACE_ROOT / "test-suit/starryos/qemu/pipe-linux-oracle"
CORPUS_PATHS = (
    CASE_DIR / "c/corpus/pipe-blocking-read.ops",
    CASE_DIR / "c/corpus/pipe-blocking-write.ops",
)
SIMPLE_CORPUS_PATH = CASE_DIR / "c/corpus/pipe.ops"
sys.path.insert(0, str(SCRIPT_DIR))

import blocking_adapter  # noqa: E402
import blocking_generator  # noqa: E402
import blocking_mutation  # noqa: E402
import blocking_reducer  # noqa: E402
import blocking_scenario  # noqa: E402
import fingerprint  # noqa: E402
import fuzz  # noqa: E402
import guest_result  # noqa: E402
import models  # noqa: E402
from linux_oracle.failure import load_failure, save_failure  # noqa: E402
from linux_oracle.persistence import (  # noqa: E402
    CampaignStore,
    PersistentStateError,
)


class PipeBlockingCodecTests(unittest.TestCase):
    def test_codec_round_trip_covers_controlled_worker_operations(self):
        encoded = (
            "version 0x5\n"
            "scenario arbitrary\n"
            "pipe2 0 1 0\n"
            "start-read 1 0 4\n"
            "assert-pending 1\n"
            "write 1 4 65\n"
            "join 1\n"
        )

        document = blocking_scenario.parse_document(encoded)
        canonical = blocking_scenario.serialize_document(document)

        self.assertEqual(blocking_scenario.parse_document(canonical), document)
        self.assertNotIn("0x", canonical)
        self.assertIn("start-read 1 0 4", canonical)
        self.assertIn("assert-pending 1", canonical)
        self.assertIn("join 1", canonical)
        state = blocking_scenario.analyze_scenario(document.scenarios[0])
        self.assertEqual(state.pipe(0).queued_bytes, 0)

    def test_codec_rejects_invalid_actor_lifecycles_and_blocking_proofs(self):
        invalid_documents = {
            "wrong-actor": (
                "version 5\nscenario x\npipe2 0 1 0\nstart-read 2 0 1\n"
            ),
            "nonblocking-start": (
                "version 5\nscenario x\npipe2 0 1 2048\nstart-read 1 0 1\n"
            ),
            "read-cannot-block": (
                "version 5\nscenario x\npipe2 0 1 0\nwrite 1 1 1\n"
                "start-read 1 0 1\n"
            ),
            "write-cannot-block": (
                "version 5\nscenario x\npipe2 0 1 0\nstart-write 1 1 1 1\n"
            ),
            "missing-pending": (
                "version 5\nscenario x\npipe2 0 1 0\nstart-read 1 0 1\n"
                "write 1 1 1\njoin 1\n"
            ),
            "different-pipe": (
                "version 5\nscenario x\npipe2 0 1 0\npipe2 2 3 0\n"
                "start-read 1 0 1\nassert-pending 1\nwrite 3 1 1\njoin 1\n"
            ),
            "uncontrolled-dup": (
                "version 5\nscenario x\npipe2 0 1 0\nstart-read 1 0 1\n"
                "assert-pending 1\ndup 1 2\n"
            ),
            "non-final-writer-close": (
                "version 5\nscenario x\npipe2 0 1 0\ndup 1 2\n"
                "start-read 1 0 1\nassert-pending 1\nclose 1\njoin 1\n"
            ),
            "join-before-completable": (
                "version 5\nscenario x\npipe2 0 1 0\nstart-read 1 0 1\n"
                "assert-pending 1\nwrite 1 0 0\njoin 1\n"
            ),
            "partial-slot-release": (
                "version 5\nscenario x\npipe2 0 1 0\nset-size 1 4096\n"
                "write 1 4096 1\nstart-write 1 1 1 2\nassert-pending 1\n"
                "read 0 1\njoin 1\n"
            ),
            "unsupported-vector-io": (
                "version 5\nscenario x\npipe2 0 1 2048\nreadv 0 0 0 0\n"
            ),
            "unfinished-worker": (
                "version 5\nscenario x\npipe2 0 1 0\nstart-read 1 0 1\n"
                "assert-pending 1\n"
            ),
        }
        for label, encoded in invalid_documents.items():
            with self.subTest(label=label), self.assertRaises(
                blocking_scenario.ScenarioCodecError
            ):
                blocking_scenario.parse_document(encoded)

    def test_shared_lifecycle_errors_keep_pipe_categories_lines_and_text(self):
        cases = {
            "repeat": (
                "version 5\nscenario x\npipe2 0 1 0\n"
                "start-read 1 0 1\nstart-read 1 0 1\n",
                "line 3: resource-conflict: only one worker call may be active",
            ),
            "pending-without-worker": (
                "version 5\nscenario x\npipe2 0 1 0\nassert-pending 1\n",
                "line 2: resource-conflict: assert-pending requires an active worker",
            ),
            "trigger-before-pending": (
                "version 5\nscenario x\npipe2 0 1 0\n"
                "start-read 1 0 1\nwrite 1 1 1\n",
                "line 3: resource-conflict: worker pending state was not confirmed",
            ),
            "trigger-after-completable": (
                "version 5\nscenario x\npipe2 0 1 0\nstart-read 1 0 1\n"
                "assert-pending 1\nwrite 1 1 1\nwrite 1 1 1\n",
                "line 5: resource-conflict: join must immediately follow a completing trigger",
            ),
            "pending-after-completable": (
                "version 5\nscenario x\npipe2 0 1 0\nstart-read 1 0 1\n"
                "assert-pending 1\nwrite 1 1 1\nassert-pending 1\n",
                "line 5: blocking-io: worker may complete before assert-pending",
            ),
            "join-without-worker": (
                "version 5\nscenario x\npipe2 0 1 0\njoin 1\n",
                "line 2: resource-conflict: join requires an active worker",
            ),
            "join-before-completable": (
                "version 5\nscenario x\npipe2 0 1 0\nstart-read 1 0 1\n"
                "assert-pending 1\njoin 1\n",
                "line 4: blocking-io: worker is not proven completable before join",
            ),
            "unfinished": (
                "version 5\nscenario x\npipe2 0 1 0\n"
                "start-read 1 0 1\nassert-pending 1\n",
                "line 4: resource-conflict: scenario ends with an unfinished worker",
            ),
        }
        for label, (encoded, expected) in cases.items():
            with self.subTest(label=label), self.assertRaises(
                blocking_scenario.ScenarioCodecError
            ) as raised:
                blocking_scenario.parse_document(encoded)
            self.assertEqual(str(raised.exception), expected)

    def test_alias_zero_write_and_shared_nonblocking_complete_read(self):
        document = blocking_scenario.parse_document(
            "version 5\nscenario x\n"
            "pipe2 0 1 2048\n"
            "dup 0 2\n"
            "dup 1 3\n"
            "set-status-flags 2 0\n"
            "set-status-flags 3 0\n"
            "start-read 1 0 1\n"
            "assert-pending 1\n"
            "write 3 0 0\n"
            "assert-pending 1\n"
            "write 3 1 65\n"
            "join 1\n"
        )

        state = blocking_scenario.analyze_scenario(document.scenarios[0])

        self.assertEqual(
            state.descriptor(0).description_id,
            state.descriptor(2).description_id,
        )
        self.assertEqual(
            state.descriptor(1).description_id,
            state.descriptor(3).description_id,
        )
        self.assertFalse(state.description(0).nonblocking)
        self.assertFalse(state.description(1).nonblocking)
        self.assertEqual(state.pipe(0).queued_bytes, 0)

    def test_eof_and_phased_slot_release_have_proven_final_states(self):
        eof = blocking_scenario.parse_document(
            "version 5\nscenario eof\npipe2 0 1 0\n"
            "start-read 1 0 8\nassert-pending 1\nclose 1\njoin 1\n"
        )
        phased = blocking_scenario.parse_document(
            "version 5\nscenario phased\npipe2 0 1 0\nset-size 1 4096\n"
            "write 1 4096 17\nstart-write 1 1 16 34\nassert-pending 1\n"
            "read 0 1\nassert-pending 1\nread 0 4095\njoin 1\n"
        )

        eof_state = blocking_scenario.analyze_scenario(eof.scenarios[0])
        phased_state = blocking_scenario.analyze_scenario(phased.scenarios[0])

        self.assertEqual(eof_state.pipe(0).writers, 0)
        self.assertEqual(eof_state.pipe(0).queued_bytes, 0)
        self.assertEqual(phased_state.pipe(0).queued_bytes, 16)
        self.assertEqual(len(phased_state.pipe(0).buffers), 1)

    def test_checked_corpora_are_canonical_and_cover_all_six_stories(self):
        documents = []
        for path in CORPUS_PATHS:
            encoded = path.read_bytes()
            document = blocking_scenario.parse_document(encoded)
            blocking_scenario.validate_entry_limits(document)
            self.assertEqual(
                blocking_scenario.serialize_document(document).encode(), encoded
            )
            documents.append(document)

        scenarios = tuple(
            scenario for document in documents for scenario in document.scenarios
        )
        operations = tuple(
            operation for scenario in scenarios for operation in scenario.operations
        )
        self.assertEqual(len(scenarios), 6)
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
            len(scenarios),
        )


class PipeBlockingCampaignTests(unittest.TestCase):
    def test_model_selection_preserves_simple_default_and_adapter_identity(self):
        self.assertIs(models.spec_for_model("simple-single"), models.DEFAULT_SPEC)
        self.assertEqual(models.DEFAULT_SPEC.adapter_id, "pipe-v4")
        self.assertEqual(models.spec_for_model("blocking").adapter_id, "pipe-blocking-v1")
        self.assertIs(
            models.spec_for_adapter_id("pipe-blocking-v1"), blocking_adapter.SPEC
        )
        with self.assertRaises(ValueError):
            models.spec_for_model("blocking-v2")
        with self.assertRaises(ValueError):
            models.spec_for_adapter_id("unknown")

    def test_fuzz_cli_selects_blocking_and_keeps_simple_default(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            arguments = [
                "--workspace",
                temporary_directory,
                "--batches",
                "1",
                "--batch-size",
                "1",
            ]
            with mock.patch.object(fuzz, "_recover_legacy", return_value=False), mock.patch.object(
                fuzz, "run_campaign", return_value=0
            ) as run:
                self.assertEqual(fuzz.main(arguments), 0)
            self.assertEqual(run.call_args.args[0].adapter_id, "pipe-v4")

        with mock.patch.object(fuzz, "run_campaign", return_value=0) as run:
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
        self.assertEqual(run.call_args.args[0].adapter_id, "pipe-blocking-v1")

    def test_blocking_adapter_has_isolated_campaign_and_wait_coverage(self):
        spec = blocking_adapter.SPEC
        self.assertEqual(spec.campaign.root, Path("coverage/pipe-blocking-oracle-fuzz"))
        self.assertNotEqual(spec.campaign.root, models.DEFAULT_SPEC.campaign.root)
        self.assertEqual(spec.coverage.target_set_id, "pipe-blocking-v1")
        self.assertIn(
            "os/arceos/modules/axtask/src/future/poll.rs", spec.coverage.source_paths
        )
        self.assertIn("components/axpoll/src/lib.rs", spec.coverage.source_paths)
        self.assertTrue(
            (WORKSPACE_ROOT / "os/arceos/modules/axtask/src/future/poll.rs").is_file()
        )
        self.assertTrue((WORKSPACE_ROOT / "components/axpoll/src/lib.rs").is_file())

    def test_generation_mutation_and_reduction_are_canonical_and_deterministic(self):
        first = [blocking_generator.canonicalize_seed(seed) for seed in range(12)]
        second = [blocking_generator.canonicalize_seed(seed) for seed in range(12)]
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
            self.assertLess(candidate.complexity, blocking_reducer.complexity_key(origin))

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
                    Path("oracle"), Path("pipe.ops"), trace
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
                    Path("oracle"), Path("pipe.ops"), trace
                )
            self.assertFalse(result.passed)
            self.assertIn("not byte-stable", result.log)

    def test_persistence_and_failure_artifacts_fail_closed_across_models(self):
        simple = models.spec_for_model("simple-single")
        spec = blocking_adapter.SPEC
        generated = blocking_generator.canonicalize_seed(4)
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = CampaignStore(spec, workspace)
            entry = store.save_entry(generated.encoded, {"region:1:1"})
            metadata_path = entry.path / "metadata.json"
            metadata = json.loads(metadata_path.read_text())
            self.assertEqual(metadata["adapter_id"], "pipe-blocking-v1")
            self.assertNotEqual(simple.campaign.root, spec.campaign.root)

            metadata["adapter_id"] = simple.adapter_id
            metadata_path.write_text(json.dumps(metadata))
            with self.assertRaises(PersistentStateError):
                store.load_entries()

            scenario_path = workspace / "pipe.ops"
            trace_path = workspace / "linux.trace"
            host_path = workspace / "pipe-linux-oracle"
            starry_path = workspace / "starryos"
            scenario_path.write_bytes(generated.encoded)
            trace_path.write_bytes(b"blocking trace")
            host_path.write_bytes(b"host elf")
            starry_path.write_bytes(b"starry elf")
            saved = save_failure(
                spec,
                workspace / "failure",
                scenario_path=scenario_path,
                trace_path=trace_path,
                host_elf_path=host_path,
                starry_elf_path=starry_path,
                guest_log="schedule-timeout",
                profraw_paths=(),
                result_category="schedule-timeout",
                mismatch=None,
            )
            self.assertIs(models.spec_for_common_failure(saved.path), spec)
            self.assertEqual(load_failure(spec, saved.path).metadata["adapter_id"], spec.adapter_id)

            for target in ("pipe.ops", "linux.trace", "pipe-linux-oracle", "starryos"):
                with self.subTest(target=target):
                    original = (saved.path / target).read_bytes()
                    (saved.path / target).write_bytes(b"tampered")
                    with self.assertRaises(PersistentStateError):
                        load_failure(spec, saved.path)
                    (saved.path / target).write_bytes(original)

            failure_metadata_path = saved.path / "metadata.json"
            failure_metadata = json.loads(failure_metadata_path.read_text())
            failure_metadata["adapter_id"] = "unknown-pipe-model"
            failure_metadata_path.write_text(json.dumps(failure_metadata))
            with self.assertRaises(PersistentStateError):
                models.spec_for_common_failure(saved.path)

    def test_result_categories_and_blocking_fingerprint_are_stable(self):
        schedule = guest_result.classify_guest_execution(
            "STARRY_PIPE_LINUX_ORACLE_SCHEDULE_TIMEOUT: line=5", 1
        )
        harness = guest_result.classify_guest_execution(
            "STARRY_PIPE_LINUX_ORACLE_HARNESS_ERROR: line=5", 1
        )
        self.assertIs(
            schedule.category, guest_result.GuestResultCategory.SCHEDULE_TIMEOUT
        )
        self.assertIs(harness.category, guest_result.GuestResultCategory.HARNESS_ERROR)

        log = (
            "STARRY_PIPE_LINUX_ORACLE_FAILED: host=linux/x86_64 line=5 "
            'scenario=0 operation=3 text="assert-pending 1" '
            "difference_mask=0x00000008 "
            "expected={kind=23,result=0,errno=0,value=0,data_len=0} "
            "actual={kind=23,result=1,errno=0,value=0,data_len=0}\n"
        )
        difference = guest_result.parse_operation_difference(log)
        self.assertIsNotNone(difference)
        origin = blocking_reducer.OperationOrigin(0, 3)
        first = fingerprint.MismatchFingerprint.from_difference(difference, origin)
        second = fingerprint.MismatchFingerprint.from_difference(difference, origin)
        self.assertEqual(first, second)
        self.assertEqual(first.operation_kind, "assert-pending")


class PipeBlockingHarnessTests(unittest.TestCase):
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
            ["cmake", "--build", str(cls.build), "--target", "pipe-linux-oracle"],
            check=True,
            capture_output=True,
            text=True,
        )
        cls.oracle = cls.build / "pipe-linux-oracle"

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def test_checked_corpora_record_identically_three_times_and_compare(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for corpus_index, corpus in enumerate(CORPUS_PATHS):
                traces = []
                for record_index in range(3):
                    trace = root / f"trace-{corpus_index}-{record_index}"
                    result = subprocess.run(
                        [str(self.oracle), "--record", str(corpus), str(trace)],
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    traces.append(trace.read_bytes())
                self.assertEqual(traces[0], traces[1])
                self.assertEqual(traces[1], traces[2])
                self.assertEqual(struct.unpack_from("=I", traces[0], 8)[0], 5)
                compared = subprocess.run(
                    [str(self.oracle), "--compare", str(corpus), str(root / f"trace-{corpus_index}-0")],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(compared.returncode, 0, compared.stderr)
                self.assertIn("STARRY_PIPE_LINUX_ORACLE_PASSED", compared.stdout)

    def test_v4_trace_identity_is_preserved_and_v5_rejects_v4_only_operations(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            simple_trace = root / "simple.trace"
            recorded = subprocess.run(
                [str(self.oracle), "--record", str(SIMPLE_CORPUS_PATH), str(simple_trace)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(recorded.returncode, 0, recorded.stderr)
            self.assertEqual(struct.unpack_from("=I", simple_trace.read_bytes(), 8)[0], 4)

            malformed = root / "malformed.ops"
            malformed.write_text(
                "version 5\nscenario x\npipe2 0 1 2048\npoll 0 1\n"
            )
            rejected = subprocess.run(
                [str(self.oracle), "--record", str(malformed), str(root / "bad.trace")],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("invalid operation", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
