import ctypes
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/pipe-oracle"
CASE_DIR = WORKSPACE_ROOT / "test-suit/starryos/qemu/pipe-linux-oracle"
CORPUS_PATH = CASE_DIR / "c/corpus/pipe-blocking-poll.ops"
sys.path.insert(0, str(SCRIPT_DIR))

import blocking_adapter  # noqa: E402
import blocking_scenario  # noqa: E402
import fingerprint  # noqa: E402
import fuzz  # noqa: E402
import guest_result  # noqa: E402
import models  # noqa: E402
import poll_adapter  # noqa: E402
import poll_generator  # noqa: E402
import poll_mutation  # noqa: E402
import poll_reducer  # noqa: E402
import poll_scenario  # noqa: E402
import scenario as simple_scenario  # noqa: E402
from linux_oracle.failure import load_failure, save_failure  # noqa: E402
from linux_oracle.persistence import CampaignStore, PersistentStateError  # noqa: E402


class PipeBlockingPollCodecTests(unittest.TestCase):
    def test_v6_round_trip_and_canonical_digest(self):
        encoded = (
            "version 0x6\n"
            "scenario arbitrary\n"
            "pipe2 0 1 2048\n"
            "start-poll 1 0 1\n"
            "assert-pending 1\n"
            "write 1 2 65\n"
            "join 1\n"
        )

        document = poll_scenario.parse_document(encoded)
        canonical = poll_scenario.serialize_document(document)

        self.assertEqual(poll_scenario.parse_document(canonical), document)
        self.assertNotIn("0x", canonical)
        self.assertIn("start-poll 1 0 1", canonical)
        self.assertEqual(
            poll_scenario.canonical_digest(document),
            hashlib.sha256(canonical.encode()).hexdigest(),
        )
        state = poll_scenario.analyze_scenario(document.scenarios[0])
        self.assertEqual(state.pipe(0).queued_bytes, 2)
        self.assertTrue(state.description(0).nonblocking)

    def test_v4_v5_v6_codecs_reject_each_other(self):
        corpora = {
            4: "version 4\nscenario x\npipe2 0 1 2048\n",
            5: (
                "version 5\nscenario x\npipe2 0 1 0\nstart-read 1 0 1\n"
                "assert-pending 1\nwrite 1 1 1\njoin 1\n"
            ),
            6: (
                "version 6\nscenario x\npipe2 0 1 0\nstart-poll 1 0 1\n"
                "assert-pending 1\nwrite 1 1 1\njoin 1\n"
            ),
        }
        parsers = {
            4: simple_scenario.parse_document,
            5: blocking_scenario.parse_document,
            6: poll_scenario.parse_document,
        }
        for parser_version, parser in parsers.items():
            for corpus_version, encoded in corpora.items():
                with self.subTest(
                    parser_version=parser_version, corpus_version=corpus_version
                ):
                    if parser_version == corpus_version:
                        parser(encoded)
                    else:
                        with self.assertRaises(poll_scenario.ScenarioCodecError):
                            parser(encoded)

    def test_rejects_invalid_actor_slot_mask_endpoint_and_initial_readiness(self):
        invalid_documents = {
            "actor": (
                "version 6\nscenario x\npipe2 0 1 0\nstart-poll 2 0 1\n"
            ),
            "slot": "version 6\nscenario x\nstart-poll 1 16 1\n",
            "events-zero": (
                "version 6\nscenario x\npipe2 0 1 0\nstart-poll 1 0 0\n"
            ),
            "events-mixed": (
                "version 6\nscenario x\npipe2 0 1 0\nstart-poll 1 0 5\n"
            ),
            "pollin-writer": (
                "version 6\nscenario x\npipe2 0 1 0\nstart-poll 1 1 1\n"
            ),
            "pollout-reader": (
                "version 6\nscenario x\npipe2 0 1 0\nstart-poll 1 0 4\n"
            ),
            "pollin-ready": (
                "version 6\nscenario x\npipe2 0 1 0\nwrite 1 1 1\n"
                "start-poll 1 0 1\n"
            ),
            "pollout-ready": (
                "version 6\nscenario x\npipe2 0 1 0\nstart-poll 1 1 4\n"
            ),
        }
        for label, encoded in invalid_documents.items():
            with self.subTest(label=label), self.assertRaises(
                poll_scenario.ScenarioCodecError
            ):
                poll_scenario.parse_document(encoded)

    def test_nonblocking_alias_zero_write_and_pollin_wakeup(self):
        document = poll_scenario.parse_document(
            "version 6\nscenario x\n"
            "pipe2 0 1 2048\n"
            "dup 0 2\n"
            "dup 1 3\n"
            "start-poll 1 2 1\n"
            "assert-pending 1\n"
            "write 3 0 0\n"
            "assert-pending 1\n"
            "write 3 3 65\n"
            "join 1\n"
        )

        state = poll_scenario.analyze_scenario(document.scenarios[0])

        self.assertEqual(state.pipe(0).queued_bytes, 3)
        self.assertTrue(state.description(0).nonblocking)
        self.assertEqual(
            state.descriptor(0).description_id,
            state.descriptor(2).description_id,
        )

    def test_pollhup_and_phased_pollout_have_proven_final_states(self):
        document = poll_scenario.parse_document(
            "version 6\nscenario hup\n"
            "pipe2 0 1 0\n"
            "start-poll 1 0 1\n"
            "assert-pending 1\n"
            "close 1\n"
            "join 1\n"
            "scenario phased\n"
            "pipe2 0 1 0\n"
            "set-size 1 4096\n"
            "write 1 4096 17\n"
            "start-poll 1 1 4\n"
            "assert-pending 1\n"
            "read 0 1\n"
            "assert-pending 1\n"
            "read 0 4095\n"
            "join 1\n"
        )

        hup = poll_scenario.analyze_scenario(document.scenarios[0])
        phased = poll_scenario.analyze_scenario(document.scenarios[1])

        self.assertEqual(hup.pipe(0).writers, 0)
        self.assertEqual(hup.pipe(0).queued_bytes, 0)
        self.assertEqual(phased.pipe(0).queued_bytes, 0)
        self.assertEqual(len(phased.pipe(0).buffers), 0)

    def test_controller_triggers_target_only_the_same_pipe(self):
        invalid_documents = {
            "different-pipe": (
                "version 6\nscenario x\npipe2 0 1 0\npipe2 2 3 0\n"
                "start-poll 1 0 1\nassert-pending 1\nwrite 3 1 1\n"
            ),
            "dup-race": (
                "version 6\nscenario x\npipe2 0 1 0\nstart-poll 1 0 1\n"
                "assert-pending 1\ndup 1 2\n"
            ),
            "non-final-writer-close": (
                "version 6\nscenario x\npipe2 0 1 0\ndup 1 2\n"
                "start-poll 1 0 1\nassert-pending 1\nclose 1\n"
            ),
            "last-reader-close": (
                "version 6\nscenario x\npipe2 0 1 0\nset-size 1 4096\n"
                "write 1 4096 1\nstart-poll 1 1 4\n"
                "assert-pending 1\nclose 0\n"
            ),
            "join-before-ready": (
                "version 6\nscenario x\npipe2 0 1 0\nstart-poll 1 0 1\n"
                "assert-pending 1\nwrite 1 0 0\njoin 1\n"
            ),
            "partial-slot-release": (
                "version 6\nscenario x\npipe2 0 1 0\nset-size 1 4096\n"
                "write 1 4096 1\nstart-poll 1 1 4\nassert-pending 1\n"
                "read 0 1\njoin 1\n"
            ),
            "unfinished": (
                "version 6\nscenario x\npipe2 0 1 0\nstart-poll 1 0 1\n"
                "assert-pending 1\n"
            ),
        }
        for label, encoded in invalid_documents.items():
            with self.subTest(label=label), self.assertRaises(
                poll_scenario.ScenarioCodecError
            ):
                poll_scenario.parse_document(encoded)

    def test_shared_lifecycle_errors_keep_pipe_categories_lines_and_text(self):
        cases = {
            "repeat": (
                "version 6\nscenario x\npipe2 0 1 0\n"
                "start-poll 1 0 1\nstart-poll 1 0 1\n",
                "line 3: resource-conflict: only one worker call may be active",
            ),
            "pending-without-worker": (
                "version 6\nscenario x\npipe2 0 1 0\nassert-pending 1\n",
                "line 2: resource-conflict: assert-pending requires an active worker",
            ),
            "trigger-before-pending": (
                "version 6\nscenario x\npipe2 0 1 0\n"
                "start-poll 1 0 1\nwrite 1 1 1\n",
                "line 3: resource-conflict: worker pending state was not confirmed",
            ),
            "trigger-after-ready": (
                "version 6\nscenario x\npipe2 0 1 0\nstart-poll 1 0 1\n"
                "assert-pending 1\nwrite 1 1 1\nwrite 1 1 1\n",
                "line 5: resource-conflict: join must immediately follow a completing trigger",
            ),
            "pending-after-ready": (
                "version 6\nscenario x\npipe2 0 1 0\nstart-poll 1 0 1\n"
                "assert-pending 1\nwrite 1 1 1\nassert-pending 1\n",
                "line 5: blocking-io: worker may complete before assert-pending",
            ),
            "join-before-ready": (
                "version 6\nscenario x\npipe2 0 1 0\nstart-poll 1 0 1\n"
                "assert-pending 1\njoin 1\n",
                "line 4: blocking-io: worker is not proven completable before join",
            ),
            "unfinished": (
                "version 6\nscenario x\npipe2 0 1 0\n"
                "start-poll 1 0 1\nassert-pending 1\n",
                "line 4: resource-conflict: scenario ends with an unfinished worker",
            ),
        }
        for label, (encoded, expected) in cases.items():
            with self.subTest(label=label), self.assertRaises(
                poll_scenario.ScenarioCodecError
            ) as raised:
                poll_scenario.parse_document(encoded)
            self.assertEqual(str(raised.exception), expected)

    def test_checked_corpus_is_canonical_and_covers_all_poll_stories(self):
        encoded = CORPUS_PATH.read_bytes()
        document = poll_scenario.parse_document(encoded)

        poll_scenario.validate_entry_limits(document)

        self.assertEqual(poll_scenario.serialize_document(document).encode(), encoded)
        self.assertEqual(
            poll_scenario.canonical_digest(document),
            "0b8bbd92dc1dbfbdc7234d0d78f2d53e987b7b1bec6bd5393bfaa1187fd5e10c",
        )
        operations = [
            operation
            for scenario in document.scenarios
            for operation in scenario.operations
        ]
        starts = [
            operation
            for operation in operations
            if isinstance(operation, poll_scenario.StartPoll)
        ]
        self.assertEqual(len(document.scenarios), 7)
        self.assertEqual({operation.events for operation in starts}, {1, 4})
        self.assertTrue(
            any(
                isinstance(operation, poll_scenario.Pipe2)
                and operation.flags & poll_scenario.O_NONBLOCK
                for operation in operations
            )
        )
        self.assertTrue(
            any(isinstance(operation, poll_scenario.Dup) for operation in operations)
        )
        self.assertTrue(
            any(
                isinstance(operation, poll_scenario.Write) and operation.length == 0
                for operation in operations
            )
        )
        self.assertTrue(
            any(isinstance(operation, poll_scenario.Close) for operation in operations)
        )


class PipeBlockingPollCampaignTests(unittest.TestCase):
    def test_model_selection_uses_v2_and_preserves_v1_replay(self):
        self.assertIs(models.spec_for_model("simple-single"), models.DEFAULT_SPEC)
        self.assertIs(models.spec_for_model("blocking"), poll_adapter.SPEC)
        self.assertIs(
            models.spec_for_adapter_id("pipe-blocking-v1"), blocking_adapter.SPEC
        )
        self.assertIs(
            models.spec_for_adapter_id("pipe-blocking-v2"), poll_adapter.SPEC
        )

    def test_fuzz_cli_routes_blocking_to_v2_and_keeps_simple_default(self):
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
        self.assertEqual(run.call_args.args[0].adapter_id, "pipe-blocking-v2")

    def test_v2_adapter_has_isolated_campaign_and_coverage(self):
        spec = poll_adapter.SPEC
        self.assertEqual(
            spec.campaign.root, Path("coverage/pipe-blocking-v2-oracle-fuzz")
        )
        self.assertEqual(spec.coverage.target_set_id, "pipe-blocking-v2")
        self.assertNotEqual(spec.campaign.root, blocking_adapter.SPEC.campaign.root)
        self.assertNotEqual(
            spec.coverage.target_set_id, blocking_adapter.SPEC.coverage.target_set_id
        )
        for source in spec.coverage.source_paths:
            self.assertTrue((WORKSPACE_ROOT / source).is_file(), source)

    def test_generation_mutation_and_reduction_are_deterministic_and_valid(self):
        first = [poll_generator.canonicalize_seed(seed) for seed in range(8)]
        second = [poll_generator.canonicalize_seed(seed) for seed in range(8)]
        self.assertEqual(
            [(item.digest, item.encoded) for item in first],
            [(item.digest, item.encoded) for item in second],
        )
        self.assertEqual(
            [item.digest for item in first],
            [
                "b1452e956862c71872b6a85d3d7e54cc14297acc47d4ebe372ee5d273b19525e",
                "3185de66c8f6bd958ae39be7669213ba64713006e8aea577a89cacbe4ea5e4a9",
                "c82274e803f571f053736de93c8036db5579c14834ff9cc114b69d563144ffa8",
                "a18e255e25b1dc4f989e04f1fb8167cdb4d73102ec2974e7e2b869b4551a40b8",
                "b0b6c8331a10da5b9fdc4811bbc6b96fa65dd9d25eb9bd267df5970b48a17dd5",
                "5469459f04bc9aea1f1bd7852764fbcb52c3bf0e9f748557a36f80619ca6c4e2",
                "9ba1566d2428a9b68691623bb332ca4f9fb686946437862e363ecbd3f6ecaa9d",
                "c8f4c725843c220f3194a90bcfcb2cea4640baaeb92a0e7c64b1e4ea9361b4e2",
            ],
        )
        observed_events = {
            operation.events
            for generated in first
            for scenario in generated.document.scenarios
            for operation in scenario.operations
            if isinstance(operation, poll_scenario.StartPoll)
        }
        self.assertEqual(observed_events, {1, 4})

        parent = first[0].document
        donor = first[1].document
        parent_digest = poll_scenario.canonical_digest(parent)
        for index, kind in enumerate(poll_mutation.MUTATION_KINDS):
            with self.subTest(kind=kind):
                candidate = poll_mutation.mutate_document(
                    poll_generator.CampaignRng(100 + index),
                    parent,
                    donor,
                    requested_kind=kind,
                )
                self.assertIs(
                    candidate.classification,
                    poll_mutation.CandidateClassification.EXECUTABLE,
                )
                self.assertNotEqual(candidate.digest, parent_digest)
                poll_scenario.validate_entry_limits(candidate.document)

        origin = poll_reducer.with_origins(first[2].document)
        candidates = list(poll_reducer.reduction_candidates(origin))
        self.assertTrue(candidates)
        for candidate in candidates:
            poll_scenario.validate_entry_limits(candidate.document.plain())
            self.assertLess(candidate.complexity, poll_reducer.complexity_key(origin))
            for scenario in candidate.document.plain().scenarios:
                self.assertEqual(
                    sum(
                        isinstance(operation, poll_scenario.StartPoll)
                        for operation in scenario.operations
                    ),
                    1,
                )
                self.assertTrue(
                    any(
                        isinstance(operation, poll_scenario.AssertPending)
                        for operation in scenario.operations
                    )
                )
                self.assertTrue(
                    any(
                        isinstance(operation, poll_scenario.Join)
                        for operation in scenario.operations
                    )
                )

        required = poll_reducer.OperationOrigin(1, 3)
        required_candidates = list(
            poll_reducer.reduction_candidates(origin, required_origin=required)
        )
        self.assertTrue(required_candidates)
        for candidate in required_candidates:
            self.assertTrue(poll_reducer.contains_origin(candidate.document, required))
            self.assertIsNotNone(
                poll_reducer.locate_origin(candidate.document, required)
            )

    def test_v2_campaign_and_failure_artifacts_reject_v1_bytes(self):
        spec = poll_adapter.SPEC
        generated = poll_generator.canonicalize_seed(3)
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            store = CampaignStore(spec, root)
            old_bytes = (CASE_DIR / "c/corpus/pipe-blocking-read.ops").read_bytes()
            with self.assertRaises(poll_scenario.ScenarioCodecError):
                store.save_entry(old_bytes, {"region:1:1"})

            scenario_path = root / "pipe.ops"
            trace_path = root / "linux.trace"
            host_path = root / "pipe-linux-oracle"
            starry_path = root / "starryos"
            scenario_path.write_bytes(generated.encoded)
            trace_path.write_bytes(b"poll trace")
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
            self.assertIs(models.spec_for_common_failure(saved.path), spec)
            self.assertEqual(
                load_failure(spec, saved.path).metadata["adapter_id"], spec.adapter_id
            )
            with self.assertRaises(PersistentStateError):
                load_failure(blocking_adapter.SPEC, saved.path)

            metadata_path = saved.path / "metadata.json"
            metadata = json.loads(metadata_path.read_text())
            metadata["adapter_id"] = "pipe-blocking-v1"
            metadata_path.write_text(json.dumps(metadata))
            self.assertIs(
                models.spec_for_common_failure(saved.path), blocking_adapter.SPEC
            )
            with self.assertRaises(PersistentStateError):
                load_failure(blocking_adapter.SPEC, saved.path)

    def test_v2_stable_recorder_requires_three_identical_traces(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            trace = root / "linux.trace"

            def stable_record(_elf, _ops, destination):
                destination.write_bytes(b"stable poll trace")
                return poll_adapter.HostRecordResult(True, False, "recorded")

            with mock.patch.object(
                poll_adapter, "record_host_once", side_effect=stable_record
            ) as recorder:
                result = poll_adapter.record_host_stable(
                    Path("oracle"), Path("pipe.ops"), trace
                )
            self.assertTrue(result.passed)
            self.assertEqual(recorder.call_count, 3)
            self.assertEqual(trace.read_bytes(), b"stable poll trace")

            calls = 0

            def unstable_record(_elf, _ops, destination):
                nonlocal calls
                destination.write_bytes(f"poll trace {calls}".encode())
                calls += 1
                return poll_adapter.HostRecordResult(True, False, "recorded")

            with mock.patch.object(
                poll_adapter, "record_host_once", side_effect=unstable_record
            ):
                result = poll_adapter.record_host_stable(
                    Path("oracle"), Path("pipe.ops"), trace
                )
            self.assertFalse(result.passed)
            self.assertIn("not byte-stable", result.log)

    def test_start_poll_fingerprint_appends_kind_without_changing_join(self):
        log = (
            "STARRY_PIPE_LINUX_ORACLE_FAILED: host=linux/x86_64 line=4 "
            'scenario=0 operation=1 text="start-poll 1 0 1" '
            "difference_mask=0x00000008 "
            "expected={kind=25,result=0,errno=0,value=1,data_len=0} "
            "actual={kind=25,result=1,errno=0,value=1,data_len=0}\n"
        )
        difference = guest_result.parse_operation_difference(log)
        self.assertIsNotNone(difference)
        result = fingerprint.MismatchFingerprint.from_difference(
            difference, poll_reducer.OperationOrigin(0, 1)
        )
        self.assertEqual(result.operation_kind, "start-poll")
        self.assertEqual(fingerprint._OPERATION_KINDS["join"], 24)
        self.assertEqual(fingerprint._OPERATION_KINDS["start-poll"], 25)

    def test_early_completion_timeout_and_helper_errors_are_typed(self):
        early_completion = (
            "STARRY_PIPE_LINUX_ORACLE_FAILED: host=linux/x86_64 line=5 "
            'scenario=0 operation=2 text="assert-pending 1" '
            "difference_mask=0x00000008 "
            "expected={kind=23,result=0,errno=0,value=0,data_len=0} "
            "actual={kind=23,result=1,errno=0,value=0,data_len=0}\n"
        )
        classified = guest_result.classify_guest_execution(early_completion, 1)
        self.assertIs(
            classified.category,
            guest_result.GuestResultCategory.SEMANTIC_MISMATCH,
        )
        schedule_timeout = guest_result.classify_guest_execution(
            "STARRY_PIPE_LINUX_ORACLE_SCHEDULE_TIMEOUT: join 1", 1
        )
        self.assertIs(
            schedule_timeout.category,
            guest_result.GuestResultCategory.SCHEDULE_TIMEOUT,
        )
        helper_error = guest_result.classify_guest_execution(
            "STARRY_PIPE_LINUX_ORACLE_HARNESS_ERROR: pthread", 1
        )
        self.assertIs(
            helper_error.category,
            guest_result.GuestResultCategory.HARNESS_ERROR,
        )


class PipeBlockingPollHarnessTests(unittest.TestCase):
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

    def test_checked_pollin_pollout_and_pollhup_record_stably_and_compare(self):
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
            self.assertEqual(traces[0][:8], b"PIPEORC1")
            self.assertEqual(ctypes.c_uint32.from_buffer_copy(traces[0], 8).value, 6)
            self._assert_join_records_capture_poll_result(traces[0])
            compared = subprocess.run(
                [str(self.oracle), "--compare", str(CORPUS_PATH), str(root / "trace-0")],
                capture_output=True,
                text=True,
            )
        self.assertEqual(compared.returncode, 0, compared.stderr)
        self.assertIn("STARRY_PIPE_LINUX_ORACLE_PASSED", compared.stdout)

    def test_initially_ready_poll_is_rejected_as_early_completion(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            corpus = root / "pipe.ops"
            corpus.write_text(
                "version 6\nscenario x\npipe2 0 1 0\nwrite 1 1 1\n"
                "start-poll 1 0 1\nassert-pending 1\n"
            )
            result = subprocess.run(
                [str(self.oracle), "--record", str(corpus), str(root / "trace")],
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("worker completed before pending guard", result.stderr)

    def test_v6_parser_and_trace_reject_v5_identity(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            corpus = root / "pipe.ops"
            corpus.write_text(
                "version 6\nscenario x\npipe2 0 1 0\nstart-read 1 0 1\n"
            )
            rejected = subprocess.run(
                [str(self.oracle), "--record", str(corpus), str(root / "bad.trace")],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("invalid operation", rejected.stderr)

            trace = root / "linux.trace"
            recorded = subprocess.run(
                [str(self.oracle), "--record", str(CORPUS_PATH), str(trace)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(recorded.returncode, 0, recorded.stderr)
            encoded = bytearray(trace.read_bytes())
            encoded[8:12] = (5).to_bytes(4, sys.byteorder)
            trace.write_bytes(encoded)
            compared = subprocess.run(
                [str(self.oracle), "--compare", str(CORPUS_PATH), str(trace)],
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(compared.returncode, 0)
        self.assertIn("version-6 corpus requires a version-6 trace", compared.stderr)

    def _assert_join_records_capture_poll_result(self, trace: bytes):
        class TraceHeader(ctypes.Structure):
            _fields_ = [
                ("magic", ctypes.c_ubyte * 8),
                ("version", ctypes.c_uint32),
                ("record_count", ctypes.c_uint32),
                ("corpus_digest", ctypes.c_uint64),
                ("page_size", ctypes.c_uint32),
                ("release", ctypes.c_char * 64),
                ("machine", ctypes.c_char * 32),
            ]

        class OperationResult(ctypes.Structure):
            _fields_ = [
                ("scenario_index", ctypes.c_uint32),
                ("operation_index", ctypes.c_uint32),
                ("kind", ctypes.c_uint32),
                ("data_len", ctypes.c_uint32),
                ("result", ctypes.c_int64),
                ("value", ctypes.c_int64),
                ("error", ctypes.c_int32),
                ("data", ctypes.c_ubyte * 8192),
            ]

        header = TraceHeader.from_buffer_copy(trace)
        offset = ctypes.sizeof(TraceHeader)
        records = []
        for _ in range(header.record_count):
            records.append(OperationResult.from_buffer_copy(trace, offset))
            offset += ctypes.sizeof(OperationResult)
        joins = [record for record in records if record.kind == 24]
        self.assertEqual(len(joins), 7)
        self.assertEqual([record.result for record in joins], [1] * 7)
        self.assertEqual([record.error for record in joins], [0] * 7)
        self.assertEqual([record.data_len for record in joins], [2] * 7)
        self.assertEqual(
            [record.data[0] | (record.data[1] << 8) for record in joins],
            [1, 1, 1, 16, 4, 4, 4],
        )


if __name__ == "__main__":
    unittest.main()
