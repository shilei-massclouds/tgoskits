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
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/eventfd-oracle"
CASE_DIR = WORKSPACE_ROOT / "test-suit/starryos/qemu/eventfd-linux-oracle"
CORPUS_PATH = CASE_DIR / "c/corpus/eventfd-blocking-poll.ops"
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
from linux_oracle.failure import load_failure, save_failure  # noqa: E402
from linux_oracle.persistence import CampaignStore, PersistentStateError  # noqa: E402


class EventFdBlockingPollCodecTests(unittest.TestCase):
    def test_v3_round_trip_and_canonical_digest(self):
        encoded = (
            "version 0x3\n"
            "scenario arbitrary\n"
            "eventfd2 0 0 2048\n"
            "start-poll 1 0 1\n"
            "assert-pending 1\n"
            "write 0 8 0 2\n"
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
        self.assertEqual(state.event(0).count, 2)

    def test_v1_v2_v3_codecs_reject_each_other(self):
        corpora = {
            1: "version 1\nscenario x\neventfd 0 0\n",
            2: (
                "version 2\nscenario x\neventfd 0 0\nstart-read 1 0\n"
                "assert-pending 1\nwrite 0 8 0 1\njoin 1\n"
            ),
            3: (
                "version 3\nscenario x\neventfd 0 0\nstart-poll 1 0 1\n"
                "assert-pending 1\nwrite 0 8 0 1\njoin 1\n"
            ),
        }
        parsers = {
            1: __import__("scenario").parse_document,
            2: blocking_scenario.parse_document,
            3: poll_scenario.parse_document,
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

    def test_rejects_invalid_actor_slot_event_mask_and_initial_readiness(self):
        invalid_documents = {
            "actor": (
                "version 3\nscenario x\neventfd 0 0\nstart-poll 2 0 1\n"
            ),
            "slot": "version 3\nscenario x\nstart-poll 1 16 1\n",
            "events-zero": (
                "version 3\nscenario x\neventfd 0 0\nstart-poll 1 0 0\n"
            ),
            "events-mixed": (
                "version 3\nscenario x\neventfd 0 0\nstart-poll 1 0 5\n"
            ),
            "pollin-ready": (
                "version 3\nscenario x\neventfd 0 1\nstart-poll 1 0 1\n"
            ),
            "pollout-ready": (
                "version 3\nscenario x\neventfd 0 0\nstart-poll 1 0 4\n"
            ),
        }
        for label, encoded in invalid_documents.items():
            with self.subTest(label=label), self.assertRaises(
                poll_scenario.ScenarioCodecError
            ):
                poll_scenario.parse_document(encoded)

    def test_nonblocking_pollin_alias_zero_write_and_wakeup(self):
        document = poll_scenario.parse_document(
            "version 3\nscenario x\n"
            "eventfd2 0 0 2048\n"
            "dup 0 1\n"
            "start-poll 1 1 1\n"
            "assert-pending 1\n"
            "write 0 8 0 0\n"
            "assert-pending 1\n"
            "write 0 8 0 3\n"
            "join 1\n"
        )

        state = poll_scenario.analyze_scenario(document.scenarios[0])

        self.assertEqual(state.event(0).count, 3)
        self.assertTrue(state.description(0).nonblocking)
        self.assertEqual(
            state.descriptor(0).description_id, state.descriptor(1).description_id
        )

    def test_controller_triggers_are_exact_and_target_the_same_eventfd(self):
        invalid_documents = {
            "different-event": (
                "version 3\nscenario x\neventfd 0 0\neventfd 1 0\n"
                "start-poll 1 0 1\nassert-pending 1\nwrite 1 8 0 1\n"
            ),
            "short-buffer": (
                "version 3\nscenario x\neventfd 0 0\nstart-poll 1 0 1\n"
                "assert-pending 1\nwrite 0 7 0 1\n"
            ),
            "invalid-pointer": (
                "version 3\nscenario x\neventfd 0 0\nstart-poll 1 0 1\n"
                "assert-pending 1\nwrite 0 8 1 1\n"
            ),
            "invalid-write-value": (
                "version 3\nscenario x\neventfd 0 0\nstart-poll 1 0 1\n"
                "assert-pending 1\nwrite 0 8 0 18446744073709551615\n"
            ),
            "close-race": (
                "version 3\nscenario x\neventfd 0 0\nstart-poll 1 0 1\n"
                "assert-pending 1\nclose 0\n"
            ),
        }
        for label, encoded in invalid_documents.items():
            with self.subTest(label=label), self.assertRaises(
                poll_scenario.ScenarioCodecError
            ):
                poll_scenario.parse_document(encoded)

    def test_pollout_ordinary_and_semaphore_reads_release_space(self):
        document = poll_scenario.parse_document(
            "version 3\nscenario ordinary\n"
            "eventfd2 0 4294967295 0\n"
            "write 0 8 0 18446744069414584319\n"
            "start-poll 1 0 4\n"
            "assert-pending 1\n"
            "read 0 8 0\n"
            "join 1\n"
            "scenario semaphore\n"
            "eventfd2 0 4294967295 2049\n"
            "write 0 8 0 18446744069414584319\n"
            "dup 0 1\n"
            "start-poll 1 1 4\n"
            "assert-pending 1\n"
            "read 0 8 0\n"
            "join 1\n"
        )

        ordinary = poll_scenario.analyze_scenario(document.scenarios[0])
        semaphore = poll_scenario.analyze_scenario(document.scenarios[1])

        self.assertEqual(ordinary.event(0).count, 0)
        self.assertEqual(semaphore.event(0).count, poll_scenario.MAX_COUNTER - 1)

    def test_shared_lifecycle_errors_keep_categories_and_text(self):
        cases = {
            "repeat": (
                "version 3\nscenario x\neventfd 0 0\n"
                "start-poll 1 0 1\nstart-poll 1 0 1\n",
                "actor-lifecycle: only one worker call may be active",
            ),
            "pending-without-worker": (
                "version 3\nscenario x\neventfd 0 0\nassert-pending 1\n",
                "actor-lifecycle: assert-pending requires an active worker",
            ),
            "trigger-before-pending": (
                "version 3\nscenario x\neventfd 0 0\n"
                "start-poll 1 0 1\nwrite 0 8 0 1\n",
                "actor-lifecycle: worker pending state was not confirmed",
            ),
            "trigger-after-ready": (
                "version 3\nscenario x\neventfd 0 0\nstart-poll 1 0 1\n"
                "assert-pending 1\nwrite 0 8 0 1\nwrite 0 8 0 1\n",
                "actor-lifecycle: join must immediately follow a completing trigger",
            ),
            "pending-after-ready": (
                "version 3\nscenario x\neventfd 0 0\nstart-poll 1 0 1\n"
                "assert-pending 1\nwrite 0 8 0 1\nassert-pending 1\n",
                "blocking-proof: worker may complete before assert-pending",
            ),
            "join-before-ready": (
                "version 3\nscenario x\neventfd 0 0\nstart-poll 1 0 1\n"
                "assert-pending 1\njoin 1\n",
                "blocking-proof: worker is not proven completable before join",
            ),
            "unfinished": (
                "version 3\nscenario x\neventfd 0 0\n"
                "start-poll 1 0 1\nassert-pending 1\n",
                "actor-lifecycle: scenario ends with an unfinished worker",
            ),
        }
        for label, (encoded, expected) in cases.items():
            with self.subTest(label=label), self.assertRaises(
                poll_scenario.ScenarioCodecError
            ) as raised:
                poll_scenario.parse_document(encoded)
            self.assertEqual(str(raised.exception), expected)

    def test_checked_corpus_is_canonical_and_covers_poll_stories(self):
        encoded = CORPUS_PATH.read_bytes()
        document = poll_scenario.parse_document(encoded)

        poll_scenario.validate_entry_limits(document)

        self.assertEqual(poll_scenario.serialize_document(document).encode(), encoded)
        self.assertEqual(
            hashlib.sha256(encoded).hexdigest(),
            "e501023e9e5156583819fbd10583079faf7a3c22e80c465d06d538674124d4c3",
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
        self.assertEqual({operation.events for operation in starts}, {1, 4})
        self.assertTrue(
            any(
                isinstance(operation, poll_scenario.EventFd2)
                and operation.flags & poll_scenario.EFD_SEMAPHORE
                for operation in operations
            )
        )
        self.assertTrue(
            any(
                isinstance(operation, poll_scenario.EventFd2)
                and operation.flags & poll_scenario.O_NONBLOCK
                for operation in operations
            )
        )
        self.assertTrue(
            any(isinstance(operation, poll_scenario.Dup) for operation in operations)
        )
        self.assertTrue(
            any(
                isinstance(operation, poll_scenario.Write) and operation.value == 0
                for operation in operations
            )
        )


class EventFdBlockingPollCampaignTests(unittest.TestCase):
    def test_model_selection_uses_v2_and_preserves_v1_replay(self):
        self.assertIs(models.spec_for_model("simple-single"), models.DEFAULT_SPEC)
        self.assertIs(models.spec_for_model("blocking"), poll_adapter.SPEC)
        self.assertIs(
            models.spec_for_adapter_id("eventfd-blocking-v1"), blocking_adapter.SPEC
        )
        self.assertIs(
            models.spec_for_adapter_id("eventfd-blocking-v2"), poll_adapter.SPEC
        )

    def test_fuzz_cli_routes_blocking_to_v2_and_keeps_simple_default(self):
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
            self.assertEqual(run.call_args.args[0].adapter_id, "eventfd-blocking-v2")

    def test_v2_adapter_has_isolated_campaign_and_coverage(self):
        spec = poll_adapter.SPEC
        self.assertEqual(
            spec.campaign.root, Path("coverage/eventfd-blocking-v2-oracle-fuzz")
        )
        self.assertEqual(spec.coverage.target_set_id, "eventfd-blocking-v2")
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
        observed_events = {
            operation.events
            for generated in first
            for scenario in generated.document.scenarios
            for operation in scenario.operations
            if isinstance(operation, poll_scenario.StartPoll)
        }
        self.assertEqual(observed_events, {1, 4})
        self.assertEqual(
            [(item.digest, len(item.encoded)) for item in first[:5]],
            [
                (
                    "86de0d7d857ca9e47662aacd52e2a74d20321a033e75724ff7d83396b850003d",
                    250,
                ),
                (
                    "62978e646a69d4da8d11a09d65974a10442ff997e900004c393877810aa34d65",
                    154,
                ),
                (
                    "b887d5116cf4d9dbfa481ab9edf2b1e40de850f157fef984d3c4e0439ce520c5",
                    245,
                ),
                (
                    "58b163939c7b654cff7cf192b41879fe1626939fbdbfc16ef5909bf1d8feef6b",
                    249,
                ),
                (
                    "316f3acff5a9abe21970d784f03e3b82f6877933853363b0f1800170cd2a22f9",
                    272,
                ),
            ],
        )

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
                starts = [
                    operation
                    for operation in scenario.operations
                    if isinstance(operation, poll_scenario.StartPoll)
                ]
                self.assertEqual(len(starts), 1)
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

    def test_v2_failure_dispatch_and_artifacts_are_isolated(self):
        spec = poll_adapter.SPEC
        generated = poll_generator.canonicalize_seed(3)
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            scenario_path = root / "eventfd.ops"
            trace_path = root / "linux.trace"
            host_path = root / "eventfd-linux-oracle"
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
            self.assertIs(models.spec_for_failure(saved.path), spec)
            self.assertEqual(
                load_failure(spec, saved.path).metadata["adapter_id"], spec.adapter_id
            )
            with self.assertRaises(PersistentStateError):
                load_failure(blocking_adapter.SPEC, saved.path)

            metadata_path = saved.path / "metadata.json"
            metadata = json.loads(metadata_path.read_text())
            metadata["adapter_id"] = "eventfd-blocking-v1"
            metadata_path.write_text(json.dumps(metadata))
            self.assertIs(models.spec_for_failure(saved.path), blocking_adapter.SPEC)
            with self.assertRaises(PersistentStateError):
                load_failure(blocking_adapter.SPEC, saved.path)

    def test_v2_campaign_rejects_v1_canonical_bytes(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = CampaignStore(poll_adapter.SPEC, workspace)
            encoded = blocking_scenario.serialize_document(
                blocking_scenario.parse_document(
                    "version 2\nscenario x\neventfd 0 0\nstart-read 1 0\n"
                    "assert-pending 1\nwrite 0 8 0 1\njoin 1\n"
                )
            ).encode()
            with self.assertRaises(poll_scenario.ScenarioCodecError):
                store.save_entry(encoded, {"region:1:1"})

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
                    Path("oracle"), Path("eventfd.ops"), trace
                )
            self.assertTrue(result.passed)
            self.assertEqual(recorder.call_count, 3)
            self.assertEqual(trace.read_bytes(), b"stable poll trace")

            calls = 0

            def unstable_record(_elf, _ops, destination):
                nonlocal calls
                destination.write_bytes(f"trace {calls}".encode())
                calls += 1
                return poll_adapter.HostRecordResult(True, False, "recorded")

            with mock.patch.object(
                poll_adapter, "record_host_once", side_effect=unstable_record
            ):
                result = poll_adapter.record_host_stable(
                    Path("oracle"), Path("eventfd.ops"), trace
                )
            self.assertFalse(result.passed)
            self.assertIn("not byte-stable", result.log)

    def test_start_poll_fingerprint_appends_kind_without_changing_join(self):
        log = (
            "STARRY_EVENTFD_LINUX_ORACLE_FAILED: host=linux/x86_64 line=4 "
            'scenario=0 operation=1 text="start-poll 1 0 1" '
            "difference_mask=0x00000008 "
            "expected={kind=18,result=0,errno=0,value=1,data_len=0} "
            "actual={kind=18,result=1,errno=0,value=1,data_len=0}\n"
        )
        difference = guest_result.parse_operation_difference(log)
        self.assertIsNotNone(difference)
        result = fingerprint.MismatchFingerprint.from_difference(
            difference, poll_reducer.OperationOrigin(0, 1)
        )
        self.assertEqual(result.operation_kind, "start-poll")
        self.assertEqual(fingerprint._KINDS["join"], 17)
        self.assertEqual(fingerprint._KINDS["start-poll"], 18)

    def test_early_completion_timeout_and_helper_errors_are_typed(self):
        early_completion = (
            "STARRY_EVENTFD_LINUX_ORACLE_FAILED: host=linux/x86_64 line=5 "
            'scenario=0 operation=2 text="assert-pending 1" '
            "difference_mask=0x00000008 "
            "expected={kind=16,result=0,errno=0,value=0,data_len=0} "
            "actual={kind=16,result=1,errno=0,value=0,data_len=0}\n"
        )
        classified = guest_result.classify_guest_execution(
            early_completion, 1
        )
        self.assertIs(
            classified.category,
            guest_result.GuestResultCategory.SEMANTIC_MISMATCH,
        )
        self.assertEqual(classified.difference.operation_text, "assert-pending 1")

        schedule_timeout = guest_result.classify_guest_execution(
            "STARRY_EVENTFD_LINUX_ORACLE_SCHEDULE_TIMEOUT: join 1", 1
        )
        self.assertIs(
            schedule_timeout.category,
            guest_result.GuestResultCategory.SCHEDULE_TIMEOUT,
        )
        helper_error = guest_result.classify_guest_execution(
            "STARRY_EVENTFD_LINUX_ORACLE_HARNESS_ERROR: pthread", 1
        )
        self.assertIs(
            helper_error.category,
            guest_result.GuestResultCategory.HARNESS_ERROR,
        )


class EventFdBlockingPollHarnessTests(unittest.TestCase):
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

    def test_checked_pollin_and_pollout_record_stably_and_compare(self):
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
                self.assertIn("operations=31", result.stdout)
                traces.append(trace.read_bytes())
            self.assertEqual(traces[0], traces[1])
            self.assertEqual(traces[1], traces[2])
            self.assertEqual(traces[0][:8], b"EVFDORC3")
            self._assert_join_records_capture_poll_result(traces[0])
            compared = subprocess.run(
                [str(self.oracle), "--compare", str(CORPUS_PATH), str(root / "trace-0")],
                capture_output=True,
                text=True,
            )
        self.assertEqual(compared.returncode, 0, compared.stderr)
        self.assertIn("STARRY_EVENTFD_LINUX_ORACLE_PASSED", compared.stdout)

    def test_v3_parser_rejects_v2_worker_operation(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            corpus = root / "eventfd.ops"
            trace = root / "linux.trace"
            corpus.write_text(
                "version 3\nscenario x\neventfd 0 0\nstart-read 1 0\n"
            )
            result = subprocess.run(
                [str(self.oracle), "--record", str(corpus), str(trace)],
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid operation", result.stderr)

    def test_v3_trace_magic_cannot_be_read_as_v2(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            trace = root / "linux.trace"
            result = subprocess.run(
                [str(self.oracle), "--record", str(CORPUS_PATH), str(trace)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            encoded = bytearray(trace.read_bytes())
            encoded[:8] = b"EVFDORC2"
            trace.write_bytes(encoded)
            compared = subprocess.run(
                [str(self.oracle), "--compare", str(CORPUS_PATH), str(trace)],
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(compared.returncode, 0)
        self.assertIn("invalid expected trace header", compared.stderr)

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
                ("value", ctypes.c_uint64),
                ("error", ctypes.c_int32),
                ("data", ctypes.c_ubyte * 16),
            ]

        header = TraceHeader.from_buffer_copy(trace)
        offset = ctypes.sizeof(TraceHeader)
        records = []
        for _ in range(header.record_count):
            records.append(OperationResult.from_buffer_copy(trace, offset))
            offset += ctypes.sizeof(OperationResult)
        joins = [record for record in records if record.kind == 17]
        self.assertEqual(len(joins), 5)
        self.assertEqual([record.result for record in joins], [1] * 5)
        self.assertEqual([record.error for record in joins], [0] * 5)
        self.assertEqual([record.data_len for record in joins], [2] * 5)
        self.assertEqual(
            [record.data[0] | (record.data[1] << 8) for record in joins],
            [1, 1, 1, 4, 4],
        )


if __name__ == "__main__":
    unittest.main()
