import hashlib
import os
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
import fingerprint  # noqa: E402
import guest_result  # noqa: E402
import models  # noqa: E402
from linux_oracle.outcomes import AllowedTrace, decode_raw_run_trace, fnv1a64  # noqa: E402


class EventFdConcurrentCodecTests(unittest.TestCase):
    def test_epoll_operations_and_wait_families_round_trip(self):
        encoded = (
            "version 4\n"
            "scenario lt\n"
            "eventfd 0 0\n"
            "epoll-create 1 0\n"
            "epoll-ctl 1 add 0 1 17\n"
            "start-epoll-wait 1 1 1 -1\n"
            "start-epoll-wait 2 1 1 -1\n"
            "assert-all-pending\n"
            "write 0 8 0 1\n"
            "join-set 1 2\n"
            "epoll-ctl 1 mod 0 1073741825 34\n"
            "epoll-ctl 1 del 0 0 0\n"
            "scenario pwait\n"
            "signal-config 10 268435456\n"
            "eventfd 0 0\n"
            "epoll-create 1 524288\n"
            "epoll-ctl 1 add 0 2147483649 51\n"
            "start-epoll-pwait 1 1 4 -1 usr1\n"
            "assert-pending 1\n"
            "send-signal 1 10\n"
            "assert-signal-handled 1 0\n"
            "write 0 8 0 1\n"
            "join 1\n"
            "assert-signal-handled 1 1\n"
            "scenario pwait2\n"
            "epoll-create 0 0\n"
            "start-epoll-pwait2 2 0 4 200000000 empty\n"
            "assert-pending 2\n"
            "join 2\n"
        )

        document = concurrent_scenario.parse_document(encoded)
        canonical = concurrent_scenario.serialize_document(document)

        self.assertEqual(concurrent_scenario.parse_document(canonical), document)
        self.assertIn("epoll-ctl 1 mod 0 1073741825 34", canonical)
        self.assertIn("start-epoll-pwait2 2 0 4 200000000 empty", canonical)

    def test_epoll_rejects_invalid_flags_events_actions_and_timeouts(self):
        prefix = "version 4\nscenario x\neventfd 0 0\nepoll-create 1 0\n"
        for operation in (
            "epoll-create 2 1",
            "epoll-ctl 1 add 0 2 1",
            "epoll-ctl 1 mod 0 268435457 1",
            "epoll-ctl 1 del 0 1 0",
            "start-epoll-wait 1 1 0 -1",
            "start-epoll-pwait 1 1 1 -1 all",
            "start-epoll-pwait2 1 1 1 1000000001 empty",
        ):
            with self.subTest(operation=operation), self.assertRaises(
                concurrent_scenario.ScenarioCodecError
            ):
                concurrent_scenario.parse_document(prefix + operation + "\n")

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

    def test_epoll_interest_tracks_eventfd_ofd_lifetime(self):
        state = concurrent_scenario.ResourceState()
        operations = (
            concurrent_scenario.EventFd(0, 0),
            concurrent_scenario.Dup(0, 1),
            concurrent_scenario.EpollCreate(2, 0),
            concurrent_scenario.EpollCtl(
                2,
                concurrent_scenario.EpollCtlAction.ADD,
                0,
                concurrent_scenario.EPOLLIN,
                17,
            ),
            concurrent_scenario.Close(0),
        )
        for operation in operations:
            state.apply(operation)
        self.assertEqual(len(state.epolls[2].registrations), 1)

        state.apply(concurrent_scenario.Close(1))

        self.assertEqual(state.epolls[2].registrations, {})

    def test_controller_read_cannot_depend_on_unjoined_writer_progress(self):
        scenario = concurrent_scenario.Scenario(
            (
                concurrent_scenario.EventFd(0, (1 << 32) - 1),
                concurrent_scenario.Write(
                    0,
                    8,
                    concurrent_scenario.PointerMode.VALID,
                    concurrent_generator._FULL_COUNTER_INCREMENT,
                ),
                concurrent_scenario.StartWrite(
                    1, 0, concurrent_scenario.MAX_COUNTER
                ),
                concurrent_scenario.StartWrite(
                    2, 0, concurrent_scenario.MAX_COUNTER
                ),
                concurrent_scenario.AssertAllPending(),
                concurrent_scenario.Read(
                    0, 8, concurrent_scenario.PointerMode.VALID
                ),
                concurrent_scenario.Read(
                    0, 8, concurrent_scenario.PointerMode.VALID
                ),
                concurrent_scenario.JoinSet((1, 2)),
            )
        )

        self.assertIsInstance(
            concurrent_scenario.analyze_scenario(scenario),
            concurrent_scenario.ResourceState,
        )
        with self.assertRaises(
            concurrent_scenario.ScenarioCodecError
        ) as raised:
            concurrent_scenario.validate_schedulable_scenario(scenario)

        self.assertEqual(raised.exception.category, "blocking-operation")
        self.assertIn("unjoined worker progress", raised.exception.detail)

        safe = concurrent_scenario.ScenarioDocument(
            (
                concurrent_generator.generate_scenario(
                    concurrent_generator.CampaignRng(42), story=0
                ),
            ),
            version=4,
        )
        unsafe = concurrent_scenario.ScenarioDocument((scenario,), version=4)
        candidate = concurrent_mutation.mutate_document(
            concurrent_generator.CampaignRng(42),
            safe,
            unsafe,
            requested_kind="append-donor",
        )
        self.assertEqual(
            candidate.classification,
            concurrent_mutation.CandidateClassification.REJECTED,
        )

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
        concurrent_scenario.validate_schedulable_document(document)
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
        self.assertEqual(
            concurrent_scenario.deterministic_scenario_indexes(document), (7,)
        )

    def test_recorder_derives_deterministic_indexes_after_combine(self):
        checked = concurrent_scenario.parse_document(CORPUS_PATH.read_bytes())
        combined = concurrent_scenario.ScenarioDocument(
            (checked.scenarios[7], checked.scenarios[0]),
            version=concurrent_scenario.CORPUS_VERSION,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            corpus = root / "eventfd.ops"
            corpus.write_text(concurrent_scenario.serialize_document(combined))
            result = concurrent_adapter.HostRecordResult(True, False, "recorded")
            with mock.patch.object(
                concurrent_adapter, "record_converged_host", return_value=result
            ) as record:
                self.assertIs(
                    concurrent_adapter.record_host_converged(
                        root / "oracle", corpus, root / "linux.trace"
                    ),
                    result,
                )

        self.assertEqual(record.call_args.kwargs["deterministic"], (0,))


class EventFdConcurrentRoutingTests(unittest.TestCase):
    def test_concurrent_model_is_exact_and_legacy_routes_are_unchanged(self):
        self.assertIs(models.spec_for_model("concurrent"), concurrent_adapter.SPEC)
        self.assertEqual(concurrent_adapter.SPEC.adapter_id, "eventfd-concurrent-v1")
        self.assertEqual(concurrent_adapter.SPEC.corpus_version, 4)
        self.assertEqual(
            concurrent_adapter.SPEC.generator_version,
            "eventfd-concurrent-generator-v3",
        )
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
        self.assertIn(
            "os/StarryOS/kernel/src/syscall/io_mpx/epoll.rs",
            concurrent_coverage.TARGET_SOURCE_PATHS,
        )
        self.assertEqual(
            {name: fingerprint._KINDS[name] for name in (
                "start-ppoll",
                "epoll-create",
                "epoll-ctl",
                "start-epoll-wait",
                "start-epoll-pwait",
                "start-epoll-pwait2",
            )},
            {
                "start-ppoll": 24,
                "epoll-create": 25,
                "epoll-ctl": 26,
                "start-epoll-wait": 27,
                "start-epoll-pwait": 28,
                "start-epoll-pwait2": 29,
            },
        )
        self.assertEqual(models.spec_for_model("simple-single").adapter_id, "eventfd-v1")
        self.assertEqual(
            models.spec_for_model("blocking").adapter_id, "eventfd-blocking-v2"
        )

    def test_generator_and_mutation_cover_signal_and_timeout_stories(self):
        generated = []
        for story in range(concurrent_generator.STORY_COUNT):
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
        self.assertTrue(
            any(
                isinstance(operation, concurrent_scenario.StartEpollWait)
                for scenario in generated[9:13]
                for operation in scenario.operations
            )
        )
        self.assertTrue(
            any(
                isinstance(operation, concurrent_scenario.StartEpollPwait2)
                for operation in generated[13].operations
            )
        )
        self.assertTrue(
            any(
                isinstance(operation, concurrent_scenario.Close)
                for operation in generated[14].operations
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
            self.assertEqual(sum(item.operation_count for item in scenarios), 216)

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
            self.assertEqual(len(allowed.scenarios[6].alternatives), 2)
            self.assertEqual(len(allowed.scenarios[7].alternatives), 1)
            compared = subprocess.run(
                [str(self.oracle), "--compare", str(CORPUS_PATH), str(aggregate)],
                capture_output=True,
                text=True,
            )
        self.assertEqual(compared.returncode, 0, compared.stderr)
        self.assertIn("STARRY_EVENTFD_LINUX_ORACLE_PASSED", compared.stdout)

    def test_indexed_completion_schedule_enumerates_two_waiter_groups(self):
        encoded = (
            "version 4\nscenario scheduled\n"
            "eventfd 0 0\n"
            "start-poll 1 0 1 -1\nstart-poll 2 0 1 -1\n"
            "assert-all-pending\nwrite 0 8 0 1\njoin-set 1 2\n"
            "read 0 8 0\neventfd 1 0\n"
            "start-poll 1 1 1 -1\nstart-poll 2 1 1 -1\n"
            "assert-all-pending\nwrite 1 8 0 1\njoin-set 1 2\n"
        )
        corpus_digest = fnv1a64(encoded.encode())
        expected = {
            0: (1, 2, 3, 4),
            1: (2, 1, 3, 4),
            2: (1, 2, 4, 3),
            3: (2, 1, 4, 3),
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            corpus = root / "scheduled.ops"
            corpus.write_text(encoded)
            for schedule, expected_ordinals in expected.items():
                for repetition in range(2):
                    trace = root / f"schedule-{schedule}-{repetition}.trace"
                    environment = os.environ.copy()
                    environment[
                        "STARRY_EVENTFD_CONCURRENT_COMPLETION_SCHEDULE"
                    ] = str(schedule)
                    recorded = subprocess.run(
                        [str(self.oracle), "--record", str(corpus), str(trace)],
                        capture_output=True,
                        env=environment,
                        text=True,
                        timeout=5,
                    )
                    self.assertEqual(recorded.returncode, 0, recorded.stderr)
                    scenario = decode_raw_run_trace(
                        trace.read_bytes(),
                        expected_magic=b"EVFDRUN4",
                        expected_version=4,
                        expected_corpus_digest=corpus_digest,
                    )[0]
                    ordinals = tuple(
                        int.from_bytes(
                            scenario.payload[index * 112 + 44 : index * 112 + 48],
                            "little",
                        )
                        for index in (1, 2, 8, 9)
                    )
                    self.assertEqual(ordinals, expected_ordinals)
    def test_epoll_wait_pwait_and_pwait2_execute_on_host(self):
        encoded = (
            "version 4\nscenario lt\neventfd 0 0\nepoll-create 1 0\n"
            "epoll-ctl 1 add 0 1 17\nstart-epoll-wait 1 1 1 -1\n"
            "start-epoll-wait 2 1 1 -1\nassert-all-pending\n"
            "write 0 8 0 1\njoin-set 1 2\n"
            "scenario pwait\nsignal-config 10 268435456\neventfd 0 0\n"
            "epoll-create 1 0\nepoll-ctl 1 add 0 2147483649 34\n"
            "start-epoll-pwait 1 1 4 -1 usr1\nassert-pending 1\n"
            "send-signal 1 10\nassert-signal-handled 1 0\n"
            "write 0 8 0 1\njoin 1\nassert-signal-handled 1 1\n"
            "scenario timeout\nepoll-create 0 0\n"
            "start-epoll-pwait2 2 0 4 200000000 empty\n"
            "assert-pending 2\njoin 2\n"
        )
        document = concurrent_scenario.parse_document(encoded)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = root / "epoll.ops"
            trace = root / "epoll.trace"
            corpus.write_text(concurrent_scenario.serialize_document(document))
            result = subprocess.run(
                [str(self.oracle), "--record", str(corpus), str(trace)],
                capture_output=True,
                text=True,
                timeout=5,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("operations=23 scenarios=3", result.stdout)

    def test_alias_close_and_fd_reuse_lifetime_executes_on_host(self):
        encoded = (
            "version 4\nscenario eventfd-ofd-lifetime\n"
            "eventfd 0 0\ndup 0 1\nepoll-create 2 0\n"
            "epoll-ctl 2 add 0 1 17\nclose 0\n"
            "start-epoll-wait 1 2 1 -1\nassert-pending 1\n"
            "write 1 8 0 1\njoin 1\nread 1 8 0\nclose 1\n"
            "eventfd 0 1\n"
            "start-epoll-wait 1 2 1 200\nassert-pending 1\njoin 1\n"
        )
        document = concurrent_scenario.parse_document(encoded)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = root / "lifetime.ops"
            trace = root / "lifetime.trace"
            corpus.write_text(concurrent_scenario.serialize_document(document))
            result = subprocess.run(
                [str(self.oracle), "--record", str(corpus), str(trace)],
                capture_output=True,
                text=True,
                timeout=5,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("operations=15 scenarios=1", result.stdout)

    def test_cleanup_joins_restarted_and_masked_workers(self):
        corpora = (
            "version 4\nscenario cleanup\nsignal-config 10 268435456\n"
            "eventfd 0 0\nstart-read 1 0 8\nassert-pending 1\n"
            "send-signal 1 10\nassert-signal-handled 1 1\ninvalid\n",
            "version 4\nscenario cleanup\nsignal-config 10 268435456\n"
            "eventfd 0 0\nstart-ppoll 1 0 1 null usr1\nassert-pending 1\n"
            "send-signal 1 10\nassert-signal-handled 1 0\ninvalid\n",
            "version 4\nscenario cleanup\nsignal-config 10 268435456\n"
            "eventfd 0 0\nepoll-create 1 0\n"
            "epoll-ctl 1 add 0 2147483649 17\n"
            "start-epoll-pwait 1 1 1 -1 usr1\nassert-pending 1\n"
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
