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
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/pipe-oracle"
CASE_DIR = WORKSPACE_ROOT / "test-suit/starryos/qemu/pipe-linux-oracle"
CORPUS_PATH = CASE_DIR / "c/corpus/pipe-concurrent.ops"
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


class PipeConcurrentCodecTests(unittest.TestCase):
    def test_epoll_operations_and_wait_families_round_trip(self):
        encoded = (
            "version 7\n"
            "scenario lt\n"
            "pipe2 0 1 0\n"
            "epoll-create 2 0\n"
            "epoll-ctl 2 add 0 1 17\n"
            "start-epoll-wait 1 2 1 -1\n"
            "start-epoll-wait 2 2 1 -1\n"
            "assert-all-pending\n"
            "write 1 1 65\n"
            "join-set 1 2\n"
            "epoll-ctl 2 mod 0 1073741825 34\n"
            "epoll-ctl 2 del 0 0 0\n"
            "scenario pwait\n"
            "signal-config 10 268435456\n"
            "pipe2 0 1 0\n"
            "epoll-create 2 524288\n"
            "epoll-ctl 2 add 0 2147483649 51\n"
            "start-epoll-pwait 1 2 4 -1 usr1\n"
            "assert-pending 1\n"
            "send-signal 1 10\n"
            "assert-signal-handled 1 0\n"
            "write 1 1 66\n"
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
        self.assertIn("epoll-ctl 2 mod 0 1073741825 34", canonical)
        self.assertIn("start-epoll-pwait2 2 0 4 200000000 empty", canonical)

    def test_epoll_rejects_invalid_flags_events_actions_and_timeouts(self):
        prefix = "version 7\nscenario x\npipe2 0 1 0\nepoll-create 2 0\n"
        for operation in (
            "epoll-create 3 1",
            "epoll-ctl 2 add 0 2 1",
            "epoll-ctl 2 mod 0 268435457 1",
            "epoll-ctl 2 del 0 1 0",
            "start-epoll-wait 1 2 0 -1",
            "start-epoll-pwait 1 2 1 -1 all",
            "start-epoll-pwait2 1 2 1 1000000001 empty",
        ):
            with self.subTest(operation=operation), self.assertRaises(
                concurrent_scenario.ScenarioCodecError
            ):
                concurrent_scenario.parse_document(prefix + operation + "\n")

    def test_signal_timeout_and_ppoll_atomic_mask_round_trip(self):
        encoded = (
            "version 7\nscenario signal-timeout\n"
            "signal-config 10 268435456\n"
            "pipe2 0 1 0\n"
            "start-read 1 0 1\n"
            "assert-pending 1\n"
            "send-signal 1 10\n"
            "assert-signal-handled 1 1\n"
            "assert-pending 1\n"
            "write 1 1 65\n"
            "join 1\n"
            "pipe2 2 3 0\n"
            "start-ppoll 2 2 1 null usr1\n"
            "assert-pending 2\n"
            "send-signal 2 10\n"
            "assert-signal-handled 2 0\n"
            "assert-pending 2\n"
            "write 3 1 66\n"
            "join 2\n"
            "assert-signal-handled 2 1\n"
            "pipe2 4 5 0\n"
            "start-poll 1 4 1 200\n"
            "assert-pending 1\n"
            "join 1\n"
        )

        document = concurrent_scenario.parse_document(encoded)
        canonical = concurrent_scenario.serialize_document(document)

        self.assertEqual(concurrent_scenario.parse_document(canonical), document)
        self.assertIn("start-ppoll 2 2 1 null usr1", canonical)

    def test_signal_and_ppoll_reject_invalid_arguments(self):
        prefix = "version 7\nscenario x\npipe2 0 1 0\n"
        for operation in (
            "signal-config 12 0",
            "signal-config 10 1",
            "assert-signal-handled 1 -1",
            "start-ppoll 1 0 1 -1 empty",
            "start-ppoll 1 0 1 1000000001 empty",
            "start-ppoll 1 0 1 null all",
        ):
            with self.subTest(operation=operation), self.assertRaises(
                concurrent_scenario.ScenarioCodecError
            ):
                concurrent_scenario.parse_document(prefix + operation + "\n")

    def test_v7_round_trip_preserves_two_worker_lifecycle(self):
        encoded = (
            "version 7\nscenario readers\npipe2 0 1 0\n"
            "start-read 1 0 1\nstart-read 2 0 1\n"
            "assert-all-pending\nwrite 1 1 65\nwrite 1 1 66\njoin-set 1 2\n"
        )
        document = concurrent_scenario.parse_document(encoded)
        canonical = concurrent_scenario.serialize_document(document)

        self.assertEqual(concurrent_scenario.parse_document(canonical), document)
        self.assertIn("start-read 2 0 1", canonical)
        self.assertIn("join-set 1 2", canonical)

    def test_blocked_io_holds_ofd_after_descriptor_close(self):
        encoded = (
            "version 7\n"
            "scenario blocked-read-close\n"
            "pipe2 0 1 0\n"
            "start-read 1 0 1\n"
            "assert-pending 1\n"
            "close 0\n"
            "assert-pending 1\n"
            "write 1 1 65\n"
            "join 1\n"
            "scenario blocked-write-close\n"
            "pipe2 0 1 0\n"
            "set-size 1 4096\n"
            "write 1 4096 17\n"
            "start-write 1 1 4096\n"
            "assert-pending 1\n"
            "close 1\n"
            "assert-pending 1\n"
            "read 0 4096\n"
            "join 1\n"
        )

        document = concurrent_scenario.parse_document(encoded)

        self.assertEqual(
            concurrent_scenario.parse_document(
                concurrent_scenario.serialize_document(document)
            ),
            document,
        )

    def test_epoll_interest_tracks_ofd_lifetime_not_fd_number(self):
        encoded = (
            "version 7\n"
            "scenario epoll-ofd-lifetime\n"
            "pipe2 0 1 0\n"
            "dup 0 2\n"
            "epoll-create 3 0\n"
            "epoll-ctl 3 add 0 1 17\n"
            "close 0\n"
            "start-epoll-wait 1 3 1 -1\n"
            "assert-pending 1\n"
            "write 1 1 65\n"
            "join 1\n"
            "read 2 1\n"
            "close 2\n"
            "close 1\n"
            "pipe2 0 1 0\n"
            "write 1 1 66\n"
            "start-epoll-wait 1 3 1 200\n"
            "assert-pending 1\n"
            "join 1\n"
        )

        document = concurrent_scenario.parse_document(encoded)

        self.assertEqual(len(document.scenarios), 1)

    def test_last_reader_close_completes_pollerr_and_epipe_workers(self):
        encoded = (
            "version 7\n"
            "scenario pollerr-epipe\n"
            "pipe2 0 1 0\n"
            "set-size 1 4096\n"
            "write 1 4096 17\n"
            "start-write 1 1 4096\n"
            "start-poll 2 1 4 -1\n"
            "assert-all-pending\n"
            "close 0\n"
            "join-set 1 2\n"
        )

        document = concurrent_scenario.parse_document(encoded)

        self.assertEqual(len(document.scenarios), 1)

    def test_v7_rejects_invalid_actor_and_cross_version(self):
        with self.assertRaises(concurrent_scenario.ScenarioCodecError):
            concurrent_scenario.parse_document(
                "version 7\nscenario x\npipe2 0 1 0\nstart-read 3 0 1\n"
            )
        with self.assertRaises(concurrent_scenario.ScenarioCodecError):
            concurrent_scenario.parse_document(
                "version 6\nscenario x\npipe2 0 1 0\n"
            )

    def test_checked_corpus_is_canonical_and_bounded(self):
        encoded = CORPUS_PATH.read_bytes()
        document = concurrent_scenario.parse_document(encoded)

        concurrent_scenario.validate_entry_limits(document)
        self.assertEqual(concurrent_scenario.serialize_document(document).encode(), encoded)
        self.assertLessEqual(len(document.scenarios), 8)
        self.assertEqual(
            concurrent_scenario.canonical_digest(document),
            hashlib.sha256(encoded).hexdigest(),
        )
        self.assertEqual(
            concurrent_scenario.deterministic_scenario_indexes(document), ()
        )

    def test_recorder_derives_deterministic_indexes_after_combine(self):
        checked = concurrent_scenario.parse_document(CORPUS_PATH.read_bytes())
        combined = concurrent_scenario.ScenarioDocument(
            (checked.scenarios[6], checked.scenarios[0]),
            version=concurrent_scenario.CORPUS_VERSION,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            corpus = root / "pipe.ops"
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

        self.assertEqual(record.call_args.kwargs["deterministic"], ())


class PipeConcurrentRoutingTests(unittest.TestCase):
    def test_concurrent_model_and_campaign_identity_are_exact(self):
        self.assertIs(models.spec_for_model("concurrent"), concurrent_adapter.SPEC)
        self.assertEqual(concurrent_adapter.SPEC.adapter_id, "pipe-concurrent-v1")
        self.assertEqual(concurrent_adapter.SPEC.corpus_version, 7)
        self.assertEqual(
            concurrent_adapter.SPEC.generator_version,
            "pipe-concurrent-generator-v2",
        )
        self.assertEqual(
            concurrent_adapter.SPEC.campaign.root,
            Path("coverage/pipe-concurrent-v1-oracle-fuzz"),
        )
        self.assertEqual(
            concurrent_adapter.SPEC.coverage.target_set_id, "pipe-concurrent-v1"
        )
        self.assertIn(
            "kernel/src/task/signal.rs", concurrent_coverage.TARGET_SOURCE_PATHS
        )
        self.assertIn(
            "kernel/src/syscall/io_mpx/epoll.rs",
            concurrent_coverage.TARGET_SOURCE_PATHS,
        )
        self.assertEqual(
            {name: fingerprint._OPERATION_KINDS[name] for name in (
                "start-ppoll",
                "epoll-create",
                "epoll-ctl",
                "start-epoll-wait",
                "start-epoll-pwait",
                "start-epoll-pwait2",
            )},
            {
                "start-ppoll": 31,
                "epoll-create": 32,
                "epoll-ctl": 33,
                "start-epoll-wait": 34,
                "start-epoll-pwait": 35,
                "start-epoll-pwait2": 36,
            },
        )
        self.assertEqual(models.spec_for_model("simple-single").adapter_id, "pipe-v4")
        self.assertEqual(models.spec_for_model("blocking").adapter_id, "pipe-blocking-v2")

    def test_cli_routes_concurrent_without_changing_default(self):
        with mock.patch.object(fuzz, "_run_common_campaign", return_value=0) as run:
            self.assertEqual(fuzz.main(["--batches", "0"]), 0)
            self.assertEqual(run.call_args.args[0].adapter_id, "pipe-v4")
        with mock.patch.object(fuzz, "_run_common_campaign", return_value=0) as run:
            self.assertEqual(fuzz.main(["--model", "concurrent", "--batches", "0"]), 0)
            self.assertEqual(run.call_args.args[0].adapter_id, "pipe-concurrent-v1")

    def test_complete_scenario_mismatch_is_typed(self):
        vector = "00" * 112
        vector_digest = hashlib.sha256(bytes.fromhex(vector)).hexdigest()
        log = (
            "STARRY_PIPE_CONCURRENT_MISMATCH: scenario=1 alternative=0 "
            "byte_offset=24 expected_length=112 actual_length=112 "
            "expected_byte=0 actual_byte=4 set_digest="
            + "11" * 32
            + " actual_digest="
            + vector_digest
            + " actual_vector="
            + vector
        )
        result = guest_result.classify_guest_execution(log, 1)
        self.assertIs(
            result.category,
            guest_result.GuestResultCategory.UNEXPLAINED_OUTCOME,
        )
        self.assertEqual(result.difference.byte_offset, 24)

    def test_generator_mutation_and_timeout_categories_cover_new_stories(self):
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
                isinstance(operation, concurrent_scenario.StartPpoll)
                for operation in generated[8].operations
            )
        )
        self.assertTrue(
            any(
                isinstance(operation, concurrent_scenario.StartEpollWait)
                for scenario in generated[9:14]
                for operation in scenario.operations
            )
        )
        self.assertTrue(
            any(
                isinstance(operation, concurrent_scenario.StartEpollPwait2)
                for operation in generated[14].operations
            )
        )
        self.assertTrue(
            any(
                isinstance(operation, concurrent_scenario.EpollCreate)
                for operation in generated[15].operations
            )
        )
        self.assertTrue(
            any(
                isinstance(operation, concurrent_scenario.Close)
                for operation in generated[16].operations
            )
        )

        parent = concurrent_scenario.ScenarioDocument((generated[0],), version=7)
        donor = concurrent_scenario.ScenarioDocument((generated[8],), version=7)
        for index, kind in enumerate(concurrent_mutation.MUTATION_KINDS):
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

        syscall_timeout = guest_result.classify_guest_execution(
            "STARRY_PIPE_LINUX_ORACLE_SYSCALL_TIMEOUT: line=1", 1
        )
        schedule_timeout = guest_result.classify_guest_execution(
            "STARRY_PIPE_LINUX_ORACLE_SCHEDULE_TIMEOUT: line=1", 1
        )
        qemu_timeout = guest_result.classify_guest_execution("", None, timed_out=True)
        self.assertIs(
            syscall_timeout.category, guest_result.GuestResultCategory.SYSCALL_TIMEOUT
        )
        self.assertIs(
            schedule_timeout.category, guest_result.GuestResultCategory.SCHEDULE_TIMEOUT
        )
        self.assertIs(qemu_timeout.category, guest_result.GuestResultCategory.TIMEOUT)

    def test_default_mutation_kind_uses_campaign_rng(self):
        parent = concurrent_scenario.ScenarioDocument(
            (
                concurrent_generator.generate_scenario(
                    concurrent_generator.CampaignRng(41), story=0
                ),
            ),
            version=7,
        )
        donor = concurrent_scenario.ScenarioDocument(
            (
                concurrent_generator.generate_scenario(
                    concurrent_generator.CampaignRng(43), story=8
                ),
            ),
            version=7,
        )

        first = concurrent_mutation.mutate_document(
            concurrent_generator.CampaignRng(42), parent, donor
        )
        second = concurrent_mutation.mutate_document(
            concurrent_generator.CampaignRng(42), parent, donor
        )

        self.assertEqual(first, second)
        self.assertIn(first.kind, concurrent_mutation.MUTATION_KINDS)


class PipeConcurrentHarnessTests(unittest.TestCase):
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

    def test_v7_raw_record_converges_and_aggregate_self_compares(self):
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
                expected_magic=b"PIPERUN7",
                expected_version=7,
                expected_corpus_digest=corpus_digest,
            )
            self.assertGreaterEqual(len(scenarios), 6)

            aggregate = root / "linux.trace"
            result = concurrent_adapter.record_host_converged(
                self.oracle, CORPUS_PATH, aggregate
            )
            self.assertTrue(result.passed, result.log)
            allowed = AllowedTrace.from_bytes(
                aggregate.read_bytes(),
                expected_magic=b"PIPEORC1",
                expected_version=7,
                expected_corpus_digest=corpus_digest,
            )
            self.assertEqual(len(allowed.scenarios), len(scenarios))
            self.assertEqual(len(allowed.scenarios[6].alternatives), 1)
            self.assertEqual(len(allowed.scenarios[7].alternatives), 1)
            compared = subprocess.run(
                [str(self.oracle), "--compare", str(CORPUS_PATH), str(aggregate)],
                capture_output=True,
                text=True,
            )
        self.assertEqual(compared.returncode, 0, compared.stderr)

    def test_indexed_completion_schedule_enumerates_two_waiter_groups(self):
        encoded = (
            "version 7\nscenario scheduled\n"
            "pipe2 0 1 0\n"
            "start-poll 1 0 1 -1\nstart-poll 2 0 1 -1\n"
            "assert-all-pending\nclose 1\njoin-set 1 2\n"
            "pipe2 2 3 0\n"
            "start-poll 1 2 1 -1\nstart-poll 2 2 1 -1\n"
            "assert-all-pending\nclose 3\njoin-set 1 2\n"
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
                        "STARRY_PIPE_CONCURRENT_COMPLETION_SCHEDULE"
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
                        expected_magic=b"PIPERUN7",
                        expected_version=7,
                        expected_corpus_digest=corpus_digest,
                    )[0]
                    ordinals = tuple(
                        int.from_bytes(
                            scenario.payload[index * 112 + 44 : index * 112 + 48],
                            "little",
                        )
                        for index in (1, 2, 7, 8)
                    )
                    self.assertEqual(ordinals, expected_ordinals)

    def test_epoll_wait_pwait_and_pwait2_execute_on_host(self):
        encoded = (
            "version 7\nscenario lt\npipe2 0 1 0\nepoll-create 2 0\n"
            "epoll-ctl 2 add 0 1 17\nstart-epoll-wait 1 2 1 -1\n"
            "start-epoll-wait 2 2 1 -1\nassert-all-pending\n"
            "write 1 1 65\njoin-set 1 2\n"
            "scenario pwait\nsignal-config 10 268435456\npipe2 0 1 0\n"
            "epoll-create 2 0\nepoll-ctl 2 add 0 2147483649 34\n"
            "start-epoll-pwait 1 2 4 -1 usr1\nassert-pending 1\n"
            "send-signal 1 10\nassert-signal-handled 1 0\n"
            "write 1 1 66\njoin 1\nassert-signal-handled 1 1\n"
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

    def test_close_and_ofd_lifetime_stories_execute_on_host(self):
        encoded = (
            "version 7\n"
            "scenario blocked-read-close\n"
            "pipe2 0 1 0\nstart-read 1 0 1\nassert-pending 1\n"
            "close 0\nassert-pending 1\nwrite 1 1 65\njoin 1\n"
            "scenario blocked-write-close\n"
            "pipe2 0 1 0\nset-size 1 4096\nwrite 1 4096 17\n"
            "start-write 1 1 4096\nassert-pending 1\nclose 1\n"
            "assert-pending 1\nread 0 4096\njoin 1\n"
            "scenario pollerr-epipe\n"
            "pipe2 0 1 0\nset-size 1 4096\nwrite 1 4096 34\n"
            "start-write 1 1 4096\nstart-poll 2 1 4 -1\n"
            "assert-all-pending\nclose 0\njoin-set 1 2\n"
            "scenario epoll-ofd-lifetime\n"
            "pipe2 0 1 0\ndup 0 2\nepoll-create 3 0\n"
            "epoll-ctl 3 add 0 1 17\nclose 0\n"
            "start-epoll-wait 1 3 1 -1\nassert-pending 1\n"
            "write 1 1 66\njoin 1\nread 2 1\nclose 2\nclose 1\n"
            "pipe2 0 1 0\nwrite 1 1 67\n"
            "start-epoll-wait 1 3 1 200\nassert-pending 1\njoin 1\n"
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
                timeout=8,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("operations=41 scenarios=4", result.stdout)

    def test_cleanup_joins_restart_mask_and_large_write_workers(self):
        corpora = (
            "version 7\nscenario cleanup\nsignal-config 10 268435456\n"
            "pipe2 0 1 0\nstart-read 1 0 1\nassert-pending 1\n"
            "send-signal 1 10\nassert-signal-handled 1 1\ninvalid\n",
            "version 7\nscenario cleanup\nsignal-config 10 268435456\n"
            "pipe2 0 1 0\nstart-ppoll 1 0 1 null usr1\nassert-pending 1\n"
            "send-signal 1 10\nassert-signal-handled 1 0\ninvalid\n",
            "version 7\nscenario cleanup\npipe2 0 1 0\nset-size 1 4096\n"
            "write 1 4096 17\nstart-write 1 1 8192\nassert-pending 1\ninvalid\n",
            "version 7\nscenario cleanup\nsignal-config 10 268435456\n"
            "pipe2 0 1 0\nepoll-create 2 0\n"
            "epoll-ctl 2 add 0 2147483649 17\n"
            "start-epoll-pwait 1 2 1 -1 usr1\nassert-pending 1\n"
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
