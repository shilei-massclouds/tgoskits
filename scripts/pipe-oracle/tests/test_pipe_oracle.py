import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import ctypes
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/pipe-oracle"
CASE_DIR = WORKSPACE_ROOT / "test-suit/starryos/qemu/pipe-linux-oracle"
ARTIFACT_ENV = "STARRY_PIPE_ORACLE_ARTIFACT_DIR"

sys.path.insert(0, str(SCRIPT_DIR))

import analyze  # noqa: E402
import corpus  # noqa: E402
import coverage  # noqa: E402
import fuzz  # noqa: E402
import generator  # noqa: E402
import mutation  # noqa: E402
import replay  # noqa: E402
import scenario  # noqa: E402


class PipeOracleRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._oracle_temp = tempfile.TemporaryDirectory()
        cls.oracle_build = Path(cls._oracle_temp.name) / "build"
        subprocess.run(
            ["cmake", "-S", str(CASE_DIR / "c"), "-B", str(cls.oracle_build)],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "cmake",
                "--build",
                str(cls.oracle_build),
                "--target",
                "pipe-linux-oracle",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        cls.oracle = cls.oracle_build / "pipe-linux-oracle"

    @classmethod
    def tearDownClass(cls):
        cls._oracle_temp.cleanup()

    def test_script_help_works_from_the_command_path(self):
        for script in ("analyze.py", "fuzz.py", "minimize.py", "replay.py"):
            result = subprocess.run(
                [sys.executable, str(SCRIPT_DIR / script), "--help"],
                cwd=WORKSPACE_ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("usage:", result.stdout)

    def test_host_oracle_cache_is_checked_by_cmake_before_reuse(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            oracle = workspace / "target/pipe-oracle-host/pipe-linux-oracle"
            oracle.parent.mkdir(parents=True)
            oracle.write_bytes(b"stale oracle")
            with mock.patch.object(fuzz.subprocess, "run") as run:
                resolved = fuzz._find_or_build_host_oracle(workspace)

        self.assertEqual(resolved, oracle)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args_list[1].args[0][-2:],
            ["--target", "pipe-linux-oracle"],
        )

    def test_legacy_seed_text_and_digest_goldens_are_unchanged(self):
        goldens = {
            b"": (
                "version 1\n"
                "scenario generated-0001\n"
                "pipe2 9 0\n"
                "close 0\n"
                "read 9 3692\n",
                "1d67f00aa8e33d81b6c6a9d18be7ecb5c195bafbc50d6263a689de793c1c04f6",
            ),
            b"pipe": (
                "version 1\n"
                "scenario generated-0001\n"
                "pipe2 4 11\n"
                "close 11\n"
                "pipe2 15 0\n"
                "scenario generated-0002\n"
                "pipe2 11 13\n"
                "fionread 11\n"
                "close 11\n"
                "dup 13 15\n"
                "set-size 15 831081\n"
                "get-size 13\n"
                "get-size 13\n"
                "dup 13 3\n"
                "pipe2 0 8\n"
                "read 0 6262\n"
                "write 8 5914 167\n"
                "set-size 8 554989\n"
                "dup 0 10\n"
                "poll 10 1\n"
                "read 10 963\n"
                "dup 13 5\n"
                "pipe2 4 6\n"
                "dup 8 12\n"
                "scenario generated-0003\n"
                "pipe2 0 8\n"
                "write 8 7016 227\n"
                "get-size 8\n"
                "poll 8 4\n"
                "set-size 8 706189\n"
                "close 0\n"
                "close 8\n"
                "pipe2 2 6\n"
                "poll 6 4\n"
                "dup 6 5\n"
                "write 5 2296 220\n"
                "read 2 4875\n"
                "pipe2 8 14\n"
                "set-size 14 622596\n"
                "read 8 7150\n"
                "scenario generated-0004\n"
                "pipe2 1 6\n"
                "dup 1 15\n"
                "close 15\n"
                "write 6 2899 19\n"
                "set-size 6 144457\n"
                "close 1\n"
                "set-size 6 849180\n"
                "pipe2 7 10\n",
                "d2f5c59d0a71945736d2f5ee090e8d8a35d2719156ab8bab3b8dff1bce2d600f",
            ),
        }

        for raw_input, (expected_text, expected_digest) in goldens.items():
            with self.subTest(raw_input=raw_input):
                actual_text, actual_digest = generator.canonicalize_input(raw_input)
                self.assertEqual(actual_text, expected_text)
                self.assertEqual(actual_digest, expected_digest)

    def test_codec_round_trip_covers_all_operations_and_canonicalizes_text(self):
        encoded = b"""
            # names and numeric spelling are not semantic
            version 0x1
            scenario arbitrary-name
            pipe2 0x0 1
            read-null 0
            read 0 0x2000
            write-null 1
            write 1 8192 0xff
            dup 1 2
            close 2
            poll 0 0x7fff
            set-size 1 0x7fffffff
            get-size 0
            fionread 1 # trailing comment
        """

        document = scenario.parse_document(encoded)
        canonical = scenario.serialize_document(document)

        self.assertEqual(scenario.parse_document(canonical), document)
        self.assertEqual(
            [
                scenario.operation_name(operation)
                for operation in document.scenarios[0].operations
            ],
            [
                "pipe2",
                "read-null",
                "read",
                "write-null",
                "write",
                "dup",
                "close",
                "poll",
                "set-size",
                "get-size",
                "fionread",
            ],
        )
        self.assertIn("scenario generated-0001\n", canonical)
        self.assertNotIn("arbitrary-name", canonical)
        self.assertNotIn("0x", canonical)
        self.assertTrue(canonical.endswith("\n"))

    def test_v2_fd_and_flag_operations_round_trip_and_run_on_host(self):
        encoded = (
            "version 2\n"
            "scenario fd-flags\n"
            "pipe2 0 1 526336\n"
            "get-status-flags 0\n"
            "set-status-flags 0 0\n"
            "set-status-flags 1 2048\n"
            "get-status-flags 0\n"
            "get-fd-flags 0\n"
            "set-fd-flags 0 0\n"
            "dup2 0 2\n"
            "get-fd-flags 2\n"
            "dup3 1 3 524288\n"
            "get-fd-flags 3\n"
        )

        document = scenario.parse_document(encoded)
        canonical = scenario.serialize_document(document)

        self.assertEqual(
            canonical,
            encoded.replace("scenario fd-flags", "scenario generated-0001"),
        )
        self.assertEqual(scenario.parse_document(canonical), document)
        self._assert_host_record_compare(canonical)

    def test_v3_vector_operations_round_trip_and_run_on_host(self):
        encoded = (
            "version 3\n"
            "scenario vectors\n"
            "pipe2 0 1 2048\n"
            "writev 1 0 4 4 0 2 65 0 0 66 0 3 67 0 1 68\n"
            "readv 0 0 4 4 0 1 0 3 0 0 0 4\n"
        )

        document = scenario.parse_document(encoded)
        canonical = scenario.serialize_document(document)

        self.assertEqual(
            canonical,
            encoded.replace("scenario vectors", "scenario generated-0001"),
        )
        self.assertIsInstance(document.scenarios[0].operations[1], scenario.Writev)
        self.assertIsInstance(document.scenarios[0].operations[2], scenario.Readv)
        self.assertEqual(scenario.parse_document(canonical), document)
        self._assert_host_record_compare(canonical)

    def test_v4_poll_many_round_trip_and_trace_preserves_order_and_revents(self):
        encoded = (
            "version 4\n"
            "scenario poll-array\n"
            "pipe2 0 1 526336\n"
            "write 1 1 65\n"
            "poll-many 0\n"
            "poll-many 4 1 -2 1 1 -1 4 1 2147483647 4 0 0 1\n"
            "poll-many 4 0 0 1 0 0 1 0 1 4 0 0 0\n"
        )

        document = scenario.parse_document(encoded)
        canonical = scenario.serialize_document(document)
        poll_many = document.scenarios[0].operations[2:]

        self.assertEqual(
            canonical,
            encoded.replace("scenario poll-array", "scenario generated-0001"),
        )
        self.assertTrue(all(isinstance(operation, scenario.PollMany) for operation in poll_many))
        self.assertEqual([len(operation.entries) for operation in poll_many], [0, 4, 4])
        self.assertEqual(scenario.parse_document(canonical), document)
        records = self._record_host_records(canonical)

        self.assertEqual((records[2].kind, records[2].result, records[2].value), (20, 0, 0))
        self.assertEqual(records[2].data_len, 0)
        self.assertEqual((records[3].kind, records[3].result, records[3].value), (20, 2, 4))
        self.assertEqual(records[3].data_len, 8)
        self.assertEqual(bytes(records[3].data[:8]), b"\x00\x00\x00\x00\x20\x00\x01\x00")
        self.assertEqual((records[4].kind, records[4].result, records[4].value), (20, 3, 4))
        self.assertEqual(bytes(records[4].data[:8]), b"\x01\x00\x01\x00\x04\x00\x00\x00")
        self._assert_host_record_compare(canonical)

    def test_poll_many_codec_rejects_versions_counts_modes_args_masks_and_arity(self):
        invalid_documents = (
            "version 3\nscenario x\npoll-many 0\n",
            "version 4\nscenario x\npoll-many -1\n",
            "version 4\nscenario x\npoll-many 5\n",
            "version 4\nscenario x\npoll-many 1\n",
            "version 4\nscenario x\npoll-many 0 0 0 1\n",
            "version 4\nscenario x\npoll-many 1 2 0 1\n",
            "version 4\nscenario x\npoll-many 1 0 -1 1\n",
            "version 4\nscenario x\npoll-many 1 0 16 1\n",
            "version 4\nscenario x\npoll-many 1 1 0 1\n",
            "version 4\nscenario x\npoll-many 1 1 -3 1\n",
            "version 4\nscenario x\npoll-many 1 1 -2 32768\n",
            "version 4\nscenario x\npoll-many 0x0\n",
            "version 4\nscenario x\npoll-many 1 0x0 0 1\n",
            "version 4\nscenario x\npoll-many 1 0 0x0 1\n",
            "version 4\nscenario x\npoll-many 1 0 0 0x1\n",
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            ops = temporary / "pipe.ops"
            trace = temporary / "linux.trace"
            for encoded in invalid_documents:
                with self.subTest(encoded=encoded):
                    with self.assertRaises(scenario.ScenarioCodecError):
                        scenario.parse_document(encoded)
                    ops.write_text(encoded)
                    recorded = subprocess.run(
                        [str(self.oracle), "--record", str(ops), str(trace)],
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(recorded.returncode, 0)

    def test_vector_codec_rejects_versions_fields_modes_counts_and_shapes(self):
        invalid_documents = (
            "version 1\nscenario x\nreadv 0 0 0 0\n",
            "version 2\nscenario x\nwritev 0 0 0 0\n",
            "version 3\nscenario x\nreadv 0 2 0 0\n",
            "version 3\nscenario x\nreadv 0 0 5 0\n",
            "version 3\nscenario x\nreadv 0 0 1 0\n",
            "version 3\nscenario x\nreadv 0 0 1 1 2 1\n",
            "version 3\nscenario x\nwritev 0 0 1 1 0 1\n",
            "version 3\nscenario x\nreadv 0 0 2 2 0 8192 0 1\n",
        )

        for encoded in invalid_documents:
            with self.subTest(encoded=encoded):
                with self.assertRaises(scenario.ScenarioCodecError):
                    scenario.parse_document(encoded)

    def test_vector_blocking_safety_accepts_only_pre_io_failures_or_nonblocking_io(self):
        for operation in (
            "readv 0 0 1 1 0 1",
            "writev 1 0 1 1 0 1 65",
            "readv 0 0 1 1 1 1",
        ):
            encoded = f"version 3\nscenario blocking\npipe2 0 1 0\n{operation}\n"
            with self.subTest(operation=operation):
                with self.assertRaises(scenario.ScenarioCodecError) as caught:
                    scenario.parse_document(encoded)
                self.assertEqual(
                    caught.exception.category,
                    scenario.CodecErrorCategory.BLOCKING_IO,
                )

        safe = (
            "version 3\n"
            "scenario safe-vector-errors\n"
            "pipe2 0 1 0\n"
            "readv 0 0 0 0\n"
            "writev 1 0 1 1 1 0 65\n"
            "readv 15 0 1 1 0 8192\n"
            "writev 0 0 1 1 0 8192 65\n"
            "readv 0 1 1 0\n"
            "writev 1 0 1025 0\n"
            "set-status-flags 0 2048\n"
            "readv 0 0 1 1 1 1\n"
        )
        scenario.parse_document(safe)

    def test_host_vector_trace_captures_errno_segments_and_read_sentinels(self):
        encoded = (
            "version 3\n"
            "scenario vector-trace\n"
            "pipe2 0 1 2048\n"
            "writev 1 0 2 2 0 2 65 0 1 66\n"
            "readv 0 0 3 3 0 1 0 2 0 2\n"
            "writev 1 0 1 1 0 1 67\n"
            "readv 0 0 1 1 1 1\n"
            "writev 15 1 1 0\n"
            "readv 0 0 1025 0\n"
        )

        records = self._record_host_records(encoded)

        self.assertEqual((records[1].kind, records[1].result), (19, 3))
        self.assertEqual((records[2].kind, records[2].result), (18, 3))
        self.assertEqual(records[2].data_len, 5)
        self.assertEqual(bytes(records[2].data[:5]), b"AAB\xa5\xa5")
        self.assertEqual(
            (records[4].kind, records[4].result, records[4].error),
            (18, -1, 14),
        )
        self.assertEqual(records[4].data_len, 0)
        self.assertEqual(
            (records[5].kind, records[5].result, records[5].error),
            (19, -1, 9),
        )
        self.assertEqual(
            (records[6].kind, records[6].result, records[6].error),
            (18, -1, 22),
        )

    def test_v2_rejects_blocking_io_but_keeps_safe_error_and_zero_length_paths(self):
        unsafe = (
            "version 2\nscenario blocking\npipe2 0 1 0\nread 0 1\n"
        )
        with self.assertRaises(scenario.ScenarioCodecError) as caught:
            scenario.parse_document(unsafe)
        self.assertEqual(
            caught.exception.category,
            scenario.CodecErrorCategory.BLOCKING_IO,
        )

        safe = (
            "version 2\n"
            "scenario safe\n"
            "pipe2 0 1 0\n"
            "read 0 0\n"
            "read 2 8192\n"
            "set-status-flags 0 2048\n"
            "read 0 1\n"
        )
        document = scenario.parse_document(safe)
        self.assertEqual(scenario.parse_document(scenario.serialize_document(document)), document)

    def test_host_harness_rejects_positive_blocking_io_before_execution(self):
        encoded = (
            "version 2\n"
            "scenario blocking-write\n"
            "pipe2 0 1 0\n"
            "write 1 1 65\n"
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            ops = Path(temporary_directory) / "pipe.ops"
            trace = Path(temporary_directory) / "linux.trace"
            ops.write_text(encoded)
            result = subprocess.run(
                [str(self.oracle), "--record", str(ops), str(trace)],
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid operation", result.stderr)

    def test_host_success_marker_starts_on_an_isolated_line(self):
        encoded = (
            "version 2\n"
            "scenario unknown-flags\n"
            "pipe2 0 1 1073741824\n"
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            ops = Path(temporary_directory) / "pipe.ops"
            trace = Path(temporary_directory) / "linux.trace"
            ops.write_text(encoded)
            subprocess.run(
                [str(self.oracle), "--record", str(ops), str(trace)],
                check=True,
                capture_output=True,
                text=True,
            )
            compared = subprocess.run(
                [str(self.oracle), "--compare", str(ops), str(trace)],
                capture_output=True,
                text=True,
            )

        self.assertEqual(compared.returncode, 0, compared.stderr)
        self.assertIn("\n\nSTARRY_PIPE_LINUX_ORACLE_PASSED:", compared.stdout)

    def test_v2_resource_state_shares_status_flags_but_rolls_back_failed_updates(self):
        shared_alias = (
            "version 2\n"
            "scenario shared\n"
            "pipe2 0 1 0\n"
            "dup 0 2\n"
            "set-status-flags 2 2048\n"
            "read 0 1\n"
        )
        scenario.parse_document(shared_alias)

        failed_updates = (
            (
                "version 2\nscenario failed-fcntl\npipe2 0 1 0\n"
                "set-status-flags 2 2048\nread 0 1\n"
            ),
            (
                "version 2\nscenario failed-dup2\npipe2 0 1 2048\n"
                "pipe2 2 3 0\ndup2 4 2\nread 2 1\n"
            ),
            (
                "version 2\nscenario failed-dup3\npipe2 0 1 2048\n"
                "pipe2 2 3 0\ndup3 0 2 2048\nread 2 1\n"
            ),
        )
        for encoded in failed_updates:
            with self.subTest(encoded=encoded.splitlines()[1]):
                with self.assertRaises(scenario.ScenarioCodecError) as caught:
                    scenario.parse_document(encoded)
                self.assertEqual(
                    caught.exception.category,
                    scenario.CodecErrorCategory.BLOCKING_IO,
                )

    def test_v1_and_v2_reject_each_others_pipe2_shape_and_v1_rejects_fd_ops(self):
        invalid_documents = (
            "version 1\nscenario x\npipe2 0 1 526336\n",
            "version 2\nscenario x\npipe2 0 1\n",
            "version 1\nscenario x\nget-fd-flags 0\n",
            "version 2\nscenario x\npipe2 0 1 16384\n",
            "version 2\nscenario x\ndup3 0 1 3\n",
        )
        for encoded in invalid_documents:
            with self.subTest(encoded=encoded):
                with self.assertRaises(scenario.ScenarioCodecError):
                    scenario.parse_document(encoded)

    def test_host_normalizes_flags_and_dup_results_with_linux_errno(self):
        encoded = (
            "version 2\n"
            "scenario observable\n"
            "pipe2 0 1 526336\n"
            "get-status-flags 0\n"
            "dup 0 2\n"
            "set-status-flags 2 0\n"
            "get-status-flags 0\n"
            "get-fd-flags 0\n"
            "set-fd-flags 0 0\n"
            "set-fd-flags 2 1\n"
            "get-fd-flags 0\n"
            "get-fd-flags 2\n"
            "dup2 1 3\n"
            "get-fd-flags 3\n"
            "dup3 1 4 524288\n"
            "get-fd-flags 4\n"
            "dup2 4 4\n"
            "get-fd-flags 4\n"
            "dup3 4 4 0\n"
            "dup3 1 5 2048\n"
            "dup2 6 5\n"
            "get-fd-flags 6\n"
            "pipe2 7 8 1073741824\n"
        )
        records = self._record_host_records(encoded)

        self.assertEqual(
            [records[index].kind for index in (1, 3, 5, 6, 10, 12)],
            [12, 13, 14, 15, 16, 17],
        )
        self.assertEqual([records[index].value for index in (1, 4)], [2048, 0])
        self.assertEqual([records[index].value for index in (8, 9)], [0, 1])
        self.assertEqual(records[10].result, 0)
        self.assertEqual(records[11].value, 0)
        self.assertEqual(records[12].result, 0)
        self.assertEqual(records[13].value, 1)
        self.assertEqual(records[14].result, 0)
        self.assertEqual(records[15].value, 1)
        self.assertEqual((records[16].result, records[16].error), (-1, 22))
        self.assertEqual((records[17].result, records[17].error), (-1, 22))
        self.assertEqual((records[18].result, records[18].error), (-1, 9))
        self.assertEqual((records[19].result, records[19].error), (-1, 9))
        self.assertEqual((records[20].result, records[20].error), (-1, 22))

    def test_scenario_names_do_not_change_semantic_ir_or_digest(self):
        first = scenario.parse_document(
            "version 1\nscenario first\npipe2 0 1\n"
        )
        second = scenario.parse_document(
            "# comment\nversion 1\nscenario second\npipe2 0x0 0x1\n"
        )

        self.assertEqual(first, second)
        self.assertEqual(
            scenario.canonical_digest(first),
            scenario.canonical_digest(second),
        )

    def test_codec_errors_have_stable_categories_and_line_numbers(self):
        cases = (
            (b"\xff", scenario.CodecErrorCategory.INVALID_ENCODING, 1),
            ("scenario x\npipe2 0 1\n", scenario.CodecErrorCategory.MISSING_VERSION, 1),
            (
                "version 1\nversion 1\nscenario x\npipe2 0 1\n",
                scenario.CodecErrorCategory.DUPLICATE_VERSION,
                2,
            ),
            (
                "version 5\nscenario x\npipe2 0 1\n",
                scenario.CodecErrorCategory.INVALID_VERSION,
                1,
            ),
            (
                "version 1\nscenario two names\npipe2 0 1\n",
                scenario.CodecErrorCategory.INVALID_SCENARIO,
                2,
            ),
            (
                "version 1\nread 0 1\n",
                scenario.CodecErrorCategory.OPERATION_BEFORE_SCENARIO,
                2,
            ),
            (
                "version 1\nscenario x\nunknown 0\n",
                scenario.CodecErrorCategory.UNKNOWN_OPERATION,
                3,
            ),
            (
                "version 1\nscenario x\nread 0\n",
                scenario.CodecErrorCategory.INVALID_ARITY,
                3,
            ),
            (
                "version 1\nscenario x\nread 0 nope\n",
                scenario.CodecErrorCategory.INVALID_NUMBER,
                3,
            ),
            (
                "version 1\nscenario x\nread 0 8193\n",
                scenario.CodecErrorCategory.OUT_OF_RANGE,
                3,
            ),
            (
                "version 1\nscenario x\npipe2 0 0\n",
                scenario.CodecErrorCategory.RESOURCE_CONFLICT,
                3,
            ),
            (
                "version 1\nscenario x\n",
                scenario.CodecErrorCategory.INCOMPLETE_DOCUMENT,
                2,
            ),
        )

        for encoded, expected_category, expected_line in cases:
            with self.subTest(category=expected_category):
                with self.assertRaises(scenario.ScenarioCodecError) as caught:
                    scenario.parse_document(encoded)
                self.assertEqual(caught.exception.category, expected_category)
                self.assertEqual(caught.exception.line_number, expected_line)

    def test_checked_in_corpus_round_trips_and_host_record_compare_is_self_consistent(self):
        checked_in = (CASE_DIR / "c/corpus/pipe.ops").read_text()
        document = scenario.parse_document(checked_in)
        canonical = scenario.serialize_document(document)
        self.assertEqual(
            scenario.parse_document(canonical),
            scenario.parse_document(scenario.serialize_document(document)),
        )
        self._assert_host_record_compare(canonical)

    def test_compare_reports_stable_difference_mask(self):
        corpus_text = "version 1\nscenario generated-0001\npipe2 0 1\n"
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            ops = temporary / "pipe.ops"
            trace = temporary / "linux.trace"
            ops.write_text(corpus_text)
            recorded = subprocess.run(
                [str(self.oracle), "--record", str(ops), str(trace)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(recorded.returncode, 0, recorded.stderr)
            encoded = bytearray(trace.read_bytes())
            # trace_header is 128 bytes; operation_result.result begins 16 bytes
            # into the first 8-byte-aligned record.
            encoded[144:152] = int(-1).to_bytes(8, "little", signed=True)
            trace.write_bytes(encoded)

            compared = subprocess.run(
                [str(self.oracle), "--compare", str(ops), str(trace)],
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(compared.returncode, 0)
        self.assertIn("difference_mask=0x00000008", compared.stderr)

    def test_compare_fails_closed_on_truncated_trailing_and_unknown_traces(self):
        corpus_text = "version 2\nscenario x\npipe2 0 1 526336\n"
        mutations = {
            "truncated": lambda encoded: encoded[:-1],
            "trailing": lambda encoded: encoded + b"x",
            "unknown-version": lambda encoded: (
                encoded[:8] + (99).to_bytes(4, "little") + encoded[12:]
            ),
        }
        for name, mutate_trace in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary_directory:
                temporary = Path(temporary_directory)
                ops = temporary / "pipe.ops"
                trace = temporary / "linux.trace"
                ops.write_text(corpus_text)
                recorded = subprocess.run(
                    [str(self.oracle), "--record", str(ops), str(trace)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(recorded.returncode, 0, recorded.stderr)
                trace.write_bytes(mutate_trace(trace.read_bytes()))

                compared = subprocess.run(
                    [str(self.oracle), "--compare", str(ops), str(trace)],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(compared.returncode, 0)
                self.assertIn("STARRY_PIPE_LINUX_ORACLE_FAILED", compared.stderr)

    def test_v1_corpus_keeps_legacy_digest_and_accepts_a_v1_trace_header(self):
        corpus_text = "version 1\nscenario legacy\npipe2 0 1\nget-fd-flags 0\n"
        with self.assertRaises(scenario.ScenarioCodecError):
            scenario.parse_document(corpus_text)

        corpus_text = "version 1\nscenario legacy\npipe2 0 1\nget-size 0\n"
        document = scenario.parse_document(corpus_text)
        expected_digest = scenario.canonical_digest(document)
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            ops = temporary / "pipe.ops"
            trace = temporary / "linux.trace"
            ops.write_text(scenario.serialize_document(document))
            recorded = subprocess.run(
                [str(self.oracle), "--record", str(ops), str(trace)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(recorded.returncode, 0, recorded.stderr)
            encoded = trace.read_bytes()
            trace.write_bytes(encoded[:8] + (1).to_bytes(4, "little") + encoded[12:])
            compared = subprocess.run(
                [str(self.oracle), "--compare", str(ops), str(trace)],
                capture_output=True,
                text=True,
            )

        self.assertEqual(
            expected_digest,
            hashlib.sha256(scenario.serialize_document(document).encode()).hexdigest(),
        )
        self.assertEqual(compared.returncode, 0, compared.stderr)

    def test_old_trace_versions_remain_compatible_and_v4_requires_trace_v4(self):
        corpora = {
            2: "version 2\nscenario fd\npipe2 0 1 2048\nget-fd-flags 0\n",
            3: "version 3\nscenario vector\npipe2 0 1 2048\nreadv 0 0 0 0\n",
            4: "version 4\nscenario poll\npoll-many 0\n",
        }
        for corpus_version, corpus_text in corpora.items():
            with self.subTest(corpus_version=corpus_version), tempfile.TemporaryDirectory() as temporary_directory:
                temporary = Path(temporary_directory)
                ops = temporary / "pipe.ops"
                trace = temporary / "linux.trace"
                ops.write_text(corpus_text)
                recorded = subprocess.run(
                    [str(self.oracle), "--record", str(ops), str(trace)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(recorded.returncode, 0, recorded.stderr)
                encoded = trace.read_bytes()
                old_trace_version = corpus_version if corpus_version < 4 else 3
                trace.write_bytes(
                    encoded[:8]
                    + old_trace_version.to_bytes(4, "little")
                    + encoded[12:]
                )
                compared = subprocess.run(
                    [str(self.oracle), "--compare", str(ops), str(trace)],
                    capture_output=True,
                    text=True,
                )

                if corpus_version < 4:
                    self.assertEqual(compared.returncode, 0, compared.stderr)
                else:
                    self.assertNotEqual(compared.returncode, 0)
                    self.assertIn(f"version-{corpus_version} corpus requires", compared.stderr)

    def test_multi_entry_batch_is_one_canonical_corpus_accepted_by_the_oracle(self):
        documents = [
            generator.legacy_document_from_input(raw_input)
            for raw_input in (b"first", b"second", bytes(range(32)))
        ]
        corpus = scenario.serialize_document(scenario.combine_documents(documents))

        self.assertEqual(corpus.count("version 4\n"), 1)
        scenario_names = [
            line.split(maxsplit=1)[1]
            for line in corpus.splitlines()
            if line.startswith("scenario ")
        ]
        self.assertEqual(len(scenario_names), len(set(scenario_names)))
        self._assert_host_record_compare(corpus)

    def test_campaign_rng_is_versioned_deterministic_and_uses_rejection_sampling(self):
        first = generator.CampaignRng(42)
        second = generator.CampaignRng(42)
        self.assertEqual(
            [first.next() for _ in range(8)],
            [second.next() for _ in range(8)],
        )

        class RejectionProbe(generator.CampaignRng):
            def __init__(self):
                self.values = iter(((1 << 64) - 1, 5))

            def next(self):
                return next(self.values)

        self.assertEqual(RejectionProbe().range(10, 20), 15)

    def test_initial_corpus_migrates_five_legacy_seeds_and_is_digest_sorted(self):
        initial_corpus = corpus.CanonicalCorpus.initial()
        entries = initial_corpus.ordered_entries()
        expected = {
            scenario.serialize_document(generator.legacy_document_from_input(raw)).encode()
            for raw in corpus.LEGACY_INITIAL_SEEDS
        }

        self.assertEqual(len(initial_corpus), 5)
        self.assertEqual({entry.encoded for entry in entries}, expected)
        self.assertEqual(
            [entry.digest for entry in entries],
            sorted(entry.digest for entry in entries),
        )

    def test_batch_selection_is_identical_in_independent_processes(self):
        script = """
import json, sys
sys.path.insert(0, 'scripts/pipe-oracle')
import corpus, fuzz, generator
rng = generator.CampaignRng(42)
batch = fuzz._select_batch(rng, corpus.CanonicalCorpus.initial(), 24)
print(json.dumps([(item.kind, item.classification.value, item.digest) for item in batch]))
"""
        outputs = []
        for _ in range(2):
            result = subprocess.run(
                [sys.executable, "-c", script],
                cwd=WORKSPACE_ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            outputs.append(result.stdout)
        self.assertEqual(outputs[0], outputs[1])
        selected = json.loads(outputs[0])
        compact = json.dumps(selected, separators=(",", ":"))
        self.assertEqual(
            hashlib.sha256(compact.encode()).hexdigest(),
            "7c8b3c9ae49cf6bf4766b6e3881b13c83a9b88c803ef117343ee3022f3675b92",
        )

    def test_every_structural_mutation_changes_digest_and_stays_within_limits(self):
        parent = self._rich_parent_document()
        donor = scenario.parse_document(
            "version 1\n"
            "scenario donor\n"
            "pipe2 8 9\n"
            "write 9 4096 90\n"
            "read 8 1\n"
            "dup 9 10\n"
            "close 10\n"
        )
        parent_digest = scenario.canonical_digest(parent)

        for index, kind in enumerate(mutation.MUTATION_KINDS):
            with self.subTest(kind=kind):
                candidate = mutation.mutate_document(
                    generator.CampaignRng(1000 + index),
                    parent,
                    donor,
                    requested_kind=kind,
                )
                self.assertNotEqual(
                    candidate.encoded,
                    scenario.serialize_document(parent).encode(),
                )
                if candidate.classification == mutation.CandidateClassification.EXECUTABLE:
                    self.assertNotEqual(candidate.digest, parent_digest)
                    self.assertEqual(
                        scenario.parse_document(candidate.encoded),
                        candidate.document,
                    )
                    scenario.validate_entry_limits(candidate.document)
                    for item in candidate.document.scenarios:
                        self.assertLessEqual(
                            len(item.operations),
                            scenario.MAX_OPS_PER_SCENARIO,
                        )
                self.assertEqual(candidate.provenance.source, "mutation")
                self.assertEqual(candidate.provenance.parent_digest, parent_digest)
                self.assertEqual(
                    candidate.provenance.donor_digest,
                    scenario.canonical_digest(donor),
                )
                self.assertEqual(candidate.provenance.mutation_type, kind)

    def test_campaign_startup_loads_disk_corpus_and_reports_counts(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = corpus.CorpusStore(workspace)
            document = generator.generate_document(generator.CampaignRng(12345))
            store.save_entry(
                document,
                corpus.CorpusProvenance.generated(),
                {"pipe.rs:1:1"},
            )
            args = SimpleNamespace(seed=42, batches=0, batch_size=8)
            output = StringIO()

            with redirect_stdout(output):
                status = fuzz._run_campaign(args, workspace, store)

        self.assertEqual(status, 0)
        self.assertIn(
            "Corpus loaded: built-in=5 disk=1 deduplicated-total=6",
            output.getvalue(),
        )

    def test_run_metadata_records_counts_sources_relationships_and_result(self):
        parent = self._rich_parent_document()
        donor = scenario.parse_document(
            "version 1\nscenario donor\npipe2 8 9\nwrite 9 1 97\n"
        )
        generated = mutation.candidate_from_document(
            generator.generate_document(generator.CampaignRng(88)),
            "generate",
        )
        mutated = mutation.mutate_document(
            generator.CampaignRng(99),
            parent,
            donor,
            requested_kind="donor-splice",
        )
        result = fuzz.BatchResult(
            False,
            "passed",
            ("pipe.rs:1:2",),
            tuple(sorted((generated.digest, mutated.digest))),
            "a" * 64,
        )

        metadata = fuzz._build_run_metadata(
            42,
            "./scripts/pipe-oracle/fuzz.py --seed 42",
            3,
            1.25,
            [generated, mutated],
            result,
        )

        self.assertEqual(
            metadata["candidate_counts"],
            {
                "candidates": 2,
                "executable": 2,
                "malformed": 0,
                "unique_inputs": 2,
            },
        )
        self.assertEqual(metadata["candidate_sources"], {"generated": 1, "mutation": 1})
        self.assertEqual(metadata["batch_duration_seconds"], 1.25)
        self.assertEqual(metadata["new_regions"], ["pipe.rs:1:2"])
        self.assertEqual(metadata["starry_elf_sha256"], "a" * 64)
        mutation_relation = metadata["candidate_relationships"][1]
        self.assertEqual(mutation_relation["parent_digest"], scenario.canonical_digest(parent))
        self.assertEqual(mutation_relation["donor_digest"], scenario.canonical_digest(donor))
        self.assertEqual(mutation_relation["mutation_type"], "donor-splice")

        with tempfile.TemporaryDirectory() as temporary_directory:
            store = corpus.CorpusStore(Path(temporary_directory))
            run_path = store.save_run("run-0001", metadata)
            saved = json.loads((run_path / "metadata.json").read_text())
        self.assertEqual(saved["schema_version"], 6)
        self.assertEqual(saved["target_set_id"], "pipe-poll-v4")
        self.assertEqual(saved["generator_version"], generator.GENERATOR_VERSION)
        self.assertEqual(saved["result"], "passed")

    def test_batch_persists_entry_and_restores_elf_coverage_after_restart(self):
        candidate = mutation.candidate_from_document(
            scenario.parse_document(
                "version 1\nscenario x\npipe2 0 1\nwrite 1 1 97\n"
            ),
            "generate",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            oracle = workspace / "pipe-linux-oracle"
            oracle.write_bytes(b"oracle")
            starry_elf = fuzz.coverage_object(workspace)
            starry_elf.parent.mkdir(parents=True)
            starry_elf.write_bytes(b"instrumented StarryOS ELF")
            profraw = workspace / "starry.profraw"
            profraw.write_bytes(b"profile")
            store = corpus.CorpusStore(workspace)

            def record_host(_elf, _ops, trace):
                trace.write_bytes(b"trace")
                return fuzz.HostRecordResult(True, False, "recorded")

            with (
                mock.patch.object(fuzz, "_find_or_build_host_oracle", return_value=oracle),
                mock.patch.object(fuzz, "_record_host", side_effect=record_host),
                mock.patch.object(
                    fuzz,
                    "_run_guest_compare",
                    return_value=("guest", [profraw], True),
                ),
                mock.patch.object(
                    fuzz,
                    "_extract_regions",
                    side_effect=(
                        {"pipe.rs:7:3"},
                        {"pipe.rs:7:3"},
                        {"pipe.rs:7:3"},
                    ),
                ),
            ):
                first = fuzz._run_batch(
                    workspace,
                    0,
                    [candidate],
                    None,
                    corpus.CanonicalCorpus.initial(),
                    store.failures_dir,
                    store=store,
                )

            restarted_store = corpus.CorpusStore(workspace)
            restarted_corpus = corpus.CanonicalCorpus.initial()
            disk_corpus = restarted_store.load_corpus()
            for entry in disk_corpus.ordered_entries():
                restarted_corpus.add(entry.document)

            with (
                mock.patch.object(fuzz, "_find_or_build_host_oracle", return_value=oracle),
                mock.patch.object(fuzz, "_record_host", side_effect=record_host),
                mock.patch.object(
                    fuzz,
                    "_run_guest_compare",
                    return_value=("guest", [profraw], True),
                ),
                mock.patch.object(
                    fuzz,
                    "_extract_regions",
                    return_value={"pipe.rs:7:3"},
                ),
            ):
                second = fuzz._run_batch(
                    workspace,
                    1,
                    [candidate],
                    None,
                    restarted_corpus,
                    restarted_store.failures_dir,
                    store=restarted_store,
                )

        self.assertFalse(first.failed)
        self.assertEqual(first.admitted_digests, (candidate.digest,))
        self.assertEqual(len(disk_corpus), 1)
        self.assertEqual(len(restarted_corpus), 6)
        self.assertFalse(second.failed)
        self.assertEqual(second.new_regions, ())
        self.assertEqual(second.admitted_digests, ())

    def test_parameter_mutation_prefers_boundaries_and_can_be_malformed(self):
        rng = generator.CampaignRng(7)
        boundary_hits = 0
        attempts = 4000
        for _ in range(attempts):
            value = mutation._mutated_number(
                rng,
                123,
                mutation.LENGTH_BOUNDARIES,
                0,
                scenario.MAX_IO_BYTES,
            )
            boundary_hits += int(value in mutation.LENGTH_BOUNDARIES)
        boundary_rate = boundary_hits / attempts
        self.assertGreater(boundary_rate, 0.70)
        self.assertLess(boundary_rate, 0.80)

        parent = self._rich_parent_document()
        classifications = set()
        malformed_categories = set()
        for seed in range(256):
            candidate = mutation.mutate_document(
                generator.CampaignRng(seed),
                parent,
                parent,
                requested_kind="mutate-parameter",
            )
            classifications.add(candidate.classification.value)
            if candidate.error_category:
                malformed_categories.add(candidate.error_category)
        self.assertEqual(classifications, {"executable", "malformed"})
        self.assertTrue(
            {"codec:out-of-range", "codec:resource-conflict"}
            & malformed_categories
        )

    def test_vector_parameter_mutation_changes_each_typed_dimension(self):
        operation = scenario.Writev(
            1,
            scenario.IovMode.VALID,
            2,
            (
                scenario.WritevSegment(scenario.IovBaseMode.VALID, 4096, 65),
                scenario.WritevSegment(scenario.IovBaseMode.INVALID, 4096, 255),
            ),
        )

        mutated_mode = mutation._mutate_operation_parameter(
            generator.CampaignRng(1), operation, "iov-mode"
        )
        mutated_count = mutation._mutate_operation_parameter(
            generator.CampaignRng(2), operation, "iov-count"
        )
        mutated_length = mutation._mutate_operation_parameter(
            generator.CampaignRng(3), operation, "segment-length", 0
        )
        mutated_base = mutation._mutate_operation_parameter(
            generator.CampaignRng(4), operation, "base-mode", 0
        )
        mutated_byte = mutation._mutate_operation_parameter(
            generator.CampaignRng(5), operation, "byte", 0
        )

        self.assertNotEqual(mutated_mode.iov_mode, operation.iov_mode)
        self.assertNotEqual(mutated_count.iovcnt, operation.iovcnt)
        self.assertNotEqual(mutated_length.segments[0].length, 4096)
        self.assertLessEqual(
            sum(segment.length for segment in mutated_length.segments),
            scenario.MAX_IO_BYTES,
        )
        self.assertNotEqual(mutated_base.segments[0].base_mode, operation.segments[0].base_mode)
        self.assertNotEqual(mutated_byte.segments[0].byte, operation.segments[0].byte)

    def test_generator_reaches_all_operations_boundaries_and_resource_errors(self):
        report = analyze.analyze(seed=42, samples=512, mutations=512, top=0)
        campaign = report["sources"]["campaign_rng"]["generation"]

        self.assertTrue(all(campaign["operation_counts"].values()))
        self.assertTrue(all(campaign["resource_categories"].values()))
        for bucket in ("0", "1", "4095", "4096", "4097", "8191", "8192"):
            self.assertGreater(campaign["parameter_buckets"]["length"][bucket], 0)
        for bucket in (
            "0",
            "1",
            "4095",
            "4096",
            "4097",
            "8191",
            "8192",
            "8193",
            "2147483647",
        ):
            self.assertGreater(campaign["parameter_buckets"]["pipe_size"][bucket], 0)
        for bucket in ("0", "1", "4096", "8192", "16384", "32767"):
            self.assertGreater(campaign["parameter_buckets"]["poll_mask"][bucket], 0)

    def test_generator_deterministically_reaches_pipe_and_dup_flag_boundaries(self):
        first_rng = generator.CampaignRng(42)
        second_rng = generator.CampaignRng(42)
        first = [generator.generate_document(first_rng) for _ in range(512)]
        second = [generator.generate_document(second_rng) for _ in range(512)]

        self.assertEqual(
            [scenario.serialize_document(document) for document in first],
            [scenario.serialize_document(document) for document in second],
        )
        operations = [
            operation
            for document in first
            for item in document.scenarios
            for operation in item.operations
        ]
        self.assertEqual(
            {operation.flags for operation in operations if isinstance(operation, scenario.Pipe2)},
            set(scenario.PIPE2_FLAG_VALUES),
        )
        self.assertEqual(
            {operation.flags for operation in operations if isinstance(operation, scenario.Dup3)},
            set(scenario.DUP3_FLAG_VALUES),
        )
        self.assertEqual(
            {
                scenario.operation_name(operation)
                for operation in operations
            },
            set(analyze.OPERATION_NAMES),
        )
        vectors = [
            operation
            for operation in operations
            if isinstance(operation, (scenario.Readv, scenario.Writev))
        ]
        self.assertEqual(
            {type(operation) for operation in vectors},
            {scenario.Readv, scenario.Writev},
        )
        self.assertEqual({int(operation.iov_mode) for operation in vectors}, {0, 1})
        self.assertEqual(
            {operation.iovcnt for operation in vectors},
            set(scenario.IOVCNT_VALUES),
        )
        self.assertEqual(
            {
                int(segment.base_mode)
                for operation in vectors
                for segment in operation.segments
            },
            {0, 1},
        )
        self.assertTrue(
            all(
                sum(segment.length for segment in operation.segments)
                <= scenario.MAX_IO_BYTES
                for operation in vectors
            )
        )

        poll_many = [
            operation
            for operation in operations
            if isinstance(operation, scenario.PollMany)
        ]
        self.assertEqual(
            {len(operation.entries) for operation in poll_many},
            set(range(scenario.MAX_POLL_FDS + 1)),
        )
        self.assertEqual(
            {
                entry.fd_arg
                for operation in poll_many
                for entry in operation.entries
                if entry.fd_mode == scenario.PollFdMode.LITERAL
            },
            set(scenario.POLL_LITERAL_FDS),
        )
        slot_lists = [
            [
                entry.fd_arg
                for entry in operation.entries
                if entry.fd_mode == scenario.PollFdMode.SLOT
            ]
            for operation in poll_many
        ]
        self.assertTrue(any(len(slots) != len(set(slots)) for slots in slot_lists))
        self.assertTrue(any(len(set(slots)) >= 2 for slots in slot_lists))
        self.assertTrue(self._generated_poll_many_reaches_alias_and_closed_peer(first))

    def test_poll_many_parameter_mutation_changes_shape_fd_reference_order_and_mask(self):
        operation = scenario.PollMany(
            (
                scenario.PollFdEntry(scenario.PollFdMode.SLOT, 3, 1),
                scenario.PollFdEntry(scenario.PollFdMode.LITERAL, -2, 4),
            )
        )

        mutations = {
            family: mutation._mutate_operation_parameter(
                generator.CampaignRng(seed),
                operation,
                family,
                entry_index,
            )
            for seed, (family, entry_index) in enumerate(
                (
                    ("poll-entry-add", None),
                    ("poll-entry-delete", None),
                    ("poll-entry-duplicate", None),
                    ("poll-entry-swap", None),
                    ("poll-fd-mode", 0),
                    ("poll-fd-arg", 0),
                    ("poll-many-mask", 0),
                ),
                start=1,
            )
        }

        self.assertEqual(len(mutations["poll-entry-add"].entries), 3)
        self.assertEqual(len(mutations["poll-entry-delete"].entries), 1)
        self.assertEqual(len(mutations["poll-entry-duplicate"].entries), 3)
        self.assertEqual(
            mutations["poll-entry-swap"].entries,
            tuple(reversed(operation.entries)),
        )
        self.assertNotEqual(
            mutations["poll-fd-mode"].entries[0].fd_mode,
            operation.entries[0].fd_mode,
        )
        self.assertNotEqual(
            mutations["poll-fd-arg"].entries[0].fd_arg,
            operation.entries[0].fd_arg,
        )
        self.assertNotEqual(
            mutations["poll-many-mask"].entries[0].events,
            operation.entries[0].events,
        )
        for mutated in mutations.values():
            document = scenario.ScenarioDocument([scenario.Scenario([mutated])])
            scenario.parse_document(scenario.serialize_document(document))

    def test_mutation_repair_upgrades_to_v4_and_synthesizes_only_nonblocking_setup(self):
        unsafe_document = scenario.ScenarioDocument(
            [
                scenario.Scenario(
                    [
                        scenario.Pipe2(0, 1, 0),
                        scenario.Read(0, 8),
                    ]
                )
            ]
        )

        repaired = mutation.repair_dependencies(unsafe_document)
        encoded = scenario.serialize_document(repaired)
        operations = repaired.scenarios[0].operations

        self.assertTrue(encoded.startswith("version 4\n"))
        self.assertEqual(
            operations,
            (
                scenario.Pipe2(0, 1, 0),
                scenario.SetStatusFlags(0, scenario.O_NONBLOCK),
                scenario.Read(0, 8),
            ),
        )

    def test_mutation_repair_adds_only_nonblocking_setup_for_positive_vector_io(self):
        unsafe_document = scenario.ScenarioDocument(
            [
                scenario.Scenario(
                    [
                        scenario.Pipe2(0, 1, 0),
                        scenario.Writev(
                            1,
                            scenario.IovMode.VALID,
                            1,
                            (
                                scenario.WritevSegment(
                                    scenario.IovBaseMode.VALID,
                                    8,
                                    65,
                                ),
                            ),
                        ),
                    ]
                )
            ]
        )

        repaired = mutation.repair_dependencies(unsafe_document)

        self.assertEqual(
            repaired.scenarios[0].operations,
            (
                scenario.Pipe2(0, 1, 0),
                scenario.SetStatusFlags(1, scenario.O_NONBLOCK),
                unsafe_document.scenarios[0].operations[1],
            ),
        )
        scenario.parse_document(scenario.serialize_document(repaired))

    def test_analysis_schema_two_is_deterministic_and_satisfies_constraints(self):
        first = analyze.analyze(seed=42, samples=128, mutations=256, top=3)
        second = analyze.analyze(seed=42, samples=128, mutations=256, top=3)

        first_json = json.dumps(first, indent=2, sort_keys=True)
        second_json = json.dumps(second, indent=2, sort_keys=True)
        self.assertEqual(first_json, second_json)
        self.assertEqual(first["schema_version"], 2)
        self.assertEqual(set(first["sources"]), {"campaign_rng", "legacy_lcg"})

        for source in first["sources"].values():
            generation_report = source["generation"]
            mutation_report = source["mutation"]
            self.assertEqual(
                generation_report["samples"],
                generation_report["unique_canonical_scenarios"]
                + generation_report["duplicate_samples"],
            )
            self.assertEqual(
                mutation_report["attempts"],
                sum(mutation_report["classifications"].values()),
            )
            self.assertEqual(
                mutation_report[
                    "executable_encoded_changed_canonical_unchanged"
                ],
                0,
            )
            for canonical_scenario in generation_report["top_scenarios"]:
                self.assertEqual(
                    canonical_scenario["digest"],
                    hashlib.sha256(
                        canonical_scenario["canonical_text"].encode()
                    ).hexdigest(),
                )

    def test_analysis_is_offline_and_does_not_create_files(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "analyze.py"),
                    "--seed",
                    "7",
                    "--samples",
                    "16",
                    "--mutations",
                    "32",
                    "--top",
                    "0",
                    "--format",
                    "json",
                ],
                cwd=temporary_path,
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(temporary_path.iterdir()), [])

        with mock.patch(
            "subprocess.run",
            side_effect=AssertionError("offline analysis must not run subprocesses"),
        ):
            analyze.analyze(seed=7, samples=16, mutations=32, top=0)

    def test_malformed_candidates_are_filtered_before_host_and_qemu(self):
        malformed = mutation.MutationCandidate(
            b"version 1\nscenario generated-0001\nread 16 1\n",
            "mutate-parameter",
            mutation.CandidateClassification.MALFORMED,
            None,
            "codec:out-of-range",
            corpus.CorpusProvenance.mutated(
                "0" * 64,
                None,
                "mutate-parameter",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            with (
                mock.patch.object(fuzz, "_find_or_build_host_oracle") as find_oracle,
                mock.patch.object(fuzz, "_run_guest_compare") as run_guest,
            ):
                failed = fuzz._run_batch(
                    workspace,
                    0,
                    [malformed],
                    set(),
                    corpus.CanonicalCorpus(),
                    workspace / "failures",
                )
        self.assertFalse(failed)
        find_oracle.assert_not_called()
        run_guest.assert_not_called()

    def test_host_parser_rejection_is_not_a_differential_failure(self):
        candidate = mutation.candidate_from_document(
            scenario.parse_document(
                "version 1\nscenario x\npipe2 0 1\n"
            ),
            "generate",
        )
        stats = fuzz.CampaignStats()
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            oracle = workspace / "pipe-linux-oracle"
            oracle.write_bytes(b"oracle")
            with (
                mock.patch.object(
                    fuzz,
                    "_find_or_build_host_oracle",
                    return_value=oracle,
                ),
                mock.patch.object(
                    fuzz,
                    "_record_host",
                    return_value=fuzz.HostRecordResult(
                        False,
                        True,
                        "invalid operation",
                    ),
                ),
                mock.patch.object(fuzz, "_run_guest_compare") as run_guest,
            ):
                failed = fuzz._run_batch(
                    workspace,
                    0,
                    [candidate],
                    set(),
                    corpus.CanonicalCorpus(),
                    workspace / "failures",
                    stats,
                )
        self.assertFalse(failed)
        self.assertEqual(stats.host_parser_rejections, 1)
        run_guest.assert_not_called()

    def test_parseable_error_resource_scenario_is_host_self_consistent(self):
        corpus = (
            "version 1\n"
            "scenario errors\n"
            "pipe2 0 1\n"
            "read-null 1\n"
            "write-null 0\n"
            "read 1 1\n"
            "write 0 1 97\n"
            "get-size 0\n"
            "get-size 1\n"
            "fionread 0\n"
            "fionread 1\n"
            "close 0\n"
            "close 0\n"
            "read 0 1\n"
            "poll 2 16384\n"
            "close 1\n"
        )
        document = scenario.parse_document(corpus)
        self.assertEqual(scenario.parse_document(scenario.serialize_document(document)), document)
        self._assert_host_record_compare(scenario.serialize_document(document))

    def test_fuzz_qemu_receives_current_batch_artifact_directory(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_directory = Path(temporary_directory).resolve()
            with mock.patch.object(fuzz, "run_guest_compare") as run:
                run.return_value = ("guest", [], True)
                fuzz._run_guest_compare(WORKSPACE_ROOT, artifact_directory)
        run.assert_called_once_with(WORKSPACE_ROOT, artifact_directory, None)

    def test_fuzz_failure_reports_replayable_artifact_path(self):
        candidate = mutation.candidate_from_document(
            scenario.parse_document(
                "version 1\nscenario x\npipe2 0 1\n"
            ),
            "generate",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            oracle = workspace / "pipe-linux-oracle"
            oracle.write_bytes(b"oracle")
            failures_directory = workspace / "coverage/pipe-oracle-fuzz/failures"

            def record_host(_elf, _ops, trace):
                trace.write_bytes(b"trace")
                return fuzz.HostRecordResult(True, False, "recorded")

            output = StringIO()
            with (
                mock.patch.object(
                    fuzz,
                    "_find_or_build_host_oracle",
                    return_value=oracle,
                ),
                mock.patch.object(fuzz, "_record_host", side_effect=record_host),
                mock.patch.object(
                    fuzz,
                    "_run_guest_compare",
                    return_value=("guest log", [], False),
                ),
                mock.patch.object(fuzz, "_save_batch_failure") as save_failure,
                redirect_stdout(output),
            ):
                failed = fuzz._run_batch(
                    workspace,
                    2,
                    [candidate],
                    set(),
                    corpus.CanonicalCorpus(),
                    failures_directory,
                )

        self.assertTrue(failed)
        failure_path = save_failure.call_args.args[0]
        expected_path = failure_path.relative_to(workspace)
        self.assertIn(f"MISMATCH saved to {expected_path}", output.getvalue())
        saved_inputs = save_failure.call_args.args[1]
        self.assertEqual(next(iter(saved_inputs.values())), candidate.encoded)
        self.assertEqual(scenario.parse_document(candidate.encoded), candidate.document)

    def test_replay_qemu_receives_failure_artifact_directory(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            failure_directory = Path(temporary_directory).resolve()
            with mock.patch.object(replay, "run_guest_compare") as run:
                run.return_value = ("guest", [], True)
                replay._run_guest_compare(WORKSPACE_ROOT, failure_directory)
        run.assert_called_once_with(WORKSPACE_ROOT, failure_directory, None)

    def test_qemu_subprocess_gets_absolute_artifact_environment(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_directory = Path(temporary_directory).resolve()
            for name in ("pipe-linux-oracle", "pipe.ops", "linux.trace"):
                (artifact_directory / name).write_bytes(name.encode())
            with mock.patch("runner.subprocess.run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, "ok", "")
                from runner import run_guest_compare

                run_guest_compare(WORKSPACE_ROOT, artifact_directory)
        child_environment = run.call_args.kwargs["env"]
        self.assertEqual(child_environment[ARTIFACT_ENV], str(artifact_directory))

    def test_attribution_qemu_pins_the_saved_starry_elf(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            workspace = temporary / "workspace"
            artifact_directory = temporary / "artifacts"
            pinned_starry_elf = temporary / "saved-starryos"
            workspace.mkdir()
            artifact_directory.mkdir()
            pinned_starry_elf.write_bytes(b"saved Starry ELF")
            for name in ("pipe-linux-oracle", "pipe.ops", "linux.trace"):
                (artifact_directory / name).write_bytes(name.encode())
            with mock.patch("runner.subprocess.run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, "ok", "")
                from runner import run_guest_compare

                run_guest_compare(
                    workspace,
                    artifact_directory.resolve(),
                    pinned_starry_elf.resolve(),
                )

        child_environment = run.call_args.kwargs["env"]
        self.assertEqual(
            child_environment["AXBUILD_STARRY_KALLSYMS_SOURCE_ELF"],
            str(pinned_starry_elf.resolve()),
        )

    def test_qemu_run_does_not_reuse_a_stale_profraw(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            artifact_directory = workspace / "artifacts"
            artifact_directory.mkdir()
            for name in ("pipe-linux-oracle", "pipe.ops", "linux.trace"):
                (artifact_directory / name).write_bytes(name.encode())
            stale_profraw = workspace / "coverage/starryos-x86_64-unknown-none.profraw"
            stale_profraw.parent.mkdir(parents=True)
            stale_profraw.write_bytes(b"stale profile")

            with mock.patch("runner.subprocess.run") as run:
                run.return_value = subprocess.CompletedProcess([], 1, "failed", "")
                from runner import run_guest_compare

                _guest_log, profraws, passed = run_guest_compare(
                    workspace,
                    artifact_directory.resolve(),
                )

        self.assertFalse(passed)
        self.assertEqual(profraws, [])

    def test_cmake_external_artifacts_are_installed_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            artifact_directory = temporary_path / "artifacts"
            build_directory = temporary_path / "build"
            install_directory = temporary_path / "install"
            artifact_directory.mkdir()
            expected = {
                "pipe-linux-oracle": b"external static elf\x00",
                "pipe.ops": b"version 1\nscenario exact\npipe2 0 1\n",
                "linux.trace": b"external trace\x00\x01",
            }
            for name, contents in expected.items():
                (artifact_directory / name).write_bytes(contents)
            environment = os.environ.copy()
            environment[ARTIFACT_ENV] = str(artifact_directory.resolve())

            subprocess.run(
                [
                    "cmake",
                    "-S",
                    str(CASE_DIR / "c"),
                    "-B",
                    str(build_directory),
                    f"-DCMAKE_INSTALL_PREFIX={install_directory}",
                ],
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["cmake", "--build", str(build_directory), "--target", "install"],
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )

            installed = {
                "pipe-linux-oracle": install_directory / "usr/bin/pipe-linux-oracle",
                "pipe.ops": install_directory
                / "usr/share/starry-tests/pipe-linux-oracle/pipe.ops",
                "linux.trace": install_directory
                / "usr/share/starry-tests/pipe-linux-oracle/linux.trace",
            }
            for name, path in installed.items():
                self.assertEqual(path.read_bytes(), expected[name])

    def test_coverage_region_ids_are_stable_hashable_and_covered_only(self):
        export = {
            "data": [
                {
                    "files": [
                        {
                            "filename": "/checkout/os/StarryOS/kernel/src/file/pipe.rs",
                            "segments": [
                                [10, 2, 4, True, True, False],
                                [11, 7, 0, True, True, False],
                                [12, 3, 9, True, False, False],
                            ],
                        },
                        {
                            "filename": "/checkout/os/StarryOS/kernel/src/file/other.rs",
                            "segments": [[10, 2, 8, True, True, False]],
                        },
                        {
                            "filename": "/checkout/os/StarryOS/kernel/src/syscall/fs/pipe.rs",
                            "segments": [[20, 4, 2, True, True, False]],
                        },
                        {
                            "filename": "/checkout/os/StarryOS/kernel/src/syscall/fs/fd_ops.rs",
                            "segments": [[30, 6, 1, True, True, False]],
                        },
                        {
                            "filename": "/checkout/os/StarryOS/kernel/src/syscall/fs/io.rs",
                            "segments": [[40, 8, 3, True, True, False]],
                        },
                        {
                            "filename": "/checkout/os/StarryOS/kernel/src/mm/io.rs",
                            "segments": [[50, 9, 5, True, True, False]],
                        },
                        {
                            "filename": "/checkout/os/StarryOS/kernel/src/syscall/io_mpx/poll.rs",
                            "segments": [[60, 10, 7, True, True, False]],
                        },
                        {
                            "filename": "/checkout/os/StarryOS/kernel/src/syscall/io_mpx/mod.rs",
                            "segments": [[70, 11, 8, True, True, False]],
                        },
                    ]
                }
            ]
        }
        region_ids = coverage.covered_pipe_region_ids(export)
        self.assertEqual(
            region_ids,
            {
                "os/StarryOS/kernel/src/file/pipe.rs:10:2",
                "os/StarryOS/kernel/src/syscall/fs/pipe.rs:20:4",
                "os/StarryOS/kernel/src/syscall/fs/fd_ops.rs:30:6",
                "os/StarryOS/kernel/src/syscall/fs/io.rs:40:8",
                "os/StarryOS/kernel/src/mm/io.rs:50:9",
                "os/StarryOS/kernel/src/syscall/io_mpx/poll.rs:60:10",
                "os/StarryOS/kernel/src/syscall/io_mpx/mod.rs:70:11",
            },
        )
        self.assertEqual(
            coverage.covered_pipe_region_ids(export, coverage.VECTOR_TARGET_SET_ID),
            {
                "os/StarryOS/kernel/src/file/pipe.rs:10:2",
                "os/StarryOS/kernel/src/syscall/fs/pipe.rs:20:4",
                "os/StarryOS/kernel/src/syscall/fs/fd_ops.rs:30:6",
                "os/StarryOS/kernel/src/syscall/fs/io.rs:40:8",
                "os/StarryOS/kernel/src/mm/io.rs:50:9",
            },
        )
        self.assertEqual(
            coverage.covered_pipe_region_ids(
                export,
                coverage.FD_TARGET_SET_ID,
            ),
            {
                "os/StarryOS/kernel/src/file/pipe.rs:10:2",
                "os/StarryOS/kernel/src/syscall/fs/pipe.rs:20:4",
                "os/StarryOS/kernel/src/syscall/fs/fd_ops.rs:30:6",
            },
        )
        self.assertEqual(
            coverage.covered_pipe_region_ids(
                export,
                coverage.LEGACY_TARGET_SET_ID,
            ),
            {"os/StarryOS/kernel/src/file/pipe.rs:10:2"},
        )
        self.assertEqual(hash(frozenset(region_ids)), hash(frozenset(region_ids)))

    def test_coverage_uses_active_rust_toolchain_llvm_tools(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            target_libdir = (
                Path(temporary_directory) / "lib/rustlib/x86_64-unknown-linux-gnu/lib"
            )
            tool = target_libdir.parent / "bin/llvm-cov"
            tool.parent.mkdir(parents=True)
            tool.touch()
            with mock.patch.object(
                coverage.subprocess,
                "check_output",
                return_value=f"{target_libdir}\n",
            ):
                resolved = coverage.llvm_tool("llvm-cov")
        self.assertEqual(resolved, tool)

    def test_case_defers_detailed_failure_and_enables_coverage(self):
        qemu_config = (CASE_DIR / "qemu-x86_64.toml").read_text()
        build_config = (CASE_DIR / "build-x86_64-unknown-none.toml").read_text()
        shell_init_command = qemu_config.split(
            'shell_init_cmd = """',
            maxsplit=1,
        )[1].split('"""', maxsplit=1)[0]

        fail_regex = qemu_config.split("fail_regex = [", maxsplit=1)[1]
        self.assertNotIn("STARRY_PIPE_LINUX_ORACLE_FAILED", fail_regex)
        self.assertIn("AXTEST_COVERAGE_DEFERRED_FAIL", fail_regex)
        self.assertNotIn("AXTEST_COVERAGE_DEFERRED_FAIL", shell_init_command)
        self.assertIn('AXTEST_COVERAGE = "y"', build_config)

    def _assert_host_record_compare(self, corpus: str):
        with tempfile.TemporaryDirectory() as temporary_directory:
            corpus_path = Path(temporary_directory) / "pipe.ops"
            trace_path = Path(temporary_directory) / "linux.trace"
            corpus_path.write_text(corpus)
            recorded = subprocess.run(
                [str(self.oracle), "--record", str(corpus_path), str(trace_path)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(recorded.returncode, 0, recorded.stderr)
            compared = subprocess.run(
                [str(self.oracle), "--compare", str(corpus_path), str(trace_path)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(compared.returncode, 0, compared.stderr)
            self.assertIn("STARRY_PIPE_LINUX_ORACLE_PASSED", compared.stdout)

    def _record_host_records(self, corpus_text: str):
        class TraceHeader(ctypes.Structure):
            _fields_ = (
                ("magic", ctypes.c_ubyte * 8),
                ("version", ctypes.c_uint32),
                ("record_count", ctypes.c_uint32),
                ("corpus_digest", ctypes.c_uint64),
                ("page_size", ctypes.c_uint32),
                ("release", ctypes.c_char * 64),
                ("machine", ctypes.c_char * 32),
            )

        class OperationResult(ctypes.Structure):
            _fields_ = (
                ("scenario_index", ctypes.c_uint32),
                ("operation_index", ctypes.c_uint32),
                ("kind", ctypes.c_uint32),
                ("data_len", ctypes.c_uint32),
                ("result", ctypes.c_int64),
                ("value", ctypes.c_int64),
                ("error", ctypes.c_int32),
                ("data", ctypes.c_ubyte * scenario.MAX_IO_BYTES),
            )

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            ops = temporary / "pipe.ops"
            trace = temporary / "linux.trace"
            canonical = scenario.serialize_document(
                scenario.parse_document(corpus_text)
            )
            ops.write_text(canonical)
            recorded = subprocess.run(
                [str(self.oracle), "--record", str(ops), str(trace)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(recorded.returncode, 0, recorded.stderr)
            encoded = trace.read_bytes()

        header = TraceHeader.from_buffer_copy(encoded)
        self.assertEqual(header.version, 4)
        offset = ctypes.sizeof(TraceHeader)
        record_size = ctypes.sizeof(OperationResult)
        self.assertEqual(len(encoded), offset + header.record_count * record_size)
        return [
            OperationResult.from_buffer_copy(encoded, offset + index * record_size)
            for index in range(header.record_count)
        ]

    def _rich_parent_document(self):
        return scenario.parse_document(
            "version 1\n"
            "scenario parent\n"
            "pipe2 0 1\n"
            "write 1 4096 97\n"
            "read 0 1\n"
            "poll 0 1\n"
            "set-size 1 8192\n"
            "get-size 0\n"
            "fionread 1\n"
            "read-null 0\n"
            "write-null 1\n"
            "dup 1 2\n"
            "close 2\n"
            "pipe2 3 4\n"
            "write 4 8192 255\n"
            "read 3 4095\n"
        )

    @staticmethod
    def _generated_poll_many_reaches_alias_and_closed_peer(documents):
        alias_reached = False
        closed_peer_reached = False
        for document in documents:
            for item in document.scenarios:
                descriptions = {}
                peer_slots = {}
                closed_slots = set()
                next_description = 0
                for operation in item.operations:
                    if isinstance(operation, scenario.Pipe2) and (
                        operation.flags & ~scenario.PIPE2_ALLOWED_FLAGS == 0
                    ):
                        descriptions[operation.read_slot] = next_description
                        descriptions[operation.write_slot] = next_description + 1
                        next_description += 2
                        peer_slots[operation.read_slot] = operation.write_slot
                        peer_slots[operation.write_slot] = operation.read_slot
                    elif isinstance(operation, (scenario.Dup, scenario.Dup2, scenario.Dup3)):
                        if operation.source_slot in descriptions:
                            descriptions[operation.destination_slot] = descriptions[
                                operation.source_slot
                            ]
                    elif isinstance(operation, scenario.Close):
                        descriptions.pop(operation.slot, None)
                        closed_slots.add(operation.slot)
                    elif isinstance(operation, scenario.PollMany):
                        slots = [
                            entry.fd_arg
                            for entry in operation.entries
                            if entry.fd_mode == scenario.PollFdMode.SLOT
                        ]
                        description_ids = [
                            descriptions[slot] for slot in slots if slot in descriptions
                        ]
                        alias_reached |= len(description_ids) != len(set(description_ids))
                        closed_peer_reached |= any(
                            peer_slots.get(slot) in closed_slots for slot in slots
                        )
        return alias_reached and closed_peer_reached


if __name__ == "__main__":
    unittest.main()
