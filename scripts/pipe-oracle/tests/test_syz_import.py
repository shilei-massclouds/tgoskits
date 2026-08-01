import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/pipe-oracle"
FIXTURES = SCRIPT_DIR / "tests/fixtures/syz"
sys.path.insert(0, str(SCRIPT_DIR))

from scenario import (
    Close,
    Dup,
    Dup2,
    Dup3,
    Fionread,
    GetFdFlags,
    GetSize,
    GetStatusFlags,
    Pipe2,
    PollFdMode,
    PollMany,
    Read,
    ReadNull,
    SetFdFlags,
    SetSize,
    SetStatusFlags,
    Write,
    WriteNull,
    canonical_digest,
    serialize_document,
)
from syz_ast import (
    SyzArray,
    SyzPointer,
    SyzResource,
    SyzResultCapture,
    SyzString,
    SyzStruct,
)
from syz_converter import (
    SUPPORTED_SYZKALLER_REVISION,
    SyzConversionError,
    SyzRejectionCategory,
    convert_syz_program,
)
from syz_import import (
    MAX_SYZ_FILE_BYTES,
    build_check_report,
    conversion_log_bytes,
    write_json_report,
)
from syz_parser import SyzSyntaxCategory, SyzSyntaxError, parse_syz_program
import import_syz


class SyzParserTests(unittest.TestCase):
    def test_parses_official_numbers_comments_and_nested_result_captures(self):
        program = parse_syz_program(
            b"# leading\npipe2(&(0x7f0000000000/01000)={<r0=>0, <r1=>0x0}, 0x800) # tail\n"
        )

        self.assertEqual(len(program.calls), 1)
        call = program.calls[0]
        self.assertEqual(call.name, "pipe2")
        pointer = call.arguments[0]
        self.assertIsInstance(pointer, SyzPointer)
        self.assertEqual(pointer.address, 0x7F0000000000)
        self.assertEqual(pointer.region_size, 0o1000)
        self.assertIsInstance(pointer.value, SyzStruct)
        self.assertEqual(
            [field.name for field in pointer.value.fields],
            ["r0", "r1"],
        )
        self.assertTrue(
            all(isinstance(field, SyzResultCapture) for field in pointer.value.fields)
        )

    def test_parses_auto_string_struct_array_resource_and_result_arithmetic(self):
        program = parse_syz_program(
            b"call(&AUTO=[{r1/0x2+0x3, 'A\\x00'}], \"4142\"/4, @field=AUTO) (async)\n"
        )

        call = program.calls[0]
        pointer = call.arguments[0]
        self.assertIsInstance(pointer, SyzPointer)
        self.assertTrue(pointer.auto)
        self.assertIsInstance(pointer.value, SyzArray)
        resource = pointer.value.elements[0].fields[0]
        self.assertEqual(resource, SyzResource("r1", 2, 3))
        string = call.arguments[1]
        self.assertEqual(string, SyzString(b"AB", 4, False))
        self.assertEqual(string.effective_data(), b"AB\x00\x00")
        self.assertEqual(call.properties[0].name, "async")

    def test_rejects_malformed_syntax_with_stable_category(self):
        with self.assertRaises(SyzSyntaxError) as raised:
            parse_syz_program(b"pipe2(&AUTO={0, 0}, 0x800\n")

        self.assertEqual(raised.exception.category, SyzSyntaxCategory.INCOMPLETE_CALL)
        self.assertEqual(raised.exception.line_number, 1)

    def test_rejects_invalid_utf8(self):
        with self.assertRaises(SyzSyntaxError) as raised:
            parse_syz_program(b"pipe(\xff)\n")

        self.assertEqual(raised.exception.category, SyzSyntaxCategory.INVALID_ENCODING)


class SyzConverterTests(unittest.TestCase):
    def test_maps_every_allowlisted_call(self):
        conversion = self._convert_fixture("accepted/all_allowlisted_calls.syz")
        operations = conversion.document.scenarios[0].operations

        self.assertEqual(
            [type(operation) for operation in operations],
            [
                Pipe2,
                Write,
                Read,
                GetStatusFlags,
                GetFdFlags,
                GetSize,
                SetFdFlags,
                SetStatusFlags,
                SetSize,
                Fionread,
                PollMany,
                Dup,
                Dup2,
                Dup3,
                Close,
                Close,
                Close,
                Pipe2,
                SetStatusFlags,
                SetStatusFlags,
                ReadNull,
                WriteNull,
                Close,
                Close,
            ],
        )
        self.assertEqual(operations[0], Pipe2(0, 1, 2048))
        self.assertEqual(operations[1], Write(1, 4, ord("A")))
        self.assertEqual(operations[17], Pipe2(0, 1, 0))
        poll = operations[10]
        self.assertEqual([entry.fd_mode for entry in poll.entries], [
            PollFdMode.SLOT,
            PollFdMode.SLOT,
            PollFdMode.LITERAL,
        ])
        self.assertEqual([entry.fd_arg for entry in poll.entries], [0, 0, -1])

    def test_anchored_and_auto_conversion_is_canonical_and_deterministic(self):
        first = self._convert_fixture("accepted/anchored_and_auto.syz")
        second = self._convert_fixture("accepted/anchored_and_auto.syz")

        self.assertEqual(first, second)
        self.assertEqual(canonical_digest(first.document), canonical_digest(second.document))
        self.assertEqual(
            serialize_document(first.document),
            serialize_document(second.document),
        )

    def test_distinguishes_valid_and_invalid_zero_length_pointers(self):
        conversion = self._convert(
            "pipe2(&AUTO={<r0=>0, <r1=>0}, 0x800)\n"
            "read(r0, &AUTO=\"\"/0, 0)\n"
            "read(r0, 0x0, 0)\n"
            "write(r1, &AUTO='', 0)\n"
            "write(r1, 0x1, 0)\n"
        )

        self.assertEqual(
            [type(operation) for operation in conversion.document.scenarios[0].operations],
            [Pipe2, Read, ReadNull, Write, WriteNull],
        )

    def test_preserves_poll_order_duplicates_and_literals(self):
        conversion = self._convert(
            "pipe2(&AUTO={<r0=>0, <r1=>0}, 0x800)\n"
            "poll(&AUTO=[{r0, 1, 0}, {r0, 4, 0}, "
            "{0xfffffffffffffffe, 0, 0}, {0x7fffffff, 0, 0}], 4, 0)\n"
        )
        poll = conversion.document.scenarios[0].operations[1]

        self.assertEqual(
            [(entry.fd_mode, entry.fd_arg, entry.events) for entry in poll.entries],
            [
                (PollFdMode.SLOT, 0, 1),
                (PollFdMode.SLOT, 0, 4),
                (PollFdMode.LITERAL, -2, 0),
                (PollFdMode.LITERAL, 2147483647, 0),
            ],
        )

    def test_rejection_categories_are_stable(self):
        cases = {
            SyzRejectionCategory.PSEUDO_SYSCALL: "syz_execute_func(0)\n",
            SyzRejectionCategory.CALL_PROPERTIES: "pipe(&AUTO={0, 0}) (async)\n",
            SyzRejectionCategory.UNSUPPORTED_CALL: "ppoll(&AUTO=[], 0, 0, 0, 0)\n",
            SyzRejectionCategory.RESOURCE_ARITHMETIC: (
                "pipe2(&AUTO={<r0=>0, <r1=>0}, 0x800)\nclose(r0+1)\n"
            ),
            SyzRejectionCategory.UNDEFINED_RESOURCE: "close(r9)\n",
            SyzRejectionCategory.USE_AFTER_CLOSE: (
                "pipe2(&AUTO={<r0=>0, <r1=>0}, 0x800)\nclose(r0)\nclose(r0)\n"
            ),
            SyzRejectionCategory.DUPLICATE_RESULT: (
                "pipe2(&AUTO={<r0=>0, <r1=>0}, 0x800)\nr0 = dup(r1)\n"
            ),
            SyzRejectionCategory.NON_UNIFORM_PAYLOAD: (
                "pipe2(&AUTO={<r0=>0, <r1=>0}, 0x800)\n"
                "write(r1, &AUTO='AB', 2)\n"
            ),
            SyzRejectionCategory.BLOCKING_IO: (
                "pipe(&AUTO={<r0=>0, <r1=>0})\nread(r0, &AUTO=\"\"/1, 1)\n"
            ),
            SyzRejectionCategory.MEMORY_OVERLAP: (
                "pipe2(&(0x7f0000000000)={<r0=>0, <r1=>0}, 0x800)\n"
                "write(r1, &(0x7f0000000004)='AAAA', 4)\n"
            ),
            SyzRejectionCategory.POLL_SHAPE: (
                "poll(&AUTO=[], 0, 1)\n"
            ),
        }
        for category, encoded in cases.items():
            with self.subTest(category=category):
                with self.assertRaises(SyzConversionError) as raised:
                    self._convert(encoded)
                self.assertEqual(raised.exception.category, category)

    def test_rejects_operation_and_slot_limits(self):
        too_many_operations = "\n".join("close(0xffffffffffffffff)" for _ in range(33))
        with self.assertRaises(SyzConversionError) as raised:
            self._convert(too_many_operations + "\n")
        self.assertEqual(raised.exception.category, SyzRejectionCategory.ENTRY_LIMIT)

        pipes = []
        for index in range(9):
            pipes.append(
                f"pipe2(&AUTO={{<r{index * 2}=>0, <r{index * 2 + 1}=>0}}, 0x800)"
            )
        with self.assertRaises(SyzConversionError) as raised:
            self._convert("\n".join(pipes) + "\n")
        self.assertEqual(raised.exception.category, SyzRejectionCategory.SLOT_LIMIT)

    def _convert_fixture(self, relative: str):
        return convert_syz_program(parse_syz_program((FIXTURES / relative).read_bytes()))

    def _convert(self, encoded: str):
        return convert_syz_program(parse_syz_program(encoded.encode()))


class SyzCheckCliTests(unittest.TestCase):
    def test_classifies_accepts_rejections_and_deduplicates_paths(self):
        report, infrastructure_failed = build_check_report(
            [FIXTURES, FIXTURES / "accepted/all_allowlisted_calls.syz"],
            SUPPORTED_SYZKALLER_REVISION,
        )

        self.assertFalse(infrastructure_failed)
        self.assertEqual(report["summary"]["total_inputs"], 4)
        self.assertEqual(report["summary"]["accepted"], 2)
        self.assertEqual(report["summary"]["rejected"], 2)
        self.assertEqual(
            report["summary"]["rejection_categories"],
            {"memory-overlap": 1, "unsupported-call": 1},
        )

    def test_rejects_symlink_and_file_size_without_reading_corpus(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            target = temporary / "target.syz"
            target.write_text("close(0xffffffffffffffff)\n")
            link = temporary / "link.syz"
            link.symlink_to(target)
            large = temporary / "large.syz"
            large.write_bytes(b"#" * (MAX_SYZ_FILE_BYTES + 1))

            report, infrastructure_failed = build_check_report(
                [temporary],
                SUPPORTED_SYZKALLER_REVISION,
            )

        self.assertFalse(infrastructure_failed)
        categories = {
            Path(input_report["path"]).name: input_report["rejection_category"]
            for input_report in report["inputs"]
        }
        self.assertEqual(categories["link.syz"], "symlink")
        self.assertEqual(categories["large.syz"], "file-too-large")
        self.assertEqual(categories["target.syz"], None)

    def test_report_write_is_atomic_and_deterministic(self):
        report, _failed = build_check_report(
            [FIXTURES / "accepted/anchored_and_auto.syz"],
            SUPPORTED_SYZKALLER_REVISION,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "nested/report.json"
            write_json_report(path, report)
            first = path.read_bytes()
            write_json_report(path, report)
            second = path.read_bytes()

        self.assertEqual(first, second)
        self.assertEqual(json.loads(first), report)

    def test_conversion_log_digest_is_path_independent(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first = root / "first.syz"
            second = root / "second.syz"
            encoded = (FIXTURES / "accepted/anchored_and_auto.syz").read_bytes()
            first.write_bytes(encoded)
            second.write_bytes(encoded)
            report, failed = build_check_report(
                (second, first),
                SUPPORTED_SYZKALLER_REVISION,
            )

        self.assertFalse(failed)
        first_report, second_report = report["inputs"]
        self.assertEqual(
            first_report["conversion_log_sha256"],
            second_report["conversion_log_sha256"],
        )
        self.assertEqual(
            conversion_log_bytes(first_report, SUPPORTED_SYZKALLER_REVISION),
            conversion_log_bytes(second_report, SUPPORTED_SYZKALLER_REVISION),
        )

    def test_cli_rejections_return_zero_and_print_json(self):
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "import_syz.py"),
                "--syzkaller-revision",
                SUPPORTED_SYZKALLER_REVISION,
                str(FIXTURES / "rejected/unsupported_call.syz"),
            ],
            cwd=WORKSPACE_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["summary"]["rejected"], 1)

    def test_check_only_cli_does_not_create_workspace_corpus(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            source = workspace / "accepted.syz"
            source.write_bytes(
                (FIXTURES / "accepted/anchored_and_auto.syz").read_bytes()
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "import_syz.py"),
                    "--syzkaller-revision",
                    SUPPORTED_SYZKALLER_REVISION,
                    "--workspace",
                    str(workspace),
                    str(source),
                ],
                cwd=WORKSPACE_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((workspace / "coverage/pipe-oracle-fuzz").exists())

    def test_admit_cli_reports_terminal_failure_with_nonzero_status(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            source = workspace / "accepted.syz"
            source.write_bytes(
                (FIXTURES / "accepted/anchored_and_auto.syz").read_bytes()
            )
            admission = {
                "schema_version": 1,
                "jobs": [],
                "summary": {
                    "jobs": 1,
                    "failed": 1,
                    "host_stable": 1,
                    "host_unstable": 0,
                    "qemu_runs": 1,
                    "new_regions": [],
                    "admitted_digests": [],
                },
            }
            arguments = [
                "import_syz.py",
                "--syzkaller-revision",
                SUPPORTED_SYZKALLER_REVISION,
                "--workspace",
                str(workspace),
                "--admit",
                str(source),
            ]
            output = io.StringIO()
            with (
                mock.patch.object(sys, "argv", arguments),
                mock.patch.object(import_syz, "run_admission", return_value=admission),
                contextlib.redirect_stdout(output),
            ):
                status = import_syz.main()

            self.assertEqual(status, 1)
            report = json.loads(output.getvalue())
            self.assertEqual(report["mode"], "admit")
            self.assertEqual(report["admission"], admission)

    @unittest.skipUnless(
        os.environ.get("SYZKALLER_CHECKOUT"),
        "set SYZKALLER_CHECKOUT to validate fixtures with pinned syz-prog2c",
    )
    def test_pinned_upstream_parser_accepts_accepted_fixtures(self):
        checkout = Path(os.environ["SYZKALLER_CHECKOUT"])
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=checkout,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        self.assertEqual(revision, SUPPORTED_SYZKALLER_REVISION)
        tool = checkout / "bin/syz-prog2c"
        self.assertTrue(tool.is_file(), "build the pinned syz-prog2c before this test")
        for fixture in sorted((FIXTURES / "accepted").glob("*.syz")):
            with self.subTest(fixture=fixture.name):
                result = subprocess.run(
                    [
                        str(tool),
                        "-os",
                        "linux",
                        "-arch",
                        "amd64",
                        "-strict",
                        "-prog",
                        str(fixture),
                    ],
                    cwd=checkout,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
