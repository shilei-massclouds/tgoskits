import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/pipe-oracle"
FIXTURES = SCRIPT_DIR / "tests/fixtures/syz"
sys.path.insert(0, str(SCRIPT_DIR))

from scenario import (  # noqa: E402
    Dup,
    Pipe2,
    SetStatusFlags,
    Writev,
    parse_document,
)
from syz_converter import SUPPORTED_SYZKALLER_REVISION  # noqa: E402
from syz_import import (  # noqa: E402
    build_check_report,
    conversion_log_bytes,
)


class SyzProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_default_v2_report_and_conversion_are_byte_compatible(self):
        source = FIXTURES / "accepted/vector_io.syz"

        report, failed = build_check_report(
            (source,),
            SUPPORTED_SYZKALLER_REVISION,
        )

        self.assertFalse(failed)
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(report["importer_version"], "2")
        input_report = report["inputs"][0]
        self.assertEqual(
            input_report["canonical_digest"],
            "994bcc59286fd9de3cd7d6223772e64d7af59e8872f324fe6ea05f25bc29142e",
        )
        self.assertEqual(
            input_report["conversion_log_sha256"],
            "1c8b0c49dcfc6e688353516124e31e71173fa34a07212df48f82984d40a0b295",
        )
        normalized = copy.deepcopy(report)
        normalized["inputs"][0]["path"] = "<PATH>"
        encoded = (json.dumps(normalized, indent=2, sort_keys=True) + "\n").encode()
        self.assertEqual(
            hashlib.sha256(encoded).hexdigest(),
            "4cf8ec497a6aaaf79ce30e2753b216f798cdb1a45a8ae1bc7555bb123f95b8e9",
        )

    def test_opt_in_prefers_lossless_conversion_without_projection(self):
        source = FIXTURES / "accepted/vector_io.syz"

        report, failed = build_check_report(
            (source,),
            SUPPORTED_SYZKALLER_REVISION,
            project_vector_slices=True,
        )

        self.assertFalse(failed)
        self.assertEqual(report["schema_version"], 3)
        self.assertEqual(report["importer_version"], "3")
        input_report = report["inputs"][0]
        self.assertEqual(input_report["conversion_kind"], "lossless")
        self.assertFalse(input_report["projection"]["attempted"])
        self.assertEqual(input_report["projection"]["targets"], [])
        self.assertEqual(
            input_report["canonical_digest"],
            "994bcc59286fd9de3cd7d6223772e64d7af59e8872f324fe6ea05f25bc29142e",
        )

    def test_projects_unrelated_calls_and_repairs_pipe_outputs_and_flags(self):
        report = self._project(
            "r9 = socket(0, 0, 0)\n"
            "pipe2(&AUTO={<r0=>0x55, <r1=>0xaa}, 0x80000)\n"
            "writev(r1, &AUTO=[{&AUTO='AA', 2}], 1)\n"
        )

        input_report = report["inputs"][0]
        self.assertEqual(input_report["status"], "accepted")
        self.assertEqual(input_report["conversion_kind"], "projected")
        document = parse_document(input_report["canonical_pipe_ops"].encode())
        self.assertEqual(len(document.scenarios), 1)
        self.assertEqual(document.scenarios[0].operations[0], Pipe2(0, 1, 526336))
        self.assertIsInstance(document.scenarios[0].operations[1], Writev)
        target = input_report["projection"]["targets"][0]
        self.assertEqual(target["status"], "accepted")
        self.assertEqual(target["dropped_calls"][0]["syz_call"], "socket")
        self.assertEqual(
            target["retained_calls"][0]["repair_reasons"],
            ["normalize-pipe-flags", "zero-pipe-output"],
        )

    def test_restores_nonblocking_before_next_positive_io(self):
        report = self._project(
            "pipe2(&AUTO={<r0=>0, <r1=>0}, 0)\n"
            "fcntl$setstatus(r1, 4, 0)\n"
            "writev(r1, &AUTO=[{&AUTO='A', 1}], 1)\n"
        )

        document = parse_document(
            report["inputs"][0]["canonical_pipe_ops"].encode()
        )
        self.assertEqual(
            document.scenarios[0].operations,
            (
                Pipe2(0, 1, 2048),
                SetStatusFlags(1, 0),
                SetStatusFlags(1, 2048),
                Writev(1, 0, 1, document.scenarios[0].operations[-1].segments),
            ),
        )
        target = report["inputs"][0]["projection"]["targets"][0]
        self.assertEqual(
            target["synthesized_calls"],
            [
                {
                    "before_line": 3,
                    "pipe_operation": "set-status-flags 1 2048",
                    "reason": "restore-nonblocking",
                    "syz_call": "fcntl$setstatus",
                }
            ],
        )

    def test_preserves_dup_resource_producer_chain(self):
        report = self._project(
            "pipe(&AUTO={<r0=>0, <r1=>0})\n"
            "r2 = dup(r1)\n"
            "writev(r2, &AUTO=[{&AUTO='A', 1}], 1)\n"
        )

        operations = parse_document(
            report["inputs"][0]["canonical_pipe_ops"].encode()
        ).scenarios[0].operations
        self.assertEqual(operations[0], Pipe2(0, 1, 2048))
        self.assertEqual(operations[1], Dup(1, 2))
        self.assertIsInstance(operations[2], Writev)

    def test_rejects_unsupported_tainted_resource_and_call_properties(self):
        cases = {
            "unsupported-resource-call": (
                "pipe(&AUTO={<r0=>0, <r1=>0})\n"
                "splice(r1, 0, 0, 0, 1, 0)\n"
                "writev(r1, &AUTO=[{&AUTO='A', 1}], 1)\n"
            ),
            "call-properties": (
                "pipe(&AUTO={<r0=>0, <r1=>0})\n"
                "fcntl$setstatus(r1, 4, 0) (async)\n"
                "writev(r1, &AUTO=[{&AUTO='A', 1}], 1)\n"
            ),
        }
        for category, source in cases.items():
            with self.subTest(category=category):
                target = self._project(source)["inputs"][0]["projection"]["targets"][0]
                self.assertEqual(target["status"], "rejected")
                self.assertEqual(target["rejection_category"], category)

    def test_rejects_unrelated_arithmetic_external_dup_and_use_after_close(self):
        cases = {
            "unrelated-vector": (
                "r0 = socket(0, 0, 0)\n"
                "writev(r0, &AUTO=[{&AUTO='A', 1}], 1)\n"
            ),
            "resource-arithmetic": (
                "pipe(&AUTO={<r0=>0, <r1=>0})\n"
                "writev(r1+1, &AUTO=[{&AUTO='A', 1}], 1)\n"
            ),
            "external-dup-resource": (
                "r9 = socket(0, 0, 0)\n"
                "pipe(&AUTO={<r0=>0, <r1=>0})\n"
                "dup2(r1, r9)\n"
                "writev(r9, &AUTO=[{&AUTO='A', 1}], 1)\n"
            ),
            "use-after-close": (
                "pipe(&AUTO={<r0=>0, <r1=>0})\n"
                "close(r1)\n"
                "writev(r1, &AUTO=[{&AUTO='A', 1}], 1)\n"
            ),
        }
        for category, source in cases.items():
            with self.subTest(category=category):
                input_report = self._project(source)["inputs"][0]
                self.assertEqual(input_report["status"], "rejected")
                target = input_report["projection"]["targets"][0]
                self.assertEqual(target["rejection_category"], category)

    def test_does_not_repair_vector_payload_shape_or_aliases(self):
        cases = {
            "vector-shape": (
                "pipe(&AUTO={<r0=>0, <r1=>0})\n"
                "writev(r1, &AUTO=[], 1)\n"
            ),
            "non-uniform-payload": (
                "pipe(&AUTO={<r0=>0, <r1=>0})\n"
                "writev(r1, &AUTO=[{&AUTO='AB', 2}], 1)\n"
            ),
            "memory-overlap": (
                "pipe(&(0x7f0000000000)={<r0=>0, <r1=>0})\n"
                "writev(r1, &(0x7f0000001000)=["
                "{&(0x7f0000001008)='A', 1}], 1)\n"
            ),
        }
        for category, source in cases.items():
            with self.subTest(category=category):
                input_report = self._project(source)["inputs"][0]
                self.assertEqual(input_report["status"], "rejected")
                target = input_report["projection"]["targets"][0]
                self.assertEqual(target["rejection_category"], category)

    def test_orders_targets_deduplicates_scenarios_and_reports_summary(self):
        report = self._project(
            "socket(0, 0, 0)\n"
            "pipe(&AUTO={<r0=>0, <r1=>0})\n"
            "writev(r1, &AUTO=[{&AUTO='A', 1}], 1)\n"
            "pipe(&AUTO={<r2=>0, <r3=>0})\n"
            "writev(r3, &AUTO=[{&AUTO='A', 1}], 1)\n"
            "pipe(&AUTO={<r4=>0, <r5=>0})\n"
            "writev(r5, &AUTO=[{&AUTO='BB', 2}], 1)\n"
        )

        input_report = report["inputs"][0]
        document = parse_document(input_report["canonical_pipe_ops"].encode())
        self.assertEqual(len(document.scenarios), 2)
        targets = input_report["projection"]["targets"]
        self.assertEqual([target["line"] for target in targets], [3, 5, 7])
        self.assertEqual(
            [target["status"] for target in targets],
            ["accepted", "duplicate", "accepted"],
        )
        self.assertEqual(
            report["summary"]["projection_targets"],
            {"accepted": 2, "duplicate": 1, "rejected": 0},
        )
        self.assertGreater(report["summary"]["projection_transformations"]["dropped"], 0)

    def test_rejects_the_complete_source_above_four_distinct_scenarios(self):
        calls = ["socket(0, 0, 0)"]
        for index in range(5):
            calls.extend(
                (
                    f"pipe(&AUTO={{<r{index * 2}=>0, <r{index * 2 + 1}=>0}})",
                    f"writev(r{index * 2 + 1}, &AUTO=[{{&AUTO='{'A' * (index + 1)}', "
                    f"{index + 1}}}], 1)",
                )
            )

        input_report = self._project("\n".join(calls) + "\n")["inputs"][0]

        self.assertEqual(input_report["status"], "rejected")
        self.assertEqual(input_report["rejection_category"], "projection-entry-limit")
        self.assertIsNone(input_report["canonical_pipe_ops"])

    def test_projection_is_deterministic_and_conversion_log_is_path_independent(self):
        encoded = (
            "socket(0, 0, 0)\n"
            "pipe(&AUTO={<r0=>7, <r1=>9})\n"
            "writev(r1, &AUTO=[{&AUTO='A', 1}], 1)\n"
        )
        first = self.root / "first.syz"
        second = self.root / "second.syz"
        first.write_text(encoded)
        second.write_text(encoded)

        report, failed = build_check_report(
            (second, first),
            SUPPORTED_SYZKALLER_REVISION,
            project_vector_slices=True,
        )

        self.assertFalse(failed)
        first_report, second_report = report["inputs"]
        self.assertEqual(
            first_report["canonical_pipe_ops"],
            second_report["canonical_pipe_ops"],
        )
        self.assertEqual(
            first_report["conversion_log_sha256"],
            second_report["conversion_log_sha256"],
        )
        self.assertEqual(
            conversion_log_bytes(
                first_report,
                SUPPORTED_SYZKALLER_REVISION,
                importer_version="3",
            ),
            conversion_log_bytes(
                second_report,
                SUPPORTED_SYZKALLER_REVISION,
                importer_version="3",
            ),
        )

    def test_cli_selects_schema_v3_only_with_projection_flag(self):
        source = self.root / "mixed.syz"
        source.write_text(
            "socket(0, 0, 0)\n"
            "pipe(&AUTO={<r0=>0, <r1=>0})\n"
            "writev(r1, &AUTO=[{&AUTO='A', 1}], 1)\n"
        )
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "import_syz.py"),
                "--syzkaller-revision",
                SUPPORTED_SYZKALLER_REVISION,
                "--project-vector-slices",
                str(source),
            ],
            cwd=WORKSPACE_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["schema_version"], 3)
        self.assertEqual(report["inputs"][0]["conversion_kind"], "projected")

    def _project(self, encoded: str):
        source = self.root / "input.syz"
        source.write_text(encoded)
        report, failed = build_check_report(
            (source,),
            SUPPORTED_SYZKALLER_REVISION,
            project_vector_slices=True,
        )
        self.assertFalse(failed)
        return report


if __name__ == "__main__":
    unittest.main()
