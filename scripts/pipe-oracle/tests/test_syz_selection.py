import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/pipe-oracle"
FIXTURES = SCRIPT_DIR / "tests/fixtures/syz"
sys.path.insert(0, str(SCRIPT_DIR))

from syz_converter import SUPPORTED_SYZKALLER_REVISION
from syz_import import build_check_report


class SyzAdmissionSelectionTests(unittest.TestCase):
    def test_reports_unlimited_canonical_digest_selection(self):
        report, infrastructure_failed = build_check_report(
            (FIXTURES,),
            SUPPORTED_SYZKALLER_REVISION,
        )

        self.assertFalse(infrastructure_failed)
        self.assertEqual(report["schema_version"], 2)
        accepted_digests = sorted(
            input_report["canonical_digest"]
            for input_report in report["inputs"]
            if input_report["status"] == "accepted"
        )
        self.assertEqual(
            report["admission_selection"],
            {
                "policy": "canonical-digest",
                "max_unique": None,
                "eligible_unique": 4,
                "selected_unique": 4,
                "deferred_unique": 0,
                "selected_digests": accepted_digests,
                "deferred_digests": [],
            },
        )

    def test_selects_a_canonical_digest_prefix_and_keeps_all_classifications(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for index in range(3):
                payload = chr(ord("A") + index) * index
                (root / f"{index}.syz").write_text(
                    "pipe2(&AUTO={<r0=>0, <r1=>0}, 0x800)\n"
                    f"write(r1, &AUTO='{payload}', {index})\n"
                )
            duplicate = root / "duplicate.syz"
            duplicate.write_bytes((root / "0.syz").read_bytes())
            rejected = root / "rejected.syz"
            rejected.write_text("socket(0, 0, 0)\n")

            report, failed = build_check_report(
                (root,),
                SUPPORTED_SYZKALLER_REVISION,
                max_admit_unique=2,
            )

        self.assertFalse(failed)
        self.assertEqual(report["summary"]["total_inputs"], 5)
        self.assertEqual(report["summary"]["accepted"], 4)
        eligible = sorted(
            {
                input_report["canonical_digest"]
                for input_report in report["inputs"]
                if input_report["status"] == "accepted"
            }
        )
        selection = report["admission_selection"]
        self.assertEqual(selection["selected_digests"], eligible[:2])
        self.assertEqual(selection["deferred_digests"], eligible[2:])
        self.assertEqual(selection["eligible_unique"], 3)
        self.assertEqual(selection["selected_unique"], 2)
        self.assertEqual(selection["deferred_unique"], 1)

    def test_rejects_nonpositive_admission_limit(self):
        for value in (0, -1, True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    build_check_report(
                        (FIXTURES / "accepted/upstream_pipe.syz",),
                        SUPPORTED_SYZKALLER_REVISION,
                        max_admit_unique=value,
                    )

    def test_cli_requires_admit_for_max_unique_and_a_positive_limit(self):
        base = [
            str(SCRIPT_DIR / "import_syz.py"),
            "--syzkaller-revision",
            SUPPORTED_SYZKALLER_REVISION,
        ]
        fixture = str(FIXTURES / "accepted/upstream_pipe.syz")
        invalid_options = (
            ("--max-admit-unique", "1"),
            ("--admit", "--max-admit-unique", "0"),
        )
        for extra in invalid_options:
            with self.subTest(extra=extra):
                result = subprocess.run(
                    [sys.executable, *base, *extra, fixture],
                    cwd=WORKSPACE_ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
