import json
import sys
import tempfile
import unittest
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/pipe-oracle"
sys.path.insert(0, str(SCRIPT_DIR))

from corpus_errors import CorpusValidationError  # noqa: E402
from import_store import ImportStore  # noqa: E402
from syz_converter import (  # noqa: E402
    IMPORTER_VERSION,
    SUPPORTED_SYZKALLER_REVISION,
)
from syz_import import build_check_report  # noqa: E402


class ImportJobPersistenceTests(unittest.TestCase):
    def test_job_persists_every_source_and_resumes_atomic_batch_progress(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            accepted_first = workspace / "a.syz"
            accepted_second = workspace / "b.syz"
            rejected = workspace / "rejected.syz"
            accepted_first.write_text("pipe(&(0x7f0000000000)={<r0=>0, <r1=>0})\n")
            accepted_second.write_bytes(accepted_first.read_bytes())
            rejected.write_text("socket(0, 0, 0)\n")
            report, failed = build_check_report(
                (accepted_second, rejected, accepted_first),
                SUPPORTED_SYZKALLER_REVISION,
            )
            self.assertFalse(failed)

            store = ImportStore(workspace)
            job = store.create_job(
                "import-0001",
                reports=report["inputs"],
                syzkaller_revision=SUPPORTED_SYZKALLER_REVISION,
                importer_version=IMPORTER_VERSION,
                host_repetitions=3,
                batch_size=8,
                max_qemu=64,
            )

            self.assertEqual(len(job.metadata["sources"]), 3)
            self.assertEqual(len(job.metadata["canonical_inputs"]), 1)
            canonical = job.metadata["canonical_inputs"][0]
            self.assertEqual(canonical["source_evidence_ids"], ["000000", "000001"])
            self.assertEqual(
                sorted(path.name for path in (job.path / "sources").iterdir()),
                ["000000.syz", "000001.syz", "000002.syz"],
            )
            self.assertEqual(
                sorted(path.name for path in (job.path / "conversions").iterdir()),
                ["000000.json", "000001.json", "000002.json"],
            )

            digest = canonical["digest"]
            provenance = store.provenance(job, digest)
            self.assertEqual(provenance.source, "syzkaller-import")
            self.assertEqual(len(provenance.external_sources), 1)
            store.begin_host_stability(job.job_id)
            store.record_host_result(
                job.job_id,
                digest,
                stable=True,
                trace_sha256="a" * 64,
                duration_seconds=0.25,
            )
            store.configure_batches(job.job_id, ((digest,),))
            store.record_batch_result(
                job.job_id,
                0,
                result_category="passed-no-new-coverage",
                qemu_runs=1,
                duration_seconds=0.5,
            )
            resumed = store.load_job(job.job_id)
            self.assertEqual(resumed.metadata["next_batch_index"], 1)
            self.assertEqual(resumed.metadata["qemu_runs"], 1)
            self.assertEqual(resumed.metadata["duration_seconds"], 0.75)

            orphan = store.jobs_dir / ".interrupted.tmp-orphan"
            orphan.mkdir()
            self.assertEqual(
                [saved.job_id for saved in store.load_resumable_jobs()],
                [job.job_id],
            )
            store.finish(job.job_id, result_category="completed")
            self.assertEqual(
                [saved.job_id for saved in store.load_resumable_jobs()],
                [job.job_id],
            )
            store.mark_run_recorded(job.job_id)
            self.assertEqual(store.load_resumable_jobs(), [])

    def test_unknown_schema_and_conversion_digest_corruption_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            source = workspace / "input.syz"
            source.write_text("pipe(&(0x7f0000000000)={<r0=>0, <r1=>0})\n")
            report, failed = build_check_report(
                (source,),
                SUPPORTED_SYZKALLER_REVISION,
            )
            self.assertFalse(failed)
            store = ImportStore(workspace)
            job = store.create_job(
                "import-corrupt",
                reports=report["inputs"],
                syzkaller_revision=SUPPORTED_SYZKALLER_REVISION,
                importer_version=IMPORTER_VERSION,
                host_repetitions=3,
                batch_size=8,
                max_qemu=1,
            )
            metadata_path = job.path / "metadata.json"
            original = metadata_path.read_text()
            metadata = json.loads(original)
            metadata["schema_version"] = 2
            metadata_path.write_text(json.dumps(metadata))
            with self.assertRaisesRegex(CorpusValidationError, "unsupported import-job schema"):
                store.load_job(job.job_id)

            metadata_path.write_text(original)
            conversion = next((job.path / "conversions").iterdir())
            conversion.write_bytes(conversion.read_bytes() + b"corrupt")
            with self.assertRaisesRegex(CorpusValidationError, "conversion log digest mismatch"):
                store.load_job(job.job_id)


if __name__ == "__main__":
    unittest.main()
