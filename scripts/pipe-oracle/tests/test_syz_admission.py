import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/pipe-oracle"

import sys

sys.path.insert(0, str(SCRIPT_DIR))

from artifact import validate_failure  # noqa: E402
from attribution_campaign import (  # noqa: E402
    AttributionReplayRuntime,
    resume_attribution_job,
)
from batch_execution import HostRecordResult  # noqa: E402
from corpus import CanonicalCorpus, CorpusStore  # noqa: E402
from guest_result import (  # noqa: E402
    GuestExecutionResult,
    GuestResultCategory,
    classify_guest_execution,
)
from import_store import ImportStore  # noqa: E402
from minimization_campaign import (  # noqa: E402
    MinimizationRuntime,
    resume_minimization_job,
)
from minimization_source import create_or_load_job_from_source  # noqa: E402
from minimization_store import MinimizationStore  # noqa: E402
from syz_admission import (  # noqa: E402
    AdmissionRuntime,
    AttributionAdmissionOutcome,
    run_admission,
)
from syz_converter import SUPPORTED_SYZKALLER_REVISION  # noqa: E402
from syz_import import build_check_report  # noqa: E402


class AdmissionHarness:
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.host_oracle = workspace / "pipe-linux-oracle"
        shutil.copy2(Path(sys.executable).resolve(), self.host_oracle)
        self.starry_elf = workspace / "starryos"
        shutil.copy2(Path(sys.executable).resolve(), self.starry_elf)
        self.record_calls = 0
        self.guest_calls = 0
        self.find_calls = 0
        self.trace_for_call = lambda _call: b"stable trace\n"
        self.guest_result_for_call = self._passed_guest
        self.extract_regions = lambda _profraws, _elf: set()
        self.resume_attribution = self._unexpected_attribution
        self.run_minimization = self._unexpected_minimization

    def runtime(self) -> AdmissionRuntime:
        return AdmissionRuntime(
            find_host_oracle=self._find_host,
            record_host=self._record_host,
            run_guest_compare=self._run_guest,
            coverage_object=lambda _workspace: self.starry_elf,
            extract_regions=self.extract_regions,
            load_active_corpus=lambda _store: CanonicalCorpus(),
            resume_attribution=self.resume_attribution,
            run_minimization=self.run_minimization,
            resume_global_jobs=lambda _workspace, _store, _command, _max_qemu: False,
        )

    def _find_host(self, _workspace: Path) -> Path:
        self.find_calls += 1
        return self.host_oracle

    def _record_host(self, _elf: Path, _ops: Path, trace: Path) -> HostRecordResult:
        self.record_calls += 1
        trace.write_bytes(self.trace_for_call(self.record_calls))
        return HostRecordResult(True, False, "host passed")

    def _run_guest(
        self,
        _workspace: Path,
        artifact_dir: Path,
        _pinned_starry_elf: Path,
    ) -> GuestExecutionResult:
        self.guest_calls += 1
        return self.guest_result_for_call(self.guest_calls, artifact_dir)

    @staticmethod
    def _passed_guest(_call: int, artifact_dir: Path) -> GuestExecutionResult:
        profraw = artifact_dir / "default.profraw"
        profraw.write_bytes(b"profile")
        return GuestExecutionResult(
            GuestResultCategory.PASSED,
            "guest passed\n",
            (profraw,),
            0,
        )

    @staticmethod
    def _unexpected_attribution(*_args):
        raise AssertionError("attribution should not run")

    @staticmethod
    def _unexpected_minimization(*_args):
        raise AssertionError("minimization should not run")


class SyzAdmissionTests(unittest.TestCase):
    def test_stable_input_without_new_coverage_is_not_admitted(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            report = _accepted_report(workspace)
            harness = AdmissionHarness(workspace)

            admission = _admit(workspace, report, harness)

            self.assertEqual(admission["summary"]["failed"], 0)
            self.assertEqual(admission["summary"]["host_stable"], 1)
            self.assertEqual(admission["summary"]["qemu_runs"], 1)
            self.assertEqual(
                admission["jobs"][0]["result"],
                "passed-no-new-coverage",
            )
            self.assertEqual(harness.record_calls, 4)
            self.assertEqual(harness.guest_calls, 1)
            self.assertEqual(len(CorpusStore(workspace).load_corpus()), 0)
            job = ImportStore(workspace).load_resumable_jobs()
            self.assertEqual(job, [])

    def test_unstable_host_trace_skips_qemu(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            report = _accepted_report(workspace)
            harness = AdmissionHarness(workspace)
            harness.trace_for_call = lambda call: f"trace {call}\n".encode()

            admission = _admit(workspace, report, harness)

            self.assertEqual(admission["summary"]["host_stable"], 0)
            self.assertEqual(admission["summary"]["host_unstable"], 1)
            self.assertEqual(admission["summary"]["qemu_runs"], 0)
            self.assertEqual(admission["jobs"][0]["result"], "no-host-stable-input")
            self.assertEqual(harness.record_calls, 3)
            self.assertEqual(harness.guest_calls, 0)

    def test_no_accepted_input_does_not_build_or_run(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            rejected = workspace / "rejected.syz"
            rejected.write_text("socket(0, 0, 0)\n")
            report, failed = build_check_report(
                (rejected,),
                SUPPORTED_SYZKALLER_REVISION,
            )
            self.assertFalse(failed)
            harness = AdmissionHarness(workspace)

            admission = _admit(workspace, report, harness)

            self.assertEqual(admission["jobs"][0]["result"], "no-accepted-input")
            self.assertEqual(harness.find_calls, 0)
            self.assertEqual(harness.record_calls, 0)
            self.assertEqual(harness.guest_calls, 0)
            job = ImportStore(workspace).load_jobs()[0]
            self.assertEqual(job.metadata["sources"], [])
            self.assertEqual(job.metadata["canonical_inputs"], [])

    def test_default_admission_selects_every_unique_digest(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            report = _unique_report(workspace, 9)
            harness = AdmissionHarness(workspace)

            admission = _admit(workspace, report, harness)

            self.assertEqual(report["admission_selection"]["max_unique"], None)
            self.assertEqual(report["admission_selection"]["selected_unique"], 9)
            self.assertEqual(report["admission_selection"]["deferred_unique"], 0)
            self.assertEqual(admission["summary"]["host_stable"], 9)
            self.assertEqual(admission["summary"]["qemu_runs"], 2)
            self.assertEqual(harness.record_calls, 29)
            self.assertEqual(harness.guest_calls, 2)

    def test_admission_limit_keeps_duplicate_sources_and_never_executes_deferred(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            report = _unique_report(workspace, 10, max_admit_unique=8)
            selected_digest = report["admission_selection"]["selected_digests"][0]
            selected_source = next(
                Path(item["path"])
                for item in report["inputs"]
                if item["canonical_digest"] == selected_digest
            )
            (workspace / "duplicate.syz").write_bytes(selected_source.read_bytes())
            report, failed = build_check_report(
                (workspace,),
                SUPPORTED_SYZKALLER_REVISION,
                max_admit_unique=8,
            )
            self.assertFalse(failed)
            harness = AdmissionHarness(workspace)

            admission = _admit(workspace, report, harness)

            selection = report["admission_selection"]
            self.assertEqual(selection["eligible_unique"], 10)
            self.assertEqual(selection["selected_unique"], 8)
            self.assertEqual(selection["deferred_unique"], 2)
            self.assertEqual(admission["summary"]["host_stable"], 8)
            self.assertEqual(admission["summary"]["qemu_runs"], 1)
            self.assertEqual(harness.record_calls, 25)
            self.assertEqual(harness.guest_calls, 1)
            job = ImportStore(workspace).load_jobs()[0]
            self.assertEqual(len(job.metadata["canonical_inputs"]), 8)
            self.assertEqual(len(job.metadata["sources"]), 9)
            self.assertTrue(
                all(source["status"] == "accepted" for source in job.metadata["sources"])
            )
            persisted = {
                item["digest"] for item in job.metadata["canonical_inputs"]
            }
            self.assertEqual(persisted, set(selection["selected_digests"]))
            self.assertTrue(persisted.isdisjoint(selection["deferred_digests"]))

    def test_v1_job_resumes_before_v2_selection_and_is_not_reused(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            report = _unique_report(workspace, 2, max_admit_unique=1)
            selected_digest = report["admission_selection"]["selected_digests"][0]
            selected_report = next(
                item
                for item in report["inputs"]
                if item["canonical_digest"] == selected_digest
            )
            store = ImportStore(workspace)
            store.create_job(
                "import-v1",
                reports=(selected_report,),
                syzkaller_revision=SUPPORTED_SYZKALLER_REVISION,
                importer_version="1",
                host_repetitions=3,
                batch_size=8,
                max_qemu=64,
            )
            harness = AdmissionHarness(workspace)

            admission = _admit(workspace, report, harness)

            self.assertEqual(len(admission["jobs"]), 2)
            self.assertEqual(admission["jobs"][0]["job_id"], "import-v1")
            self.assertEqual(harness.record_calls, 8)
            self.assertEqual(harness.guest_calls, 2)
            jobs = store.load_jobs()
            self.assertEqual(
                sorted(job.metadata["importer_version"] for job in jobs),
                ["1", "2"],
            )

    def test_saved_batch_evidence_prevents_duplicate_qemu_after_interruption(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            report = _accepted_report(workspace)
            harness = AdmissionHarness(workspace)

            def interrupt_after_qemu(_profraws, _elf):
                raise KeyboardInterrupt("simulated interruption")

            harness.extract_regions = interrupt_after_qemu
            with self.assertRaises(KeyboardInterrupt):
                _admit(workspace, report, harness)
            self.assertEqual(harness.guest_calls, 1)
            jobs = ImportStore(workspace).load_resumable_jobs()
            self.assertEqual(len(jobs), 1)
            self.assertIsNotNone(
                ImportStore(workspace).load_batch_evidence(jobs[0].job_id, 0)
            )

            events = []

            def extract_after_resume(_profraws, _elf):
                events.append("import")
                return set()

            def resume_global(_workspace, _store, _command, _max_qemu):
                events.append("global")
                return False

            harness.extract_regions = extract_after_resume
            runtime = harness.runtime()
            runtime = AdmissionRuntime(
                **{
                    **runtime.__dict__,
                    "resume_global_jobs": resume_global,
                }
            )
            admission = run_admission(
                workspace,
                report,
                command="test import",
                host_repetitions=3,
                batch_size=8,
                max_qemu=64,
                runtime=runtime,
            )

            self.assertEqual(admission["summary"]["failed"], 0)
            self.assertEqual(admission["summary"]["qemu_runs"], 1)
            self.assertEqual(harness.guest_calls, 1)
            self.assertEqual(events, ["import", "global"])
            self.assertEqual(
                len(list(ImportStore(workspace).jobs_dir.iterdir())),
                1,
            )

            repeated = _admit(workspace, report, harness)
            self.assertEqual(repeated["summary"]["qemu_runs"], 1)
            self.assertEqual(harness.guest_calls, 1)
            self.assertEqual(
                len(list(ImportStore(workspace).jobs_dir.iterdir())),
                1,
            )

    def test_semantic_mismatch_saves_v3_failure_and_runs_minimization(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            report = _accepted_report(workspace)
            harness = AdmissionHarness(workspace)
            minimization_calls = []

            def mismatch(_call: int, artifact_dir: Path) -> GuestExecutionResult:
                profraw = artifact_dir / "default.profraw"
                profraw.write_bytes(b"profile")
                log = (
                    "STARRY_PIPE_LINUX_ORACLE_FAILED: host=6.8/x86_64 line=2 "
                    "scenario=0 operation=0 text=\"pipe2 0 1 0\" "
                    "difference_mask=0x00000008 "
                    "expected={kind=1,result=0,errno=0,value=0,data_len=0} "
                    "actual={kind=1,result=1,errno=0,value=0,data_len=0}\n"
                )
                return classify_guest_execution(log, 1, (profraw,))

            def minimize(_workspace, _store, source, max_qemu):
                minimization_calls.append((source, max_qemu))
                outcome = SimpleNamespace(job_id="minimize-imported", failed=False)
                job = SimpleNamespace(
                    metadata={
                        "candidate_qemu": 0,
                        "validation_qemu": 1,
                        "proof_qemu": 2,
                    }
                )
                return outcome, job

            harness.guest_result_for_call = mismatch
            harness.run_minimization = minimize

            admission = _admit(workspace, report, harness)

            self.assertEqual(admission["summary"]["failed"], 1)
            self.assertEqual(admission["jobs"][0]["result"], "semantic-mismatch")
            self.assertEqual(len(minimization_calls), 1)
            failure = Path(admission["jobs"][0]["failure_path"])
            metadata = validate_failure(failure)
            self.assertEqual(metadata["schema_version"], 3)
            self.assertTrue((failure / "source.syz").is_file())
            self.assertTrue((failure / "conversion-log.json").is_file())

    def test_new_coverage_is_attributed_minimized_and_admitted(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            report = _accepted_report(workspace)
            harness = AdmissionHarness(workspace)
            region = "crates/starry-process/src/pipe.rs:1:1"
            minimized_digest = "f" * 64
            harness.extract_regions = lambda _profraws, _elf: {region}

            def attribute(
                active_workspace,
                corpus_store,
                attribution_store,
                corpus,
                job,
            ):
                runtime = AttributionReplayRuntime(
                    record_host=harness._record_host,
                    run_guest_compare=harness._run_guest,
                    extract_regions=lambda profraws, elf, _target: harness.extract_regions(
                        profraws,
                        elf,
                    ),
                    coverage_object=lambda _workspace: harness.starry_elf,
                )
                outcome = resume_attribution_job(
                    active_workspace,
                    corpus_store,
                    attribution_store,
                    corpus,
                    job,
                    runtime,
                )
                return AttributionAdmissionOutcome(
                    outcome.failed,
                    outcome.category,
                    outcome.new_regions,
                    outcome.admitted_digests,
                    outcome.representative_digests,
                    outcome.qemu_replays,
                )

            def minimize(active_workspace, corpus_store, source, max_qemu):
                store = MinimizationStore(
                    active_workspace,
                    corpus_store.generator_version,
                )
                job = create_or_load_job_from_source(
                    active_workspace,
                    source,
                    corpus_store,
                    store,
                    max_qemu=max_qemu,
                    active_starry_elf=harness.starry_elf,
                )
                runtime = MinimizationRuntime(
                    record_host=harness._record_host,
                    run_guest_compare=harness._run_guest,
                    extract_regions=lambda profraws, elf, _target: harness.extract_regions(
                        profraws,
                        elf,
                    ),
                    coverage_object=lambda _workspace: harness.starry_elf,
                )
                outcome = resume_minimization_job(
                    active_workspace,
                    corpus_store,
                    store,
                    job,
                    runtime,
                )
                reported_outcome = SimpleNamespace(
                    **{
                        **outcome.__dict__,
                        "minimized_digests": (minimized_digest,),
                    }
                )
                return reported_outcome, store.load_job(job.job_id)

            harness.resume_attribution = attribute
            harness.run_minimization = minimize
            runtime = harness.runtime()
            runtime = AdmissionRuntime(
                **{
                    **runtime.__dict__,
                    "load_active_corpus": lambda store: store.load_corpus(),
                }
            )

            admission = run_admission(
                workspace,
                report,
                command="test import",
                host_repetitions=3,
                batch_size=8,
                max_qemu=64,
                runtime=runtime,
            )

            self.assertEqual(admission["summary"]["failed"], 0)
            self.assertEqual(admission["summary"]["new_regions"], [region])
            self.assertEqual(
                admission["summary"]["admitted_digests"],
                [minimized_digest],
            )
            corpus = CorpusStore(workspace).load_corpus()
            self.assertEqual(len(corpus), 1)
            entry = corpus.ordered_entries()[0]
            metadata = CorpusStore(workspace).entry_metadata(entry.digest)
            self.assertEqual(metadata["origin"]["source"], "syzkaller-import")
            self.assertEqual(len(metadata["origin"]["external_sources"]), 1)

    def test_new_coverage_fails_closed_when_attribution_exceeds_qemu_budget(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            report = _accepted_report(workspace)
            harness = AdmissionHarness(workspace)
            region = "crates/starry-process/src/pipe.rs:1:1"
            harness.extract_regions = lambda _profraws, _elf: {region}

            admission = run_admission(
                workspace,
                report,
                command="test import",
                host_repetitions=3,
                batch_size=8,
                max_qemu=1,
                runtime=harness.runtime(),
            )

            self.assertEqual(admission["summary"]["failed"], 1)
            self.assertEqual(admission["summary"]["qemu_runs"], 1)
            self.assertEqual(admission["summary"]["new_regions"], [region])
            self.assertEqual(admission["jobs"][0]["result"], "qemu-budget-exhausted")
            self.assertEqual(harness.guest_calls, 1)
            self.assertEqual(len(CorpusStore(workspace).load_corpus()), 0)

    def test_host_record_failure_is_typed_and_skips_qemu(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            report = _accepted_report(workspace)
            harness = AdmissionHarness(workspace)

            def fail_record(_elf, _ops, _trace):
                harness.record_calls += 1
                return HostRecordResult(False, False, "record failed")

            runtime = harness.runtime()
            runtime = AdmissionRuntime(
                **{
                    **runtime.__dict__,
                    "record_host": fail_record,
                }
            )
            admission = run_admission(
                workspace,
                report,
                command="test import",
                host_repetitions=3,
                batch_size=8,
                max_qemu=64,
                runtime=runtime,
            )

            self.assertEqual(admission["summary"]["failed"], 1)
            self.assertEqual(admission["jobs"][0]["result"], "host-record-failure")
            self.assertEqual(harness.record_calls, 1)
            self.assertEqual(harness.guest_calls, 0)


def _accepted_report(workspace: Path):
    source = workspace / "accepted.syz"
    source.write_text("pipe(&(0x7f0000000000)={<r0=>0, <r1=>0})\n")
    report, failed = build_check_report(
        (source,),
        SUPPORTED_SYZKALLER_REVISION,
    )
    if failed:
        raise AssertionError("test classification unexpectedly failed")
    return report


def _unique_report(
    workspace: Path,
    count: int,
    *,
    max_admit_unique=None,
):
    for index in range(count):
        length = index + 1
        payload = chr(ord("A") + index) * length
        (workspace / f"accepted-{index:02d}.syz").write_text(
            "pipe2(&AUTO={<r0=>0, <r1=>0}, 0x800)\n"
            f"write(r1, &AUTO='{payload}', {length})\n"
        )
    report, failed = build_check_report(
        (workspace,),
        SUPPORTED_SYZKALLER_REVISION,
        max_admit_unique=max_admit_unique,
    )
    if failed:
        raise AssertionError("test classification unexpectedly failed")
    return report


def _admit(workspace: Path, report, harness: AdmissionHarness):
    return run_admission(
        workspace,
        report,
        command="test import",
        host_repetitions=3,
        batch_size=8,
        max_qemu=64,
        runtime=harness.runtime(),
    )


if __name__ == "__main__":
    unittest.main()
