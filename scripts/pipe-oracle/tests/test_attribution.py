import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/pipe-oracle"

sys.path.insert(0, str(SCRIPT_DIR))

import attribution  # noqa: E402
import corpus  # noqa: E402
import fuzz  # noqa: E402
import generator  # noqa: E402
import mutation  # noqa: E402
import scenario  # noqa: E402


class ExactAttributionRegressionTests(unittest.TestCase):
    def test_representative_selection_is_deterministic_and_removes_redundancy(self):
        entry_regions = {
            "d" * 64: set(),
            "c" * 64: {"region-3"},
            "b" * 64: {"region-2"},
            "a" * 64: {"region-1", "region-2"},
        }

        representatives = attribution.select_representatives(
            entry_regions,
            {"region-1", "region-2", "region-3"},
        )
        reversed_representatives = attribution.select_representatives(
            dict(reversed(list(entry_regions.items()))),
            {"region-3", "region-2", "region-1"},
        )

        self.assertEqual(representatives, ("a" * 64, "c" * 64))
        self.assertEqual(reversed_representatives, representatives)

    def test_representative_selection_rejects_unattributed_target_region(self):
        with self.assertRaisesRegex(
            attribution.AttributionInstability,
            "target regions were not reproduced",
        ):
            attribution.select_representatives(
                {"a" * 64: {"region-1"}},
                {"region-1", "region-missing"},
            )

    def test_interrupted_job_resumes_with_all_completed_entry_mappings(self):
        first = scenario.parse_document(
            "version 1\nscenario first\npipe2 0 1\n"
        )
        second = scenario.parse_document(
            "version 1\nscenario second\npipe2 2 3\n"
        )
        entries = (
            attribution.AttributionInput.from_document(
                first, corpus.CorpusProvenance.generated()
            ),
            attribution.AttributionInput.from_document(
                second, corpus.CorpusProvenance.generated()
            ),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = attribution.AttributionStore(workspace)
            with self._evidence(
                workspace,
                "initial",
                {"baseline", "region-1", "region-2"},
                b"same starry elf",
            ) as initial_evidence:
                job = store.create_job(
                    "campaign-batch-0001",
                    fuzz_seed=42,
                    batch_index=0,
                    entries=entries,
                    baseline_regions={"baseline"},
                    target_regions={"region-1", "region-2"},
                    initial_evidence=initial_evidence,
                    duration_seconds=1.25,
                )

            first_digest = entries[0].digest
            with self._evidence(
                workspace,
                "first-entry",
                {"baseline", "region-1"},
                b"same starry elf",
            ) as entry_evidence:
                store.record_entry_replay(
                    job.job_id,
                    first_digest,
                    entry_evidence,
                    duration_seconds=0.5,
                )

            restarted = attribution.AttributionStore(workspace)
            resumable = restarted.load_resumable_jobs()

            self.assertEqual([item.job_id for item in resumable], [job.job_id])
            metadata = resumable[0].metadata
            self.assertEqual(metadata["state"], "entry-replays")
            self.assertEqual(metadata["completed_entry_digests"], [first_digest])
            self.assertEqual(
                metadata["entry_regions"],
                {first_digest: ["region-1"]},
            )
            self.assertEqual(metadata["qemu_replays"], 1)

    def test_resume_restarts_the_whole_job_when_the_elf_changed_between_campaigns(self):
        document = scenario.parse_document(
            "version 1\nscenario only\npipe2 0 1\n"
        )
        entry = attribution.AttributionInput.from_document(
            document,
            corpus.CorpusProvenance.generated(),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = attribution.AttributionStore(workspace)
            with self._evidence(
                workspace,
                "old-batch",
                {"old-region"},
                b"old starry elf",
            ) as old_evidence:
                job = store.create_job(
                    "campaign-batch-0001",
                    fuzz_seed=7,
                    batch_index=0,
                    entries=(entry,),
                    baseline_regions=set(),
                    target_regions={"old-region"},
                    initial_evidence=old_evidence,
                    duration_seconds=1.0,
                )
            with self._evidence(
                workspace,
                "old-entry",
                {"old-region"},
                b"old starry elf",
            ) as old_entry_evidence:
                store.record_entry_replay(
                    job.job_id,
                    entry.digest,
                    old_entry_evidence,
                    duration_seconds=0.5,
                )

            with self._evidence(
                workspace,
                "new-batch",
                {"new-base", "new-region"},
                b"new starry elf",
            ) as new_evidence:
                restarted = store.restart_for_elf(
                    job.job_id,
                    baseline_regions={"new-base"},
                    target_regions={"new-region"},
                    evidence=new_evidence,
                    duration_seconds=0.75,
                )

            self.assertEqual(restarted.metadata["attempt"], 2)
            self.assertEqual(restarted.metadata["state"], "entry-replays")
            self.assertEqual(restarted.metadata["completed_entry_digests"], [])
            self.assertEqual(restarted.metadata["entry_regions"], {})
            self.assertEqual(restarted.metadata["target_regions"], ["new-region"])
            transition = restarted.metadata["elf_transitions"][0]
            self.assertNotEqual(
                transition["previous_sha256"], transition["restarted_sha256"]
            )

    def test_unstable_job_moves_complete_evidence_to_failures(self):
        document = scenario.parse_document(
            "version 1\nscenario only\npipe2 0 1\n"
        )
        entry = attribution.AttributionInput.from_document(
            document,
            corpus.CorpusProvenance.generated(),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = attribution.AttributionStore(workspace)
            with self._evidence(
                workspace,
                "initial",
                {"region-1"},
                b"starry elf",
            ) as evidence:
                job = store.create_job(
                    "campaign-batch-0001",
                    fuzz_seed=1,
                    batch_index=0,
                    entries=(entry,),
                    baseline_regions=set(),
                    target_regions={"region-1"},
                    initial_evidence=evidence,
                    duration_seconds=1.0,
                )

            failure_path = store.fail_job(
                job.job_id,
                "target regions were not reproduced: region-1",
            )

            self.assertFalse(job.path.exists())
            self.assertTrue((failure_path / "inputs" / f"{entry.digest}.ops").is_file())
            self.assertTrue((failure_path / "replays/attempt-0001-batch/pipe.ops").is_file())
            metadata = json.loads((failure_path / "metadata.json").read_text())
            self.assertEqual(metadata["state"], "unstable")
            self.assertIn("region-1", metadata["failure_reason"])
            self.assertEqual(store.load_resumable_jobs(), [])

    def test_job_metadata_update_is_atomic(self):
        document = scenario.parse_document(
            "version 1\nscenario only\npipe2 0 1\n"
        )
        entry = attribution.AttributionInput.from_document(
            document,
            corpus.CorpusProvenance.generated(),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = attribution.AttributionStore(workspace)
            with self._evidence(
                workspace,
                "initial",
                {"region-1"},
                b"starry elf",
            ) as evidence:
                job = store.create_job(
                    "campaign-batch-0001",
                    fuzz_seed=1,
                    batch_index=0,
                    entries=(entry,),
                    baseline_regions=set(),
                    target_regions={"region-1"},
                    initial_evidence=evidence,
                    duration_seconds=1.0,
                )
            original = (job.path / "metadata.json").read_bytes()

            with (
                self._evidence(
                    workspace,
                    "entry",
                    {"region-1"},
                    b"starry elf",
                ) as evidence,
                mock.patch.object(
                    attribution.os,
                    "replace",
                    side_effect=OSError("simulated metadata interruption"),
                ),
            ):
                with self.assertRaisesRegex(OSError, "simulated metadata interruption"):
                    store.record_entry_replay(
                        job.job_id,
                        entry.digest,
                        evidence,
                        duration_seconds=0.5,
                    )

            self.assertEqual((job.path / "metadata.json").read_bytes(), original)

    def test_corrupt_replay_evidence_fails_closed(self):
        document = scenario.parse_document(
            "version 1\nscenario only\npipe2 0 1\n"
        )
        entry = attribution.AttributionInput.from_document(
            document,
            corpus.CorpusProvenance.generated(),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = attribution.AttributionStore(workspace)
            with self._evidence(
                workspace,
                "initial",
                {"region-1"},
                b"starry elf",
            ) as evidence:
                job = store.create_job(
                    "campaign-batch-0001",
                    fuzz_seed=1,
                    batch_index=0,
                    entries=(entry,),
                    baseline_regions=set(),
                    target_regions={"region-1"},
                    initial_evidence=evidence,
                    duration_seconds=1.0,
                )

            replay_trace = (
                job.path / "replays/attempt-0001-batch/linux.trace"
            )
            replay_trace.write_bytes(b"corrupt trace")

            with self.assertRaisesRegex(
                corpus.CorpusValidationError,
                "replay trace digest mismatch",
            ):
                store.load_job(job.job_id)

    def test_legacy_schema_v2_job_loads_with_pipe_only_target(self):
        import attribution_schema

        document = scenario.parse_document(
            "version 1\nscenario legacy\npipe2 0 1\n"
        )
        entry = attribution.AttributionInput.from_document(
            document,
            corpus.CorpusProvenance.generated(),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = attribution.AttributionStore(workspace)
            with self._evidence(
                workspace,
                "legacy",
                {"pipe-region"},
                b"legacy elf",
            ) as evidence:
                job = store.create_job(
                    "legacy-attribution",
                    fuzz_seed=1,
                    batch_index=0,
                    entries=(entry,),
                    baseline_regions=set(),
                    target_regions={"pipe-region"},
                    initial_evidence=evidence,
                    duration_seconds=0.1,
                )

            metadata_path = job.path / "metadata.json"
            metadata = json.loads(metadata_path.read_text())
            metadata["schema_version"] = 2
            metadata["generator_version"] = "2"
            del metadata["target_set_id"]
            metadata_path.write_text(json.dumps(metadata))
            result_path = (
                job.path / "replays/attempt-0001-batch/coverage.json"
            )
            result = json.loads(result_path.read_text())
            result["schema_version"] = 2
            del result["target_set_id"]
            result_path.write_text(json.dumps(result))

            loaded = attribution.AttributionStore(workspace).load_job(job.job_id)
            self.assertEqual(
                attribution_schema.job_target_set_id(loaded.metadata),
                "pipe-v1",
            )

            result["schema_version"] = 3
            result["target_set_id"] = "pipe-fd-v2"
            result_path.write_text(json.dumps(result))
            with self.assertRaisesRegex(Exception, "evidence schema mismatch"):
                attribution.AttributionStore(workspace).load_job(job.job_id)
            result["schema_version"] = 2
            del result["target_set_id"]
            result_path.write_text(json.dumps(result))

            metadata["target_set_id"] = "pipe-fd-v2"
            metadata_path.write_text(json.dumps(metadata))
            with self.assertRaisesRegex(Exception, "metadata keys mismatch"):
                attribution.AttributionStore(workspace).load_job(job.job_id)

    def test_job_preserves_host_oracle_executable_mode(self):
        document = scenario.parse_document(
            "version 1\nscenario only\npipe2 0 1\n"
        )
        entry = attribution.AttributionInput.from_document(
            document,
            corpus.CorpusProvenance.generated(),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = attribution.AttributionStore(workspace)
            with self._evidence(
                workspace,
                "initial",
                {"region-1"},
                b"starry elf",
            ) as evidence:
                evidence.host_oracle_path.chmod(0o755)
                job = store.create_job(
                    "campaign-batch-0001",
                    fuzz_seed=1,
                    batch_index=0,
                    entries=(entry,),
                    baseline_regions=set(),
                    target_regions={"region-1"},
                    initial_evidence=evidence,
                    duration_seconds=1.0,
                )

            saved_mode = store.host_oracle_path(job).stat().st_mode

            self.assertEqual(saved_mode & 0o111, 0o111)

    def test_productive_batch_replays_each_entry_then_one_representative_set(self):
        candidates = (
            mutation.candidate_from_document(
                scenario.parse_document(
                    "version 1\nscenario first\npipe2 0 1\nwrite 1 1 97\n"
                ),
                "generate",
            ),
            mutation.candidate_from_document(
                scenario.parse_document(
                    "version 1\nscenario second\npipe2 2 3\nwrite 3 2 98\n"
                ),
                "generate",
            ),
        )
        ordered_digests = tuple(sorted(candidate.digest for candidate in candidates))

        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            oracle = workspace / "pipe-linux-oracle"
            oracle.write_bytes(b"oracle")
            starry_elf = fuzz.coverage_object(workspace)
            starry_elf.parent.mkdir(parents=True)
            starry_elf.write_bytes(b"stable instrumented StarryOS ELF")
            profraw = workspace / "starry.profraw"
            profraw.write_bytes(b"profile")
            corpus_store = corpus.CorpusStore(workspace)
            record_count = 0

            def record_host(_elf, _ops, trace):
                nonlocal record_count
                record_count += 1
                trace.write_bytes(f"trace-{record_count}".encode())
                return fuzz.HostRecordResult(True, False, "recorded")

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
                    return_value=("guest", [profraw], True),
                ) as guest_compare,
                mock.patch.object(
                    fuzz,
                    "_extract_regions",
                    side_effect=(
                        {"region-1", "region-2"},
                        {"region-1", "region-2"},
                        {"region-2"},
                        {"region-1", "region-2"},
                    ),
                ),
            ):
                result = fuzz._run_batch(
                    workspace,
                    0,
                    list(candidates),
                    None,
                    corpus.CanonicalCorpus.initial(),
                    corpus_store.failures_dir,
                    store=corpus_store,
                    fuzz_seed=42,
                    attribution_job_id="campaign-batch-0001",
                )

            job = attribution.AttributionStore(workspace).load_job(
                "campaign-batch-0001"
            )
            replay_traces = {
                (replay / "linux.trace").read_bytes()
                for replay in (job.path / "replays").iterdir()
                if replay.is_dir()
            }

            self.assertFalse(result.failed)
            self.assertEqual(guest_compare.call_count, 4)
            self.assertEqual(record_count, 4)
            self.assertEqual(result.attribution_replays, 3)
            self.assertEqual(result.representative_digests, (ordered_digests[0],))
            self.assertEqual(
                dict(result.entry_regions),
                {
                    ordered_digests[0]: ("region-1", "region-2"),
                    ordered_digests[1]: ("region-2",),
                },
            )
            self.assertEqual(len(replay_traces), 4)
            self.assertEqual(len(corpus_store.load_corpus()), 1)
            self.assertEqual(
                corpus_store.load_coverage_regions(starry_elf),
                {"region-1", "region-2"},
            )

    def test_unstable_entry_attribution_stops_without_updating_baseline(self):
        candidates = (
            mutation.candidate_from_document(
                scenario.parse_document(
                    "version 1\nscenario first\npipe2 0 1\n"
                ),
                "generate",
            ),
            mutation.candidate_from_document(
                scenario.parse_document(
                    "version 1\nscenario second\npipe2 2 3\n"
                ),
                "generate",
            ),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            oracle = workspace / "pipe-linux-oracle"
            oracle.write_bytes(b"oracle")
            starry_elf = fuzz.coverage_object(workspace)
            starry_elf.parent.mkdir(parents=True)
            starry_elf.write_bytes(b"stable instrumented StarryOS ELF")
            profraw = workspace / "starry.profraw"
            profraw.write_bytes(b"profile")
            corpus_store = corpus.CorpusStore(workspace)

            def record_host(_elf, _ops, trace):
                trace.write_bytes(b"fresh trace")
                return fuzz.HostRecordResult(True, False, "recorded")

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
                    return_value=("guest", [profraw], True),
                ),
                mock.patch.object(
                    fuzz,
                    "_extract_regions",
                    side_effect=(
                        {"region-1", "region-2"},
                        {"region-1"},
                        {"region-1"},
                    ),
                ),
            ):
                result = fuzz._run_batch(
                    workspace,
                    0,
                    list(candidates),
                    None,
                    corpus.CanonicalCorpus.initial(),
                    corpus_store.failures_dir,
                    store=corpus_store,
                    attribution_job_id="unstable-batch-0001",
                )

            failure = (
                corpus_store.failures_dir / "attribution-unstable-batch-0001"
            )
            failure_metadata = json.loads(
                (failure / "metadata.json").read_text(encoding="utf-8")
            )

            self.assertTrue(result.failed)
            self.assertEqual(result.category, "attribution-instability")
            self.assertEqual(corpus_store.load_coverage_regions(starry_elf), set())
            self.assertEqual(len(corpus_store.load_corpus()), 0)
            self.assertEqual(failure_metadata["state"], "unstable")
            self.assertEqual(
                set(failure_metadata["entry_regions"]),
                {candidate.digest for candidate in candidates},
            )
            self.assertIn("region-2", failure_metadata["failure_reason"])

    def test_host_replay_failure_without_trace_preserves_failure_evidence(self):
        document = scenario.parse_document(
            "version 1\nscenario only\npipe2 0 1\n"
        )
        entry = attribution.AttributionInput.from_document(
            document,
            corpus.CorpusProvenance.generated(),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            attribution_store = attribution.AttributionStore(workspace)
            with self._evidence(
                workspace,
                "initial",
                {"region-1"},
                b"stable Starry ELF",
            ) as evidence:
                job = attribution_store.create_job(
                    "host-failure-batch-0001",
                    fuzz_seed=7,
                    batch_index=0,
                    entries=(entry,),
                    baseline_regions=set(),
                    target_regions={"region-1"},
                    initial_evidence=evidence,
                    duration_seconds=1.0,
                )

            active_elf = fuzz.coverage_object(workspace)
            active_elf.parent.mkdir(parents=True)
            active_elf.write_bytes(b"stable Starry ELF")
            corpus_store = corpus.CorpusStore(workspace)
            with (
                mock.patch.object(
                    fuzz,
                    "_record_host",
                    return_value=fuzz.HostRecordResult(
                        False,
                        False,
                        "host record failed before creating a trace",
                    ),
                ),
                mock.patch.object(fuzz, "_run_guest_compare") as guest_compare,
            ):
                result = fuzz._resume_attribution_job(
                    workspace,
                    corpus_store,
                    attribution_store,
                    corpus.CanonicalCorpus.initial(),
                    job,
                )

            failure = corpus_store.failures_dir / "attribution-host-failure-batch-0001"
            replay = failure / f"replays/attempt-0001-entry-{entry.digest}"

            self.assertTrue(result.failed)
            self.assertEqual(result.category, "attribution-instability")
            guest_compare.assert_not_called()
            self.assertEqual((replay / "linux.trace").read_bytes(), b"")
            self.assertIn(
                "host record failed before creating a trace",
                (replay / "guest.log").read_text(encoding="utf-8"),
            )
            self.assertEqual(corpus_store.load_coverage_regions(active_elf), set())

    def test_campaign_startup_finalizes_completed_job_before_new_batches(self):
        document = scenario.parse_document(
            "version 1\nscenario only\npipe2 0 1\n"
        )
        entry = attribution.AttributionInput.from_document(
            document,
            corpus.CorpusProvenance.generated(),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            attribution_store = attribution.AttributionStore(workspace)
            with self._evidence(
                workspace,
                "initial",
                {"region-1"},
                b"starry elf",
            ) as evidence:
                job = attribution_store.create_job(
                    "interrupted-batch-0001",
                    fuzz_seed=9,
                    batch_index=0,
                    entries=(entry,),
                    baseline_regions=set(),
                    target_regions={"region-1"},
                    initial_evidence=evidence,
                    duration_seconds=1.0,
                )
            with self._evidence(
                workspace,
                "entry",
                {"region-1"},
                b"starry elf",
            ) as evidence:
                job = attribution_store.record_entry_replay(
                    job.job_id,
                    entry.digest,
                    evidence,
                    duration_seconds=0.5,
                )
            with self._evidence(
                workspace,
                "representative",
                {"region-1"},
                b"starry elf",
            ) as evidence:
                attribution_store.record_representative_replay(
                    job.job_id,
                    evidence,
                    duration_seconds=0.5,
                )

            corpus_store = corpus.CorpusStore(workspace)
            status = fuzz._run_campaign(
                SimpleNamespace(seed=42, batches=0, batch_size=8),
                workspace,
                corpus_store,
            )

            finalized = attribution_store.load_job(job.job_id)

            self.assertEqual(status, 0)
            self.assertTrue(finalized.metadata["run_recorded"])
            self.assertEqual(len(corpus_store.load_corpus()), 1)
            self.assertTrue(
                (corpus_store.runs_dir / job.job_id / "metadata.json").is_file()
            )

    def test_elf_change_during_continuous_replays_fails_without_baseline_update(self):
        candidate = mutation.candidate_from_document(
            scenario.parse_document(
                "version 1\nscenario only\npipe2 0 1\n"
            ),
            "generate",
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            oracle = workspace / "pipe-linux-oracle"
            oracle.write_bytes(b"oracle")
            starry_elf = fuzz.coverage_object(workspace)
            starry_elf.parent.mkdir(parents=True)
            starry_elf.write_bytes(b"first Starry ELF")
            profraw = workspace / "starry.profraw"
            profraw.write_bytes(b"profile")
            corpus_store = corpus.CorpusStore(workspace)
            guest_runs = 0

            def record_host(_elf, _ops, trace):
                trace.write_bytes(b"fresh trace")
                return fuzz.HostRecordResult(True, False, "recorded")

            def run_guest(_workspace, _artifact, _pinned_starry_elf=None):
                nonlocal guest_runs
                guest_runs += 1
                if guest_runs == 2:
                    starry_elf.write_bytes(b"different Starry ELF")
                return "guest", [profraw], True

            with (
                mock.patch.object(
                    fuzz,
                    "_find_or_build_host_oracle",
                    return_value=oracle,
                ),
                mock.patch.object(fuzz, "_record_host", side_effect=record_host),
                mock.patch.object(fuzz, "_run_guest_compare", side_effect=run_guest),
                mock.patch.object(
                    fuzz,
                    "_extract_regions",
                    return_value={"region-1"},
                ),
            ):
                result = fuzz._run_batch(
                    workspace,
                    0,
                    [candidate],
                    None,
                    corpus.CanonicalCorpus.initial(),
                    corpus_store.failures_dir,
                    store=corpus_store,
                    attribution_job_id="elf-unstable-batch-0001",
                )

            failure = (
                corpus_store.failures_dir / "attribution-elf-unstable-batch-0001"
            )
            metadata = json.loads(
                (failure / "metadata.json").read_text(encoding="utf-8")
            )

            self.assertTrue(result.failed)
            self.assertEqual(guest_runs, 2)
            self.assertIn("Starry ELF changed", metadata["failure_reason"])
            self.assertEqual(list(corpus_store.coverage_state_dir.glob("*.json")), [])
            self.assertEqual(len(corpus_store.load_corpus()), 0)

    def test_resume_replays_full_batch_on_changed_elf_before_attribution(self):
        document = scenario.parse_document(
            "version 1\nscenario only\npipe2 0 1\n"
        )
        entry = attribution.AttributionInput.from_document(
            document,
            corpus.CorpusProvenance.generated(),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            attribution_store = attribution.AttributionStore(workspace)
            with self._evidence(
                workspace,
                "old-batch",
                {"old-region"},
                b"old Starry ELF",
            ) as evidence:
                job = attribution_store.create_job(
                    "resume-elf-batch-0001",
                    fuzz_seed=11,
                    batch_index=0,
                    entries=(entry,),
                    baseline_regions=set(),
                    target_regions={"old-region"},
                    initial_evidence=evidence,
                    duration_seconds=1.0,
                )

            current_elf = fuzz.coverage_object(workspace)
            current_elf.parent.mkdir(parents=True)
            current_elf.write_bytes(b"new Starry ELF")
            profraw = workspace / "starry.profraw"
            profraw.write_bytes(b"profile")
            corpus_store = corpus.CorpusStore(workspace)

            def record_host(_elf, _ops, trace):
                trace.write_bytes(b"fresh trace")
                return fuzz.HostRecordResult(True, False, "recorded")

            with (
                mock.patch.object(fuzz, "_record_host", side_effect=record_host),
                mock.patch.object(
                    fuzz,
                    "_run_guest_compare",
                    return_value=("guest", [profraw], True),
                ) as guest_compare,
                mock.patch.object(
                    fuzz,
                    "_extract_regions",
                    return_value={"new-region"},
                ),
            ):
                result = fuzz._resume_attribution_job(
                    workspace,
                    corpus_store,
                    attribution_store,
                    corpus.CanonicalCorpus.initial(),
                    job,
                )

            completed = attribution_store.load_job(job.job_id)

            self.assertFalse(result.failed)
            self.assertEqual(guest_compare.call_count, 3)
            self.assertEqual(completed.metadata["attempt"], 2)
            self.assertEqual(len(completed.metadata["elf_transitions"]), 1)
            self.assertEqual(result.new_regions, ("new-region",))
            self.assertEqual(result.attribution_replays, 3)
            self.assertEqual(
                corpus_store.load_coverage_regions(current_elf),
                {"new-region"},
            )

    def _evidence(self, workspace, name, covered_regions, elf_contents):
        return _EvidenceFixture(workspace, name, covered_regions, elf_contents)


class _EvidenceFixture:
    def __init__(self, workspace, name, covered_regions, elf_contents):
        self._temporary = tempfile.TemporaryDirectory(dir=workspace)
        self.root = Path(self._temporary.name)
        self.ops = self.root / "pipe.ops"
        self.trace = self.root / "linux.trace"
        self.profraw = self.root / f"{name}.profraw"
        self.elf = self.root / "starryos"
        self.oracle = self.root / "pipe-linux-oracle"
        self.ops.write_text("version 1\nscenario x\npipe2 0 1\n")
        self.trace.write_bytes(f"trace-{name}".encode())
        self.profraw.write_bytes(f"profile-{name}".encode())
        self.elf.write_bytes(elf_contents)
        self.oracle.write_bytes(b"host oracle")
        self.evidence = attribution.ReplayEvidence(
            ops_path=self.ops,
            trace_path=self.trace,
            guest_log=f"guest-{name}",
            profraw_paths=(self.profraw,),
            starry_elf_path=self.elf,
            host_oracle_path=self.oracle,
            covered_regions=frozenset(covered_regions),
            result_category="passed",
        )

    def __enter__(self):
        return self.evidence

    def __exit__(self, _error_type, _error, _traceback):
        self._temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
