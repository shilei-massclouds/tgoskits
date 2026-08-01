import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/pipe-oracle"

sys.path.insert(0, str(SCRIPT_DIR))

import runner  # noqa: E402
import scenario  # noqa: E402


class GuestResultRegressionTests(unittest.TestCase):
    def test_monitor_socket_failure_is_infrastructure_not_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            artifact_dir = workspace / "artifact"
            artifact_dir.mkdir()
            for name in runner.REQUIRED_ARTIFACTS:
                (artifact_dir / name).write_bytes(b"artifact")

            completed = subprocess.CompletedProcess(
                args=["cargo", "xtask"],
                returncode=1,
                stdout="",
                stderr=(
                    "Error: QEMU monitor socket was not available at "
                    "/tmp/axbuild-qemu.sock\n"
                ),
            )
            with mock.patch.object(runner.subprocess, "run", return_value=completed):
                result = runner.run_guest_compare(workspace, artifact_dir)

        self.assertEqual(
            result.category,
            runner.GuestResultCategory.INFRASTRUCTURE_FAILURE,
        )

    def test_qemu_process_start_failure_is_a_typed_infrastructure_result(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            artifact_dir = workspace / "artifact"
            artifact_dir.mkdir()
            for name in runner.REQUIRED_ARTIFACTS:
                (artifact_dir / name).write_bytes(b"artifact")

            with mock.patch.object(
                runner.subprocess,
                "run",
                side_effect=FileNotFoundError("cargo is unavailable"),
            ):
                result = runner.run_guest_compare(workspace, artifact_dir)

        self.assertEqual(
            result.category,
            runner.GuestResultCategory.INFRASTRUCTURE_FAILURE,
        )
        self.assertIn("failed to start", result.log)

    def test_difference_mask_builds_a_stable_mismatch_fingerprint(self):
        import fingerprint

        log = (
            "STARRY_PIPE_LINUX_ORACLE_FAILED: host=6.8/x86_64 line=7 "
            "scenario=0 operation=2 text=\"write 1 8 65\" "
            "difference_mask=0x00000018 "
            "expected={kind=4,result=-1,errno=32,value=0,data_len=0} "
            "actual={kind=4,result=0,errno=0,value=0,data_len=0}\n"
        )

        result = runner.classify_guest_execution(log, 1)
        mismatch = fingerprint.MismatchFingerprint.from_difference(
            result.difference,
            fingerprint.OperationOrigin(0, 2),
        )
        restored = fingerprint.MismatchFingerprint.from_metadata(
            mismatch.as_metadata()
        )

        self.assertEqual(result.category, runner.GuestResultCategory.SEMANTIC_MISMATCH)
        self.assertEqual(mismatch, restored)
        self.assertEqual(mismatch.difference_fields, ("result", "errno"))
        self.assertEqual(mismatch.expected_result_class, "error")
        self.assertEqual(mismatch.expected_errno, 32)
        self.assertEqual(mismatch.actual_result_class, "zero")
        self.assertIsNone(mismatch.actual_errno)


class StructuredReducerRegressionTests(unittest.TestCase):
    def setUp(self):
        import reducer

        self.reducer = reducer
        self.document = scenario.parse_document(
            "version 1\n"
            "scenario first\n"
            "pipe2 8 9\n"
            "dup 9 12\n"
            "write 12 8192 255\n"
            "poll 8 32767\n"
            "close 12\n"
            "scenario second\n"
            "pipe2 14 15\n"
            "set-size 15 2147483647\n"
            "read 14 8192\n"
        )

    def test_candidate_order_is_deterministic_and_strictly_smaller(self):
        first = self.reducer.StructuredReducer(
            self.reducer.ReductionInput.initial(self.document),
            critical_origin=self.reducer.OperationOrigin(0, 2),
        )
        second = self.reducer.StructuredReducer(
            self.reducer.ReductionInput.initial(self.document),
            critical_origin=self.reducer.OperationOrigin(0, 2),
        )

        first_candidates = self._collect(first)
        second_candidates = self._collect(second)

        self.assertEqual(
            [(item.transform, item.digest) for item in first_candidates],
            [(item.transform, item.digest) for item in second_candidates],
        )
        original_key = self.reducer.complexity_key(self.document)
        self.assertTrue(first_candidates)
        self.assertTrue(
            all(item.complexity < original_key for item in first_candidates)
        )
        self.assertEqual(
            len({item.digest for item in first_candidates}),
            len(first_candidates),
        )

    def test_critical_origin_survives_and_every_candidate_is_canonical(self):
        critical = self.reducer.OperationOrigin(0, 2)
        reducer = self.reducer.StructuredReducer(
            self.reducer.ReductionInput.initial(self.document),
            critical_origin=critical,
        )

        for candidate in self._collect(reducer):
            flattened_origins = {
                origin
                for scenario_origins in candidate.reduction_input.origins
                for origin in scenario_origins
            }
            self.assertIn(critical, flattened_origins)
            encoded = scenario.serialize_document(candidate.reduction_input.document)
            self.assertEqual(scenario.parse_document(encoded), candidate.reduction_input.document)

    def test_argument_reduction_uses_boundary_values_and_dense_slots(self):
        reducer = self.reducer.StructuredReducer(
            self.reducer.ReductionInput.initial(self.document)
        )
        candidates = self._collect(reducer)
        texts = {
            scenario.serialize_document(candidate.reduction_input.document)
            for candidate in candidates
        }

        self.assertTrue(any("write 12 0 255" in text for text in texts))
        self.assertTrue(any("write 12 8192 0" in text for text in texts))
        self.assertTrue(any("poll 8 0" in text for text in texts))
        self.assertTrue(any("set-size 15 4096" in text for text in texts))
        self.assertTrue(any("pipe2 0 1" in text for text in texts))

    def test_v2_reducer_simplifies_flags_redirects_dup_targets_and_never_repairs(self):
        document = scenario.parse_document(
            "version 2\n"
            "scenario flags\n"
            "pipe2 8 9 526336\n"
            "dup2 9 12\n"
            "set-fd-flags 12 3\n"
            "set-status-flags 12 526336\n"
            "write 12 8 65\n"
            "dup3 12 14 524288\n"
            "get-fd-flags 14\n"
        )
        reduction_input = self.reducer.ReductionInput.initial(document)
        reducer = self.reducer.StructuredReducer(reduction_input)
        candidates = self._collect(reducer)

        self.assertTrue(any(item.transform.startswith("compress-dup") for item in candidates))
        self.assertTrue(any(item.transform.startswith("shrink-pipe2-flags") for item in candidates))
        self.assertTrue(any(item.transform.startswith("shrink-fd-flags") for item in candidates))
        self.assertEqual(
            len({item.digest for item in candidates}),
            len(candidates),
        )
        original_operation_count = sum(
            len(item.operations) for item in document.scenarios
        )
        self.assertTrue(
            all(
                sum(
                    len(item.operations)
                    for item in candidate.reduction_input.document.scenarios
                )
                <= original_operation_count
                for candidate in candidates
            )
        )

    def test_v3_reducer_simplifies_vector_shape_base_length_and_byte(self):
        document = scenario.parse_document(
            "version 3\n"
            "scenario vectors\n"
            "pipe2 8 9 2048\n"
            "writev 9 0 3 3 1 16 255 0 32 127 0 64 65\n"
            "readv 8 0 2 2 0 8 0 16\n"
        )
        critical = self.reducer.OperationOrigin(0, 1)
        reducer = self.reducer.StructuredReducer(
            self.reducer.ReductionInput.initial(document),
            critical_origin=critical,
        )
        candidates = self._collect(reducer)
        transforms = {candidate.transform for candidate in candidates}
        original_key = self.reducer.complexity_key(document)

        self.assertTrue(any(name.startswith("shrink-iov-count") for name in transforms))
        self.assertTrue(any(name.startswith("shrink-base-mode-0") for name in transforms))
        self.assertTrue(any(name.startswith("shrink-segment-length-0") for name in transforms))
        self.assertTrue(any(name.startswith("shrink-segment-byte-0") for name in transforms))
        self.assertTrue(all(candidate.complexity < original_key for candidate in candidates))
        self.assertEqual(len({candidate.digest for candidate in candidates}), len(candidates))
        for candidate in candidates:
            flattened = {
                origin
                for origins in candidate.reduction_input.origins
                for origin in origins
            }
            self.assertIn(critical, flattened)
            self.assertEqual(
                scenario.parse_document(
                    scenario.serialize_document(candidate.reduction_input.document)
                ),
                candidate.reduction_input.document,
            )

    def test_v4_reducer_simplifies_poll_entries_without_synthesizing_resources(self):
        document = scenario.parse_document(
            "version 4\n"
            "scenario poll-array\n"
            "poll-many 4 1 2147483647 32767 0 3 64 0 3 64 1 -2 4\n"
        )
        critical = self.reducer.OperationOrigin(0, 0)
        reducer = self.reducer.StructuredReducer(
            self.reducer.ReductionInput.initial(document),
            critical_origin=critical,
        )
        candidates = self._collect(reducer)
        transforms = {candidate.transform for candidate in candidates}
        original_key = self.reducer.complexity_key(document)

        self.assertTrue(any("poll-entry-delete" in name for name in transforms))
        self.assertTrue(any("poll-entry-order" in name for name in transforms))
        self.assertTrue(any("poll-fd-mode" in name for name in transforms))
        self.assertTrue(any("poll-fd-arg" in name for name in transforms))
        self.assertTrue(any("poll-mask" in name for name in transforms))
        self.assertTrue(all(candidate.complexity < original_key for candidate in candidates))
        self.assertEqual(len({candidate.digest for candidate in candidates}), len(candidates))
        for candidate in candidates:
            operations = candidate.reduction_input.document.scenarios[0].operations
            self.assertEqual(len(operations), 1)
            self.assertIsInstance(operations[0], scenario.PollMany)
            self.assertEqual(candidate.reduction_input.origins, ((critical,),))

    def test_snapshot_resumes_after_last_yielded_candidate(self):
        first = self.reducer.StructuredReducer(
            self.reducer.ReductionInput.initial(self.document)
        )
        yielded = [first.next_candidate() for _ in range(5)]
        snapshot = first.snapshot()
        expected_next = first.next_candidate()

        resumed = self.reducer.StructuredReducer.restore(
            self.reducer.ReductionInput.initial(self.document),
            snapshot,
        )

        self.assertTrue(all(item is not None for item in yielded))
        self.assertEqual(resumed.next_candidate(), expected_next)

    @staticmethod
    def _collect(reducer):
        candidates = []
        while candidate := reducer.next_candidate():
            candidates.append(candidate)
        return candidates


class FailureSchemaRegressionTests(unittest.TestCase):
    def test_v2_is_strict_and_retains_typed_result_fingerprint_and_starry_elf(self):
        import artifact
        import fingerprint

        with tempfile.TemporaryDirectory() as temporary_directory:
            failure_dir = Path(temporary_directory)
            (failure_dir / "pipe.ops").write_text(
                "version 1\nscenario generated-0001\npipe2 0 1\nwrite 1 1 65\n",
                encoding="utf-8",
            )
            (failure_dir / "linux.trace").write_bytes(b"trace")
            (failure_dir / "guest.log").write_text("semantic mismatch", encoding="utf-8")
            executable = Path(sys.executable).resolve()
            (failure_dir / "pipe-linux-oracle").write_bytes(executable.read_bytes())
            (failure_dir / "starryos").write_bytes(executable.read_bytes())
            mismatch = fingerprint.MismatchFingerprint(
                fingerprint.OperationOrigin(0, 1),
                "write",
                ("result", "errno"),
                "error",
                "zero",
                32,
                None,
            )
            metadata = artifact.build_failure_metadata_v2(
                failure_dir,
                generator_version="scenario-v1",
                fuzz_seed=42,
                batch_index=3,
                command="fuzz.py",
                result_category=runner.GuestResultCategory.SEMANTIC_MISMATCH,
                mismatch_fingerprint=mismatch,
            )
            (failure_dir / "metadata.json").write_text(
                __import__("json").dumps(metadata),
                encoding="utf-8",
            )

            loaded = artifact.validate_failure(failure_dir)
            (failure_dir / "unexpected").write_bytes(b"unexpected")
            with self.assertRaisesRegex(Exception, "unexpected failure artifact"):
                artifact.validate_failure(failure_dir)
            (failure_dir / "unexpected").unlink()
            (failure_dir / "input.bin").symlink_to(
                failure_dir / "pipe-linux-oracle"
            )
            with self.assertRaisesRegex(Exception, "unrecorded artifact file"):
                artifact.validate_failure(failure_dir)
            (failure_dir / "input.bin").unlink()
            metadata["unknown"] = True
            (failure_dir / "metadata.json").write_text(
                __import__("json").dumps(metadata),
                encoding="utf-8",
            )

            self.assertEqual(loaded["schema_version"], 2)
            self.assertEqual(loaded["starry_elf_sha256"], loaded["host_oracle_sha256"])
            with self.assertRaisesRegex(Exception, "metadata keys mismatch"):
                artifact.validate_failure(failure_dir)

    def test_v1_lazy_import_replays_only_a_strict_semantic_mismatch(self):
        import common
        import corpus
        import generator
        import minimization_source
        import minimization_store

        mismatch_log = (
            "STARRY_PIPE_LINUX_ORACLE_FAILED: host=6.8/x86_64 line=4 "
            "scenario=0 operation=1 text=\"write 1 1 65\" "
            "expected={kind=4,result=-1,errno=32,value=0,data_len=0} "
            "actual={kind=4,result=0,errno=0,value=0,data_len=0}\n"
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            failure = workspace / "legacy-failure"
            failure.mkdir()
            executable = Path(sys.executable).resolve()
            (failure / "pipe-linux-oracle").write_bytes(executable.read_bytes())
            (failure / "pipe.ops").write_text(
                "version 1\nscenario generated-0001\npipe2 0 1\nwrite 1 1 65\n"
            )
            (failure / "linux.trace").write_bytes(b"trace")
            (failure / "guest.log").write_text(mismatch_log)
            metadata = common.build_metadata(
                seed=42,
                batch_index=1,
                generator_version=generator.GENERATOR_VERSION,
                input_path=None,
                elf_path=failure / "pipe-linux-oracle",
                ops_path=failure / "pipe.ops",
                trace_path=failure / "linux.trace",
                guest_log_path=failure / "guest.log",
                profraw_paths=None,
                command="legacy fuzz",
                result_category="mismatch",
            )
            common.save_metadata(failure, metadata)
            corpus_store = corpus.CorpusStore(workspace)
            store = minimization_store.MinimizationStore(
                workspace,
                generator.GENERATOR_VERSION,
            )

            job = minimization_source.create_or_load_job_from_source(
                workspace,
                failure,
                corpus_store,
                store,
                max_qemu=4,
                active_starry_elf=executable,
            )

            self.assertEqual(job.metadata["kind"], "mismatch")
            self.assertEqual(
                job.metadata["expected_fingerprint"]["operation_origin"],
                {"scenario_index": 0, "operation_index": 1},
            )
            store.mark_unstable(job, "simulated terminal mismatch")
            with self.assertRaisesRegex(Exception, "terminal minimization job"):
                minimization_source.create_or_load_job_from_source(
                    workspace,
                    failure,
                    corpus_store,
                    store,
                    max_qemu=4,
                    active_starry_elf=executable,
                )

            infrastructure = workspace / "legacy-infrastructure"
            __import__("shutil").copytree(failure, infrastructure)
            (infrastructure / "guest.log").write_text(
                "QEMU monitor socket was not available at /tmp/monitor.sock\n"
            )
            metadata = common.build_metadata(
                seed=42,
                batch_index=2,
                generator_version=generator.GENERATOR_VERSION,
                input_path=None,
                elf_path=infrastructure / "pipe-linux-oracle",
                ops_path=infrastructure / "pipe.ops",
                trace_path=infrastructure / "linux.trace",
                guest_log_path=infrastructure / "guest.log",
                profraw_paths=None,
                command="legacy fuzz",
                result_category="mismatch",
            )
            common.save_metadata(infrastructure, metadata)

            with self.assertRaisesRegex(ValueError, "does not contain"):
                minimization_source.create_or_load_job_from_source(
                    workspace,
                    infrastructure,
                    corpus_store,
                    store,
                    max_qemu=4,
                    active_starry_elf=executable,
                )


class MinimizationPolicyRegressionTests(unittest.TestCase):
    def test_coverage_responsibility_uses_first_digest_and_keeps_history(self):
        import minimization

        responsibilities = minimization.assign_coverage_responsibilities(
            ("b" * 64, "a" * 64),
            {
                "a" * 64: {"shared", "a-only"},
                "b" * 64: {"shared", "b-only"},
            },
            {"a" * 64: {"historical-a"}, "b" * 64: {"historical-b"}},
            {"shared", "a-only", "b-only"},
        )

        self.assertEqual(
            responsibilities,
            {
                "a" * 64: {"shared", "a-only", "historical-a"},
                "b" * 64: {"b-only", "historical-b"},
            },
        )

    def test_session_round_robins_items_and_enforces_shared_candidate_budget(self):
        import minimization
        import reducer

        first = scenario.parse_document(
            "version 1\nscenario first\npipe2 0 1\nwrite 1 8192 255\n"
        )
        second = scenario.parse_document(
            "version 1\nscenario second\npipe2 2 3\npoll 2 32767\n"
        )
        session = minimization.MinimizationSession(
            "coverage",
            (
                minimization.MinimizationItem(
                    scenario.canonical_digest(first),
                    reducer.ReductionInput.initial(first),
                    frozenset({"first"}),
                ),
                minimization.MinimizationItem(
                    scenario.canonical_digest(second),
                    reducer.ReductionInput.initial(second),
                    frozenset({"second"}),
                ),
            ),
            max_qemu=4,
        )

        scheduled = []
        while candidate := session.next_candidate():
            scheduled.append(candidate.item_index)
            session.record_candidate(candidate, accepted=False)

        self.assertEqual(scheduled, [0, 1, 0, 1])
        self.assertEqual(session.candidate_qemu, 4)
        self.assertTrue(session.budget_limited)

    def test_mismatch_predicate_rejects_origin_or_fingerprint_drift(self):
        import fingerprint
        import minimization
        import reducer

        document = scenario.parse_document(
            "version 1\nscenario mismatch\npipe2 0 1\nwrite 1 1 65\n"
        )
        reduction_input = reducer.ReductionInput.initial(document)
        expected = fingerprint.MismatchFingerprint(
            fingerprint.OperationOrigin(0, 1),
            "write",
            ("result", "errno"),
            "error",
            "zero",
            32,
            None,
        )
        same = expected
        drifted = fingerprint.MismatchFingerprint(
            fingerprint.OperationOrigin(0, 0),
            "pipe2",
            ("result",),
            "error",
            "zero",
            22,
            None,
        )

        self.assertEqual(
            minimization.mismatch_decision(
                runner.GuestResultCategory.SEMANTIC_MISMATCH,
                same,
                expected,
            ),
            minimization.PredicateDecision.ACCEPT,
        )
        self.assertEqual(
            minimization.mismatch_decision(
                runner.GuestResultCategory.SEMANTIC_MISMATCH,
                drifted,
                expected,
            ),
            minimization.PredicateDecision.REJECT,
        )
        self.assertEqual(
            minimization.mismatch_decision(
                runner.GuestResultCategory.PASSED,
                None,
                expected,
            ),
            minimization.PredicateDecision.REJECT,
        )
        self.assertEqual(
            minimization.mismatch_decision(
                runner.GuestResultCategory.INFRASTRUCTURE_FAILURE,
                None,
                expected,
            ),
            minimization.PredicateDecision.EXCEPTIONAL,
        )
        self.assertEqual(reduction_input.origins[0][1], expected.operation_origin)

    def test_final_proof_calls_predicate_exactly_twice_and_requires_both(self):
        import minimization

        calls = []

        def predicate():
            calls.append(len(calls))
            return len(calls) < 3

        self.assertTrue(minimization.run_final_proof(predicate))
        self.assertEqual(calls, [0, 1])

        calls.clear()

        def unstable():
            calls.append(len(calls))
            return len(calls) == 1

        self.assertFalse(minimization.run_final_proof(unstable))
        self.assertEqual(calls, [0, 1])


class MinimizationPersistenceRegressionTests(unittest.TestCase):
    def test_campaign_recovers_jobs_and_reloads_corpus_before_rng(self):
        import corpus
        import fuzz

        events = []

        def load_active(_store):
            events.append("load-corpus")
            return corpus.CanonicalCorpus.initial(), 5, 0

        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = corpus.CorpusStore(workspace)
            args = SimpleNamespace(
                seed=42,
                batches=0,
                batch_size=8,
                max_qemu=4,
                no_minimize=False,
            )
            with (
                mock.patch.object(fuzz, "_load_active_corpus", side_effect=load_active),
                mock.patch.object(
                    fuzz,
                    "_resume_saved_jobs",
                    side_effect=lambda *_args: events.append("attribution") or False,
                ),
                mock.patch.object(
                    fuzz,
                    "_resume_minimization_work",
                    side_effect=lambda *_args: events.append("minimization") or False,
                ),
                mock.patch.object(
                    fuzz,
                    "CampaignRng",
                    side_effect=lambda _seed: events.append("rng") or mock.Mock(),
                ),
            ):
                status = fuzz._run_campaign(args, workspace, store)

        self.assertEqual(status, 0)
        self.assertEqual(
            events,
            ["load-corpus", "attribution", "minimization", "load-corpus", "rng"],
        )

    def test_schema_v1_round_trips_and_unknown_fields_fail_closed(self):
        import fingerprint
        import minimization
        import minimization_store
        import reducer

        document = scenario.parse_document(
            "version 1\nscenario persisted\npipe2 0 1\nwrite 1 8 65\n"
        )
        mismatch = fingerprint.MismatchFingerprint(
            fingerprint.OperationOrigin(0, 1),
            "write",
            ("result", "errno"),
            "error",
            "zero",
            32,
            None,
        )
        item = minimization.MinimizationItem(
            scenario.canonical_digest(document),
            reducer.ReductionInput.initial(document),
            critical_origin=mismatch.operation_origin,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            executable = Path(sys.executable).resolve()
            store = minimization_store.MinimizationStore(
                workspace,
                generator_version="scenario-v1",
            )
            job = store.create_job(
                "minimize-mismatch-0001",
                kind="mismatch",
                source={"kind": "failure", "path": "/failure", "id": "failure-1"},
                items=(item,),
                starry_elf=executable,
                host_oracle=executable,
                max_qemu=64,
                expected_fingerprint=mismatch,
            )
            loaded = store.load_job(job.job_id)
            metadata_path = loaded.path / "metadata.json"
            metadata = __import__("json").loads(metadata_path.read_text())
            metadata["unknown"] = True
            metadata_path.write_text(__import__("json").dumps(metadata))

            self.assertEqual(loaded.metadata["state"], "validating")
            self.assertEqual(loaded.metadata["max_candidate_qemu"], 64)
            self.assertEqual(loaded.metadata["items"][0]["original_digest"], item.original_digest)
            with self.assertRaisesRegex(Exception, "metadata keys mismatch"):
                store.load_job(job.job_id)

    def test_legacy_schema_v1_job_loads_with_pipe_only_target(self):
        import generator
        import minimization
        import minimization_schema
        import minimization_store
        import reducer

        document = scenario.parse_document(
            "version 1\nscenario legacy\npipe2 0 1\n"
        )
        item = minimization.MinimizationItem(
            scenario.canonical_digest(document),
            reducer.ReductionInput.initial(document),
            frozenset({"pipe-region"}),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            executable = Path(sys.executable).resolve()
            store = minimization_store.MinimizationStore(
                workspace,
                generator.GENERATOR_VERSION,
            )
            job = store.create_job(
                "legacy-minimization",
                kind="coverage",
                source={"kind": "attribution", "path": "/job", "id": "attr-1"},
                items=(item,),
                starry_elf=executable,
                host_oracle=executable,
                max_qemu=4,
                expected_fingerprint=None,
            )
            metadata_path = job.path / "metadata.json"
            metadata = __import__("json").loads(metadata_path.read_text())
            metadata["schema_version"] = 1
            metadata["generator_version"] = "2"
            del metadata["target_set_id"]
            metadata_path.write_text(__import__("json").dumps(metadata))

            loaded = store.load_job(job.job_id)
            self.assertEqual(
                minimization_schema.job_target_set_id(loaded.metadata),
                "pipe-v1",
            )

    def test_fd_schema_v2_job_loads_only_with_pipe_fd_target(self):
        import generator
        import minimization
        import minimization_schema
        import minimization_store
        import reducer

        document = scenario.parse_document(
            "version 2\nscenario fd\npipe2 0 1 2048\nget-fd-flags 0\n"
        )
        item = minimization.MinimizationItem(
            scenario.canonical_digest(document),
            reducer.ReductionInput.initial(document),
            frozenset({"fd-region"}),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            executable = Path(sys.executable).resolve()
            store = minimization_store.MinimizationStore(
                workspace,
                generator.GENERATOR_VERSION,
            )
            job = store.create_job(
                "fd-minimization",
                kind="coverage",
                source={"kind": "attribution", "path": "/job", "id": "attr-2"},
                items=(item,),
                starry_elf=executable,
                host_oracle=executable,
                max_qemu=4,
                expected_fingerprint=None,
            )
            metadata_path = job.path / "metadata.json"
            metadata = __import__("json").loads(metadata_path.read_text())
            metadata["schema_version"] = 2
            metadata["generator_version"] = "3"
            metadata["target_set_id"] = "pipe-fd-v2"
            metadata_path.write_text(__import__("json").dumps(metadata))

            loaded = store.load_job(job.job_id)
            self.assertEqual(
                minimization_schema.job_target_set_id(loaded.metadata),
                "pipe-fd-v2",
            )

            metadata["target_set_id"] = "pipe-vector-v3"
            metadata_path.write_text(__import__("json").dumps(metadata))
            with self.assertRaisesRegex(Exception, "unsupported minimization target set"):
                store.load_job(job.job_id)

    def test_vector_schema_v3_job_loads_only_with_pipe_vector_target(self):
        import generator
        import minimization
        import minimization_schema
        import minimization_store
        import reducer

        document = scenario.parse_document(
            "version 3\nscenario vector\npipe2 0 1 2048\nreadv 0 0 0 0\n"
        )
        item = minimization.MinimizationItem(
            scenario.canonical_digest(document),
            reducer.ReductionInput.initial(document),
            frozenset({"vector-region"}),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            executable = Path(sys.executable).resolve()
            store = minimization_store.MinimizationStore(
                workspace,
                generator.GENERATOR_VERSION,
            )
            job = store.create_job(
                "vector-minimization",
                kind="coverage",
                source={"kind": "attribution", "path": "/job", "id": "attr-3"},
                items=(item,),
                starry_elf=executable,
                host_oracle=executable,
                max_qemu=4,
                expected_fingerprint=None,
            )
            metadata_path = job.path / "metadata.json"
            metadata = __import__("json").loads(metadata_path.read_text())
            metadata["schema_version"] = 3
            metadata["generator_version"] = "4"
            metadata["target_set_id"] = "pipe-vector-v3"
            metadata_path.write_text(__import__("json").dumps(metadata))

            loaded = store.load_job(job.job_id)
            self.assertEqual(
                minimization_schema.job_target_set_id(loaded.metadata),
                "pipe-vector-v3",
            )

            metadata["target_set_id"] = "pipe-poll-v4"
            metadata_path.write_text(__import__("json").dumps(metadata))
            with self.assertRaisesRegex(Exception, "unsupported minimization target set"):
                store.load_job(job.job_id)

    def test_changed_active_elf_moves_job_to_stale_failure(self):
        import minimization
        import minimization_store
        import reducer

        document = scenario.parse_document(
            "version 1\nscenario coverage\npipe2 0 1\nwrite 1 8 65\n"
        )
        item = minimization.MinimizationItem(
            scenario.canonical_digest(document),
            reducer.ReductionInput.initial(document),
            frozenset({"pipe.rs:1:1"}),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            first_elf = workspace / "first-elf"
            second_elf = workspace / "second-elf"
            first_elf.write_bytes(Path(sys.executable).resolve().read_bytes())
            second_elf.write_bytes(first_elf.read_bytes() + b"changed")
            store = minimization_store.MinimizationStore(
                workspace,
                generator_version="scenario-v1",
            )
            job = store.create_job(
                "minimize-coverage-0001",
                kind="coverage",
                source={"kind": "attribution", "path": "/job", "id": "attr-1"},
                items=(item,),
                starry_elf=first_elf,
                host_oracle=first_elf,
                max_qemu=4,
                expected_fingerprint=None,
            )

            failure = store.mark_stale_if_elf_changed(job, second_elf)

            self.assertIsNotNone(failure)
            self.assertFalse(job.path.exists())
            stale_metadata = __import__("json").loads(
                (failure / "metadata.json").read_text()
            )
            self.assertEqual(stale_metadata["state"], "stale")

    def test_uncommitted_checkpoint_repeats_the_same_candidate_on_resume(self):
        import minimization
        import minimization_store
        import reducer

        document = scenario.parse_document(
            "version 1\nscenario crash\npipe2 0 1\nwrite 1 8192 255\n"
        )
        item = minimization.MinimizationItem(
            scenario.canonical_digest(document),
            reducer.ReductionInput.initial(document),
            frozenset({"pipe.rs:1:1"}),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            executable = Path(sys.executable).resolve()
            store = minimization_store.MinimizationStore(workspace, "scenario-v1")
            job = store.create_job(
                "minimize-checkpoint-crash",
                kind="coverage",
                source={"kind": "attribution", "path": "/job", "id": "attr-1"},
                items=(item,),
                starry_elf=executable,
                host_oracle=executable,
                max_qemu=4,
                expected_fingerprint=None,
            )
            job = store.record_validation(
                job,
                result_category="passed",
                satisfied=True,
                evidence_digest="a" * 64,
                duration_seconds=0,
            )
            session = store.restore_session(job)
            scheduled = session.next_candidate()
            self.assertIsNotNone(scheduled)

            # Simulate a crash after the checkpoint rename but before metadata commit.
            store.save_best_checkpoint(
                job,
                scheduled.item_index,
                scheduled.candidate.reduction_input,
            )
            resumed = store.restore_session(job)
            repeated = resumed.next_candidate()

        self.assertEqual(repeated.candidate.digest, scheduled.candidate.digest)
        self.assertEqual(repeated.candidate.transform, scheduled.candidate.transform)

    def test_failed_saved_proof_runs_the_second_proof_then_becomes_unstable(self):
        import corpus
        import generator
        import guest_result
        import minimization
        import minimization_campaign
        import minimization_store
        import reducer

        document = scenario.parse_document(
            "version 1\nscenario proof\npipe2 0 1\nwrite 1 8 65\n"
        )
        item = minimization.MinimizationItem(
            scenario.canonical_digest(document),
            reducer.ReductionInput.initial(document),
            frozenset({"pipe.rs:1:1"}),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            executable = Path(sys.executable).resolve()
            store = minimization_store.MinimizationStore(
                workspace,
                generator.GENERATOR_VERSION,
            )
            job = store.create_job(
                "minimize-proof-crash",
                kind="coverage",
                source={"kind": "attribution", "path": "/job", "id": "attr-1"},
                items=(item,),
                starry_elf=executable,
                host_oracle=executable,
                max_qemu=4,
                expected_fingerprint=None,
            )
            job = store.record_validation(
                job,
                result_category="passed",
                satisfied=True,
                evidence_digest="a" * 64,
                duration_seconds=0,
            )
            job = store.begin_final_proof(job, store.restore_session(job))
            job = store.record_proof(
                job,
                result_category="passed",
                decision=minimization.PredicateDecision.REJECT,
                satisfied=False,
                evidence_digest="b" * 64,
                duration_seconds=0,
            )
            profraw = workspace / "fresh.profraw"
            profraw.write_bytes(b"profile")
            qemu = mock.Mock(
                return_value=guest_result.GuestExecutionResult(
                    guest_result.GuestResultCategory.PASSED,
                    "passed",
                    (profraw,),
                    0,
                )
            )

            def record_host(_elf, _ops, trace):
                trace.write_bytes(b"trace")
                return SimpleNamespace(passed=True, parser_rejection=False, log="recorded")

            runtime = minimization_campaign.MinimizationRuntime(
                record_host=record_host,
                run_guest_compare=qemu,
                extract_regions=lambda _profraws, _elf, _target: {"pipe.rs:1:1"},
                coverage_object=lambda _workspace: executable,
            )

            outcome = minimization_campaign.resume_minimization_job(
                workspace,
                corpus.CorpusStore(workspace),
                store,
                job,
                runtime,
            )

            failure = workspace / "coverage/pipe-oracle-fuzz/failures/minimization-minimize-proof-crash"
            failed_metadata = __import__("json").loads(
                (failure / "metadata.json").read_text()
            )

        self.assertTrue(outcome.failed)
        self.assertEqual(outcome.category, "unstable")
        self.assertEqual(failed_metadata["state"], "unstable")
        qemu.assert_called_once()

    def test_original_host_failure_is_unstable_without_consuming_qemu(self):
        import corpus
        import generator
        import minimization
        import minimization_campaign
        import minimization_store
        import reducer

        document = scenario.parse_document(
            "version 1\nscenario host-failure\npipe2 0 1\n"
        )
        item = minimization.MinimizationItem(
            scenario.canonical_digest(document),
            reducer.ReductionInput.initial(document),
            frozenset({"pipe.rs:1:1"}),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            executable = Path(sys.executable).resolve()
            store = minimization_store.MinimizationStore(
                workspace,
                generator.GENERATOR_VERSION,
            )
            job = store.create_job(
                "minimize-original-host-failure",
                kind="coverage",
                source={"kind": "attribution", "path": "/job", "id": "attr-1"},
                items=(item,),
                starry_elf=executable,
                host_oracle=executable,
                max_qemu=4,
                expected_fingerprint=None,
            )
            qemu = mock.Mock(side_effect=AssertionError("unexpected QEMU"))
            runtime = minimization_campaign.MinimizationRuntime(
                record_host=lambda _elf, _ops, _trace: SimpleNamespace(
                    passed=False,
                    parser_rejection=False,
                    log="host record failed",
                ),
                run_guest_compare=qemu,
                extract_regions=mock.Mock(side_effect=AssertionError("unexpected coverage")),
                coverage_object=lambda _workspace: executable,
            )

            outcome = minimization_campaign.resume_minimization_job(
                workspace,
                corpus.CorpusStore(workspace),
                store,
                job,
                runtime,
            )
            failed = store.load_failed_job(job.job_id)

        self.assertTrue(outcome.failed)
        self.assertEqual(outcome.category, "unstable")
        self.assertEqual(failed.metadata["validation_qemu"], 0)
        self.assertEqual(
            failed.metadata["validation"]["result_category"],
            "oracle-failure",
        )
        qemu.assert_not_called()

    def test_version_digest_and_symlink_corruption_fail_closed(self):
        import minimization
        import minimization_store
        import reducer

        document = scenario.parse_document(
            "version 1\nscenario corrupt\npipe2 0 1\n"
        )
        item = minimization.MinimizationItem(
            scenario.canonical_digest(document),
            reducer.ReductionInput.initial(document),
            frozenset({"pipe.rs:1:1"}),
        )
        mutations = ("version", "elf-digest", "input-symlink")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary_directory:
                workspace = Path(temporary_directory)
                executable = Path(sys.executable).resolve()
                store = minimization_store.MinimizationStore(workspace, "scenario-v1")
                job = store.create_job(
                    f"minimize-corrupt-{mutation}",
                    kind="coverage",
                    source={"kind": "attribution", "path": "/job", "id": "attr-1"},
                    items=(item,),
                    starry_elf=executable,
                    host_oracle=executable,
                    max_qemu=4,
                    expected_fingerprint=None,
                )
                if mutation == "version":
                    metadata_path = job.path / "metadata.json"
                    metadata = __import__("json").loads(metadata_path.read_text())
                    metadata["schema_version"] = 5
                    metadata_path.write_text(__import__("json").dumps(metadata))
                elif mutation == "elf-digest":
                    with (job.path / "starryos").open("ab") as output:
                        output.write(b"corrupt")
                else:
                    input_path = job.path / "inputs" / f"{item.original_digest}.ops"
                    input_path.unlink()
                    input_path.symlink_to(job.path / "starryos")

                with self.assertRaises(Exception):
                    store.load_job(job.job_id)

    def test_coverage_campaign_counts_validation_candidates_and_two_proofs(self):
        import corpus
        import generator
        import guest_result
        import minimization
        import minimization_campaign
        import minimization_store
        import reducer

        document = scenario.parse_document(
            "version 1\nscenario campaign\npipe2 0 1\nwrite 1 8192 255\npoll 0 32767\n"
        )
        item = minimization.MinimizationItem(
            scenario.canonical_digest(document),
            reducer.ReductionInput.initial(document),
            frozenset({"pipe.rs:1:1"}),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            active_elf = workspace / "starryos"
            active_elf.write_bytes(Path(sys.executable).resolve().read_bytes())
            profraw = workspace / "fresh.profraw"
            profraw.write_bytes(b"profile")
            corpus_store = corpus.CorpusStore(
                workspace,
                generator_version=generator.GENERATOR_VERSION,
            )
            corpus_store.admit_attributed_entry(
                document,
                corpus.CorpusProvenance.generated(),
                {"pipe.rs:1:1"},
                "attribution-0001",
            )
            store = minimization_store.MinimizationStore(
                workspace,
                generator_version=generator.GENERATOR_VERSION,
            )
            job = store.create_job(
                "minimize-coverage-campaign",
                kind="coverage",
                source={"kind": "attribution", "path": "/job", "id": "attr-1"},
                items=(item,),
                starry_elf=active_elf,
                host_oracle=active_elf,
                max_qemu=2,
                expected_fingerprint=None,
            )
            calls = []

            def record_host(_elf, _ops, trace):
                trace.write_bytes(b"trace")
                return SimpleNamespace(passed=True, parser_rejection=False, log="recorded")

            def run_guest(_workspace, _artifact_dir, _pinned):
                calls.append("qemu")
                return guest_result.GuestExecutionResult(
                    guest_result.GuestResultCategory.PASSED,
                    "passed",
                    (profraw,),
                    0,
                )

            runtime = minimization_campaign.MinimizationRuntime(
                record_host=record_host,
                run_guest_compare=run_guest,
                extract_regions=lambda _profraws, _elf, _target: {"pipe.rs:1:1"},
                coverage_object=lambda _workspace: active_elf,
            )

            outcome = minimization_campaign.resume_minimization_job(
                workspace,
                corpus_store,
                store,
                job,
                runtime,
            )
            completed = store.load_job(job.job_id)

        self.assertFalse(outcome.failed)
        self.assertEqual(outcome.completion, "budget-limited")
        self.assertEqual(len(calls), 5)
        self.assertEqual(completed.metadata["validation_qemu"], 1)
        self.assertEqual(completed.metadata["candidate_qemu"], 2)
        self.assertEqual(completed.metadata["proof_qemu"], 2)

    def test_mismatch_campaign_preserves_fingerprint_and_original_artifact(self):
        import artifact
        import common
        import corpus
        import fingerprint
        import generator
        import guest_result
        import minimization
        import minimization_campaign
        import minimization_store
        import reducer

        document = scenario.parse_document(
            "version 1\n"
            "scenario mismatch\n"
            "pipe2 0 1\n"
            "write 1 8192 255\n"
            "poll 0 32767\n"
        )
        expected = fingerprint.MismatchFingerprint(
            fingerprint.OperationOrigin(0, 1),
            "write",
            ("result", "errno"),
            "error",
            "zero",
            32,
            None,
        )
        item = minimization.MinimizationItem(
            scenario.canonical_digest(document),
            reducer.ReductionInput.initial(document),
            critical_origin=expected.operation_origin,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            executable = Path(sys.executable).resolve()
            source = workspace / "original-failure"
            source.mkdir()
            encoded = scenario.serialize_document(document).encode("utf-8")
            (source / "pipe.ops").write_bytes(encoded)
            (source / "input.bin").write_bytes(encoded)
            (source / "linux.trace").write_bytes(b"trace")
            (source / "guest.log").write_text("original semantic mismatch")
            (source / "pipe-linux-oracle").write_bytes(executable.read_bytes())
            (source / "starryos").write_bytes(executable.read_bytes())
            metadata = artifact.build_failure_metadata_v2(
                source,
                generator_version=generator.GENERATOR_VERSION,
                fuzz_seed=42,
                batch_index=1,
                command="fuzz.py",
                result_category=guest_result.GuestResultCategory.SEMANTIC_MISMATCH,
                mismatch_fingerprint=expected,
            )
            common.save_metadata(source, metadata)

            corpus_store = corpus.CorpusStore(workspace)
            store = minimization_store.MinimizationStore(
                workspace,
                generator.GENERATOR_VERSION,
            )
            job = store.create_job(
                "minimize-mismatch-campaign",
                kind="mismatch",
                source={
                    "kind": "failure",
                    "path": str(source),
                    "id": source.name,
                },
                items=(item,),
                starry_elf=executable,
                host_oracle=executable,
                max_qemu=1,
                expected_fingerprint=expected,
            )
            qemu_calls = []

            def record_host(_elf, _ops, trace):
                trace.write_bytes(b"fresh trace")
                return SimpleNamespace(passed=True, parser_rejection=False, log="recorded")

            def run_guest(_workspace, artifact_dir, _pinned):
                qemu_calls.append("qemu")
                candidate = scenario.parse_document(
                    (artifact_dir / "pipe.ops").read_bytes()
                )
                operations = candidate.scenarios[0].operations
                operation_index = next(
                    index
                    for index, operation in enumerate(operations)
                    if scenario.operation_name(operation) == "write"
                )
                operation_text = scenario.format_operation(operations[operation_index])
                difference = guest_result.OperationDifference(
                    0,
                    operation_index,
                    operation_text,
                    4,
                    ("result", "errno"),
                    -1,
                    32,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                return guest_result.GuestExecutionResult(
                    guest_result.GuestResultCategory.SEMANTIC_MISMATCH,
                    "same semantic mismatch",
                    (),
                    1,
                    difference,
                )

            runtime = minimization_campaign.MinimizationRuntime(
                record_host=record_host,
                run_guest_compare=run_guest,
                extract_regions=lambda _profraws, _elf, _target: set(),
                coverage_object=lambda _workspace: executable,
            )

            outcome = minimization_campaign.resume_minimization_job(
                workspace,
                corpus_store,
                store,
                job,
                runtime,
            )
            minimized = next(
                corpus_store.failures_dir.glob("original-failure_minimized_*")
            )
            minimized_metadata = artifact.validate_failure(minimized)
            original_retained = source.is_dir()

        self.assertFalse(outcome.failed)
        self.assertEqual(outcome.completion, "budget-limited")
        self.assertEqual(len(qemu_calls), 4)
        self.assertTrue(original_retained)
        self.assertLess(
            minimized_metadata["ops_size"],
            metadata["ops_size"],
        )
        self.assertEqual(
            minimized_metadata["mismatch_fingerprint"],
            expected.as_metadata(),
        )


if __name__ == "__main__":
    unittest.main()
