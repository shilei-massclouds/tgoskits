import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = WORKSPACE_ROOT / "scripts/eventfd-oracle"
CASE_DIR = WORKSPACE_ROOT / "test-suit/starryos/qemu/eventfd-linux-oracle"
CORPUS_PATH = CASE_DIR / "c/corpus/eventfd.ops"
sys.path.insert(0, str(SCRIPT_DIR))

import artifact  # noqa: E402
import adapter  # noqa: E402
import attribution  # noqa: E402
import batch_execution  # noqa: E402
import fingerprint  # noqa: E402
import fuzz  # noqa: E402
import generator  # noqa: E402
import guest_result  # noqa: E402
import jobs  # noqa: E402
import minimization  # noqa: E402
import mutation  # noqa: E402
import reducer  # noqa: E402
import runner  # noqa: E402
import scenario  # noqa: E402
import store  # noqa: E402
from linux_oracle.campaign import CampaignBudget  # noqa: E402
from linux_oracle import driver as common_driver  # noqa: E402


class EventFdOracleTests(unittest.TestCase):
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

    def test_codec_round_trip_covers_every_operation(self):
        encoded = (
            "version 0x1\n"
            "scenario arbitrary\n"
            "eventfd 0x0 7\n"
            "eventfd2 1 0 526336\n"
            "read 1 0x10 0\n"
            "write 1 8 0 18446744073709551614\n"
            "dup 1 2\n"
            "dup2 2 3\n"
            "dup3 3 4 524288\n"
            "get-status-flags 4\n"
            "set-status-flags 4 2048\n"
            "get-fd-flags 4\n"
            "set-fd-flags 4 1\n"
            "poll-many 3 0 4 5 1 -2 1 1 2147483647 4\n"
            "close 4\n"
        )
        document = scenario.parse_document(encoded)
        canonical = scenario.serialize_document(document)
        self.assertEqual(scenario.parse_document(canonical), document)
        self.assertNotIn("0x", canonical)
        self.assertIn("scenario generated-0001", canonical)
        self.assertEqual(
            [scenario.operation_name(item) for item in document.scenarios[0].operations],
            [
                "eventfd",
                "eventfd2",
                "read",
                "write",
                "dup",
                "dup2",
                "dup3",
                "get-status-flags",
                "set-status-flags",
                "get-fd-flags",
                "set-fd-flags",
                "poll-many",
                "close",
            ],
        )

    def test_resource_state_models_normal_and_semaphore_counter(self):
        normal = scenario.parse_document(
            "version 1\nscenario x\neventfd2 0 7 2048\nread 0 8 0\n"
        )
        normal_state = scenario.analyze_scenario(normal.scenarios[0])
        self.assertEqual(normal_state.event(0).count, 0)

        semaphore = scenario.parse_document(
            "version 1\nscenario x\neventfd2 0 3 2049\nread 0 8 0\nread 0 8 1\n"
        )
        semaphore_state = scenario.analyze_scenario(semaphore.scenarios[0])
        self.assertEqual(semaphore_state.event(0).count, 1)

    def test_empty_read_and_overflow_write_require_nonblocking(self):
        invalid = (
            "version 1\nscenario x\neventfd 0 0\nread 0 8 0\n"
        )
        with self.assertRaisesRegex(scenario.ScenarioCodecError, "blocking-operation"):
            scenario.parse_document(invalid)

        oversized = (
            "version 1\nscenario x\neventfd 0 4294967295\n"
            "write 0 16 0 18446744073709551613\n"
        )
        with self.assertRaisesRegex(scenario.ScenarioCodecError, "blocking-operation"):
            scenario.parse_document(oversized)
        invalid = (
            "version 1\nscenario x\neventfd 0 0\n"
            "write 0 8 0 18446744073709551614\nwrite 0 8 0 1\n"
        )
        with self.assertRaisesRegex(scenario.ScenarioCodecError, "blocking-operation"):
            scenario.parse_document(invalid)

    def test_alias_shares_nonblock_but_not_cloexec(self):
        document = scenario.parse_document(
            "version 1\nscenario x\n"
            "eventfd2 0 1 526336\n"
            "dup 0 1\n"
            "set-status-flags 1 0\n"
            "set-fd-flags 1 1\n"
        )
        state = scenario.analyze_scenario(document.scenarios[0])
        self.assertFalse(state.description(0).nonblocking)
        self.assertFalse(state.description(1).nonblocking)
        self.assertTrue(state.descriptor(0).cloexec)
        self.assertTrue(state.descriptor(1).cloexec)

    def test_dup2_dup3_replace_and_use_after_close_is_safe(self):
        document = scenario.parse_document(
            "version 1\nscenario x\n"
            "eventfd2 0 1 2048\n"
            "eventfd2 1 2 2048\n"
            "dup2 0 1\n"
            "dup3 1 2 524288\n"
            "close 1\n"
            "read 1 8 0\n"
        )
        state = scenario.analyze_scenario(document.scenarios[0])
        self.assertIsNone(state.descriptor(1))
        self.assertEqual(state.descriptor(2).description_id, state.descriptor(0).description_id)
        self.assertTrue(state.descriptor(2).cloexec)

    def test_unknown_creation_and_dup3_flags_are_explicit_error_paths(self):
        document = scenario.parse_document(
            "version 1\nscenario x\n"
            "eventfd2 0 0 1073741824\n"
            "get-status-flags 0\n"
            "dup3 0 1 1073741824\n"
        )
        state = scenario.analyze_scenario(document.scenarios[0])
        self.assertIsNone(state.descriptor(0))
        self.assertIsNone(state.descriptor(1))

    def test_checked_corpus_is_canonical_and_covers_boundaries(self):
        encoded = CORPUS_PATH.read_bytes()
        document = scenario.parse_document(encoded)
        scenario.validate_entry_limits(document)
        self.assertEqual(scenario.serialize_document(document).encode(), encoded)
        operations = [item for group in document.scenarios for item in group.operations]
        reads = [item for item in operations if isinstance(item, scenario.Read)]
        writes = [item for item in operations if isinstance(item, scenario.Write)]
        self.assertTrue({0, 7, 8, 9, 16} <= {item.length for item in reads})
        self.assertTrue({0, 7, 8, 9} <= {item.length for item in writes})
        self.assertIn(scenario.MAX_U64, {item.value for item in writes})
        self.assertIn(scenario.MAX_COUNTER, {item.value for item in writes})

    def test_checked_corpus_records_identically_three_times_and_compares(self):
        traces = []
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for index in range(3):
                trace = root / f"trace-{index}"
                recorded = subprocess.run(
                    [str(self.oracle), "--record", str(CORPUS_PATH), str(trace)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(recorded.returncode, 0, recorded.stderr)
                traces.append(trace.read_bytes())
            self.assertEqual(traces[0], traces[1])
            self.assertEqual(traces[1], traces[2])
            compared = subprocess.run(
                [str(self.oracle), "--compare", str(CORPUS_PATH), str(root / "trace-0")],
                capture_output=True,
                text=True,
            )
        self.assertEqual(compared.returncode, 0, compared.stderr)
        self.assertIn("STARRY_EVENTFD_LINUX_ORACLE_PASSED: operations=107", compared.stdout)

    def test_generated_inputs_are_deterministic_and_accepted_by_host_harness(self):
        first = [generator.generate_input(generator.CampaignRng(seed)) for seed in range(8)]
        second = [generator.generate_input(generator.CampaignRng(seed)) for seed in range(8)]
        self.assertEqual(
            [(item.digest, item.encoded) for item in first],
            [(item.digest, item.encoded) for item in second],
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for index, generated in enumerate(first):
                ops = root / f"{index}.ops"
                trace = root / f"{index}.trace"
                ops.write_bytes(generated.encoded)
                recorded = subprocess.run(
                    [str(self.oracle), "--record", str(ops), str(trace)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(recorded.returncode, 0, recorded.stderr)

    def test_standard_campaign_batch_combines_entry_limited_candidates(self):
        generated = [generator.canonicalize_seed(seed) for seed in range(32)]
        inputs = tuple(
            batch_execution.BatchInput(item.digest, item.encoded)
            for item in generated
        )

        prepared = batch_execution.prepare_batch(inputs)

        self.assertEqual(len(prepared.inputs), 32)
        self.assertGreater(prepared.scenario_count, scenario.MAX_SCENARIOS_PER_ENTRY)
        self.assertEqual(
            hashlib.sha256(prepared.encoded).hexdigest(), prepared.scenario_digest
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            ops = root / "eventfd.ops"
            trace = root / "linux.trace"
            host = root / "eventfd-linux-oracle"
            starry = root / "starryos"
            ops.write_bytes(prepared.encoded)
            trace.write_bytes(b"combined trace")
            host.write_bytes(b"host elf")
            starry.write_bytes(b"starry elf")

            saved = artifact.save_failure(
                root / "failure",
                ops_path=ops,
                trace_path=trace,
                host_elf_path=host,
                starry_elf_path=starry,
                guest_log="combined batch failure",
                profraw_paths=(),
                result_category="semantic-mismatch",
                mismatch=None,
            )

        self.assertEqual(saved.metadata["scenario_sha256"], prepared.scenario_digest)

    def test_every_mutation_kind_changes_digest_and_remains_executable(self):
        parent = generator.generate_document(generator.CampaignRng(42))
        donor = generator.generate_document(generator.CampaignRng(43))
        parent_digest = scenario.canonical_digest(parent)
        for index, kind in enumerate(mutation.MUTATION_KINDS):
            with self.subTest(kind=kind):
                candidate = mutation.mutate_document(
                    generator.CampaignRng(100 + index),
                    parent,
                    donor,
                    requested_kind=kind,
                )
                self.assertIs(
                    candidate.classification,
                    mutation.CandidateClassification.EXECUTABLE,
                )
                self.assertNotEqual(candidate.digest, parent_digest)
                scenario.validate_entry_limits(candidate.document)

    def test_reducer_preserves_required_origin_and_resource_validity(self):
        document = generator.generate_document(generator.CampaignRng(42))
        origin_document = reducer.with_origins(document)
        required = origin_document.scenarios[0].operations[-1].origin
        candidates = list(
            reducer.reduction_candidates(origin_document, required_origin=required)
        )
        self.assertTrue(candidates)
        for candidate in candidates:
            self.assertTrue(reducer.contains_origin(candidate.document, required))
            scenario.validate_entry_limits(candidate.document.plain())
            self.assertLess(candidate.complexity, reducer.complexity_key(origin_document))

    def test_attribution_is_exact_and_deterministic(self):
        result = attribution.attribute_regions(
            {"b": {"r1", "r2"}, "a": {"r1", "r3"}, "c": {"r2"}},
            {"r1", "r2", "r3"},
        )
        self.assertEqual(result.representatives, ("a", "b"))
        responsibilities = attribution.assigned_responsibilities(result)
        self.assertEqual(set().union(*map(set, responsibilities.values())), {"r1", "r2", "r3"})

    def test_minimization_requires_validation_and_two_final_proofs(self):
        document = scenario.parse_document(
            "version 1\nscenario x\neventfd2 0 1 2048\n"
            "get-fd-flags 0\nget-status-flags 0\nread 0 8 0\n"
        )
        calls = []

        def predicate(candidate):
            calls.append(candidate)
            return reducer.contains_origin(candidate, reducer.OperationOrigin(0, 3))

        result = minimization.minimize(
            document,
            predicate,
            max_candidates=8,
            required_origin=reducer.OperationOrigin(0, 3),
        )
        self.assertTrue(result.validation_passed)
        self.assertEqual(result.final_proofs, (True, True))
        self.assertIn(result.mode, ("minimized", "budget-limited"))
        self.assertGreaterEqual(len(calls), 3)

    def test_minimization_preserves_infrastructure_failure_for_recovery(self):
        generated = generator.canonicalize_seed(3)
        with tempfile.TemporaryDirectory() as temporary_directory:
            corpus_store = store.CorpusStore(Path(temporary_directory))
            task_store = jobs.TaskStore(corpus_store.root, "minimization")
            task = task_store.claim(
                task_store.create(
                    "minimization-infrastructure",
                    (generated.encoded,),
                    {"kind": "regression"},
                )
            )
            observation = common_driver.ExecutionObservation(
                False, "infrastructure-failure", (), "f" * 64
            )

            with mock.patch.object(
                common_driver, "execute_inputs", return_value=observation
            ):
                with self.assertRaisesRegex(
                    common_driver.CampaignReplayError,
                    "minimization replay failed: infrastructure-failure",
                ):
                    common_driver.run_minimization_task(
                        adapter.SPEC,
                        adapter.SPEC.campaign_hooks,
                        Path(temporary_directory),
                        corpus_store,
                        Path("host-oracle"),
                        task_store,
                        task,
                        generated.encoded,
                        {"region:1:1"},
                        Path("starryos"),
                        CampaignBudget(64),
                        8,
                        0,
                    )

            recovered = task_store.load(task.path)
            self.assertEqual(recovered.metadata["state"], "running")
            self.assertIsNone(recovered.metadata["result"])

    def test_recovered_attribution_commits_its_coverage_index(self):
        generated = generator.canonicalize_seed(4)
        elf_digest = "e" * 64
        target_regions = ["event.rs:1:1", "event.rs:2:1"]
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            corpus_store = store.CorpusStore(workspace)
            task_store = jobs.TaskStore(corpus_store.root, "attribution")
            task_store.create(
                "attribution-recovery",
                (generated.encoded,),
                {
                    "target_regions": target_regions,
                    "starry_elf_sha256": elf_digest,
                    "max_minimize": 0,
                    "minimize_enabled": False,
                    "batch_index": 0,
                },
            )

            with (
                mock.patch.object(
                    common_driver,
                    "fixed_elf_from_digest",
                    return_value=workspace / "starryos",
                ),
                mock.patch.object(
                    common_driver, "run_attribution_task", return_value=[]
                ),
            ):
                common_driver.recover_pending_tasks(
                    adapter.SPEC,
                    adapter.SPEC.campaign_hooks,
                    workspace,
                    corpus_store,
                    Path("host-oracle"),
                    CampaignBudget(64),
                )

            self.assertEqual(
                set(corpus_store.load_coverage(elf_digest)), set(target_regions)
            )

    def test_guest_difference_parser_and_fingerprint(self):
        log = (
            "STARRY_EVENTFD_LINUX_ORACLE_FAILED: host=linux/x86 line=4 scenario=0 "
            'operation=2 text="read 0 8 0" difference_mask=0x00000018 '
            "expected={kind=3,result=-1,errno=11,value=0,data_len=16} "
            "actual={kind=3,result=8,errno=0,value=0,data_len=16}\n"
        )
        difference = guest_result.parse_operation_difference(log)
        self.assertIsNotNone(difference)
        item = fingerprint.MismatchFingerprint.from_difference(
            difference, reducer.OperationOrigin(0, 2)
        )
        self.assertEqual(item.operation_kind, "read")
        self.assertEqual(item.difference_fields, ("result", "errno"))

    def test_guest_difference_parser_accepts_serial_wrapping(self):
        log = (
            "STARRY_EVENTFD_LINUX_ORACLE_FAILED: host=5.15.0-186-generic/x86_\n"
            "=== FAIL PATTERN MATCHED: (?m)^STARRY_EVENTFD_LINUX_ORACLE_FAILED:\n"
            "64 line=20 scenario=1 operation=16 text=\"write 5 7 1 1844674407370955\n"
            "1613\" difference_mask=0x00000010 "
            "expected={kind=4,result=-1,errno=22,\n"
            "value=0,data_len=0} actual={kind=4,result=-1,errno=14,value=0,data_le\n"
            "n=0}\n"
        )

        result = guest_result.classify_guest_execution(log, 1)

        self.assertIs(
            result.category, guest_result.GuestResultCategory.SEMANTIC_MISMATCH
        )
        self.assertIsNotNone(result.difference)
        self.assertEqual(result.difference.expected_errno, 22)
        self.assertEqual(result.difference.actual_errno, 14)

    def test_corpus_store_fails_closed_on_adapter_digest_and_unknown_field_tampering(self):
        generated = generator.canonicalize_seed(9)
        for mutation_kind in ("adapter", "digest", "unknown"):
            with self.subTest(mutation_kind=mutation_kind), tempfile.TemporaryDirectory() as temporary_directory:
                corpus_store = store.CorpusStore(Path(temporary_directory))
                entry = corpus_store.save_entry(generated.encoded, {"region:1:1"})
                metadata_path = entry.path / "metadata.json"
                metadata = json.loads(metadata_path.read_text())
                if mutation_kind == "adapter":
                    metadata["adapter_id"] = "wrong"
                elif mutation_kind == "digest":
                    metadata["scenario_sha256"] = "0" * 64
                else:
                    metadata["unexpected"] = True
                metadata_path.write_text(json.dumps(metadata))
                with self.assertRaises(store.PersistentStateError):
                    corpus_store.load_entries()

    def test_task_store_recovers_pending_tasks_in_sorted_order_and_rejects_wrong_adapter(self):
        first = generator.canonicalize_seed(1)
        second = generator.canonicalize_seed(2)
        ordered = sorted((first, second), key=lambda item: item.digest)
        with tempfile.TemporaryDirectory() as temporary_directory:
            task_store = jobs.TaskStore(Path(temporary_directory), "attribution")
            task_store.create("b-task", tuple(item.encoded for item in ordered))
            task_store.create("a-task", tuple(item.encoded for item in ordered))
            self.assertEqual(
                [task.metadata["task_id"] for task in task_store.pending()],
                ["a-task", "b-task"],
            )
            task = task_store.pending()[0]
            metadata_path = task.path / "metadata.json"
            metadata = json.loads(metadata_path.read_text())
            metadata["adapter_id"] = "pipe-v4"
            metadata_path.write_text(json.dumps(metadata))
            with self.assertRaises(store.PersistentStateError):
                task_store.load(task.path)

    def test_failure_artifact_rejects_trace_and_elf_tampering(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            trace = root / "trace"
            subprocess.run(
                [str(self.oracle), "--record", str(CORPUS_PATH), str(trace)],
                check=True,
                capture_output=True,
                text=True,
            )
            starry = root / "starryos"
            starry.write_bytes(b"fixed starry elf")
            profraw = root / "eventfd.profraw"
            profraw.write_bytes(b"profile")
            for target in ("linux.trace", "starryos"):
                with self.subTest(target=target):
                    destination = root / f"failure-{target}"
                    saved = artifact.save_failure(
                        destination,
                        ops_path=CORPUS_PATH,
                        trace_path=trace,
                        host_elf_path=self.oracle,
                        starry_elf_path=starry,
                        guest_log="semantic mismatch",
                        profraw_paths=(profraw,),
                        result_category="semantic-mismatch",
                        mismatch=None,
                    )
                    (saved.path / target).write_bytes(b"tampered")
                    with self.assertRaises(store.PersistentStateError):
                        artifact.load_failure(saved.path)

    def test_runner_uses_explicit_default_off_eventfd_case(self):
        config = (CASE_DIR / "qemu-x86_64.toml").read_text()
        self.assertIn('default_run = false', config)
        self.assertIn("STARRY_EVENTFD_LINUX_ORACLE_FAILED:", config)
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workspace = root / "workspace"
            artifacts = root / "artifacts"
            workspace.mkdir()
            artifacts.mkdir()
            for name in runner.REQUIRED_ARTIFACTS:
                (artifacts / name).write_bytes(b"x")
            with mock.patch.object(runner.subprocess, "run") as run:
                run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
                result = runner.run_guest_compare(workspace, artifacts)
            self.assertTrue(result.passed)
            self.assertIn("qemu/eventfd-linux-oracle", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
