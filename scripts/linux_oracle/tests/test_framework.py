"""Contract tests using a third adapter with deliberately distinct names."""

import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from linux_oracle.batch import BatchInput, HostRecordResult, execute_batch, prepare_batch
from linux_oracle.campaign import (
    CampaignBudget,
    CampaignBudgetExhausted,
    CampaignRequest,
    recover_tasks,
)
from linux_oracle.coverage import region_ids
from linux_oracle import driver
from linux_oracle import execution as common_execution
from linux_oracle.persistence import CampaignStore, PersistentStateError
from linux_oracle.replay import build_replay_invocation
from linux_oracle.spec import (
    AdapterSpec,
    ArtifactLayout,
    CampaignHooks,
    CampaignLayout,
    CodecSpec,
    CoverageTarget,
    OutcomeSetHooks,
    QemuSpec,
    ReductionHooks,
)
from linux_oracle.tasks import TaskStore
from linux_oracle.task_execution import TaskRuntime, run_minimization_task


@dataclass(frozen=True)
class FakeGuestResult:
    passed: bool
    log: str
    profraw_paths: tuple[Path, ...]


def parse_fake(encoded: bytes) -> tuple[str, ...]:
    try:
        text = encoded.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("fake input is not ASCII") from error
    lines = text.splitlines()
    if not lines or lines[0] != "faux.ops v7" or text != "\n".join(lines) + "\n":
        raise ValueError("fake input header or newline is invalid")
    if any(not line.startswith("item ") for line in lines[1:]):
        raise ValueError("fake operation is invalid")
    return tuple(lines[1:])


def serialize_fake(document: object) -> bytes:
    return ("faux.ops v7\n" + "".join(f"{item}\n" for item in document)).encode(
        "ascii"
    )


def combine_fake(documents) -> tuple[str, ...]:
    return tuple(item for document in documents for item in document)


def validate_fake(document: object) -> None:
    if not document or len(document) > 4:
        raise ValueError("fake entry size is invalid")


def record_fake(_elf: Path, _scenario: Path, trace: Path) -> HostRecordResult:
    trace.write_bytes(b"faux trace\n")
    return HostRecordResult(True, False, "recorded")


def classify_fake(log, returncode, profraws=(), *, timed_out=False):
    return FakeGuestResult(not timed_out and returncode == 0, log, tuple(profraws))


class FakeRng:
    def __init__(self, seed: int):
        self.value = seed

    def range(self, start: int, stop: int) -> int:
        self.value += 1
        return start + self.value % (stop - start)


def find_fake_host(workspace: Path) -> Path:
    host = workspace / "source-runner"
    host.write_bytes(b"ELF")
    return host


def seed_fake(_workspace: Path):
    yield fake_input("seed").encoded


def generate_fake(_rng: object) -> bytes:
    return fake_input("generated").encoded


def mutate_fake(_rng: object, _parent: bytes, _donor: bytes) -> bytes:
    return fake_input("mutated").encoded


def reduce_fake_initial(encoded: bytes) -> bytes:
    return encoded


def reduce_fake_candidates(_encoded: bytes):
    return ()


FAKE_SPEC = AdapterSpec(
    adapter_id="faux-v7",
    adapter_version=7,
    corpus_version=3,
    generator_version="faux-generator-v2",
    artifacts=ArtifactLayout("faux.case", "reference.bin", "faux-runner"),
    campaign=CampaignLayout(Path("state/faux-campaign")),
    qemu=QemuSpec(
        case="qemu/faux-check",
        artifact_environment="FAUX_ARTIFACT_DIRECTORY",
        pinned_elf_environment="FAUX_PINNED_KERNEL",
        architecture="test-arch",
        profraw_path=Path("metrics/faux.profraw"),
        coverage_object_path=Path("out/faux-kernel"),
        timeout_seconds=17,
    ),
    coverage=CoverageTarget(
        "faux-target-v9", ("subsystem/alpha.py", "subsystem/beta.py")
    ),
    codec=CodecSpec(
        parse_fake,
        serialize_fake,
        combine_fake,
        validate_fake,
        len,
    ),
    host_record=record_fake,
    classify_guest=classify_fake,
    normalize_guest=lambda value: value,
    campaign_hooks=CampaignHooks(
        find_or_build_host=find_fake_host,
        seed_inputs=seed_fake,
        make_rng=FakeRng,
        generate=generate_fake,
        mutate=mutate_fake,
        reduction=ReductionHooks(
            initial=reduce_fake_initial,
            candidates=reduce_fake_candidates,
            encode=lambda encoded: encoded,
            complexity=lambda encoded: (len(encoded), encoded),
        ),
    ),
)


def fake_input(*items: str) -> BatchInput:
    encoded = serialize_fake(tuple(f"item {item}" for item in items))
    return BatchInput(hashlib.sha256(encoded).hexdigest(), encoded)


class FrameworkContractTests(unittest.TestCase):
    def test_host_unstable_initial_reduction_input_remains_fatal(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = CampaignStore(FAKE_SPEC, workspace)
            original = fake_input("unstable-original").encoded
            task_store = TaskStore(FAKE_SPEC, store.root, "minimization")
            task = task_store.claim(
                task_store.create("reject-unstable-original", (original,))
            )
            diagnostic = "host-unstable: allowed result set did not converge"

            def observe(*_args, **_kwargs):
                return driver.ExecutionObservation(
                    False, "host-unstable", (), "", diagnostic
                )

            runtime = TaskRuntime(
                FAKE_SPEC,
                FAKE_SPEC.campaign_hooks,
                workspace,
                store,
                workspace / "host-oracle",
                CampaignBudget(16),
                0,
                observe,
            )
            with self.assertRaisesRegex(
                driver.CampaignReplayError,
                "minimization replay failed: host-unstable",
            ):
                run_minimization_task(
                    runtime,
                    task_store,
                    task,
                    original,
                    {"region:1:1"},
                    workspace / "starryos",
                    8,
                )

            recovered = task_store.load(task.path)
            self.assertEqual(recovered.metadata["state"], "running")
            self.assertIsNone(recovered.metadata["result"])

    def test_host_schedule_timeout_initial_reduction_input_remains_fatal(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = CampaignStore(FAKE_SPEC, workspace)
            original = fake_input("timed-out-original").encoded
            task_store = TaskStore(FAKE_SPEC, store.root, "minimization")
            task = task_store.claim(
                task_store.create("reject-timeout-original", (original,))
            )
            diagnostic = (
                "STARRY_EVENTFD_LINUX_ORACLE_SCHEDULE_TIMEOUT: "
                'line=9 operation="write 1 8 0 1"'
            )

            def observe(*_args, **_kwargs):
                return driver.ExecutionObservation(
                    False,
                    "host-schedule-timeout",
                    (),
                    "",
                    diagnostic,
                )

            runtime = TaskRuntime(
                FAKE_SPEC,
                FAKE_SPEC.campaign_hooks,
                workspace,
                store,
                workspace / "host-oracle",
                CampaignBudget(16),
                0,
                observe,
            )
            with self.assertRaisesRegex(
                driver.CampaignReplayError,
                "minimization replay failed: host-schedule-timeout",
            ):
                run_minimization_task(
                    runtime,
                    task_store,
                    task,
                    original,
                    {"region:1:1"},
                    workspace / "starryos",
                    8,
                )

            recovered = task_store.load(task.path)
            self.assertEqual(recovered.metadata["state"], "running")
            self.assertIsNone(recovered.metadata["result"])

    def test_host_unstable_reduction_candidate_is_rejected_with_audit(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = CampaignStore(FAKE_SPEC, workspace)
            original = fake_input("keep", "drop").encoded
            unstable_candidate = fake_input("keep").encoded
            reduction = replace(
                FAKE_SPEC.campaign_hooks.reduction,
                candidates=lambda encoded: (
                    (unstable_candidate,) if encoded == original else ()
                ),
            )
            hooks = replace(FAKE_SPEC.campaign_hooks, reduction=reduction)
            task_store = TaskStore(FAKE_SPEC, store.root, "minimization")
            task = task_store.claim(
                task_store.create("reject-unstable-candidate", (original,))
            )
            diagnostic = (
                "host-unstable: scenario 0 has an alternative observed fewer "
                "than 3 times"
            )

            def observe(*args, **_kwargs):
                candidate = args[4][0].encoded
                if candidate == unstable_candidate:
                    return driver.ExecutionObservation(
                        False, "host-unstable", (), "", diagnostic
                    )
                return driver.ExecutionObservation(
                    True, "passed", ("region:1:1",), "e" * 64
                )

            runtime = TaskRuntime(
                FAKE_SPEC,
                hooks,
                workspace,
                store,
                workspace / "host-oracle",
                CampaignBudget(16),
                0,
                observe,
            )
            result = run_minimization_task(
                runtime,
                task_store,
                task,
                original,
                {"region:1:1"},
                workspace / "starryos",
                8,
            )

            self.assertEqual(result, original)
            completed = task_store.load(task.path)
            self.assertEqual(completed.metadata["state"], "completed")
            self.assertEqual(
                completed.metadata["result"]["candidate_rejections"],
                [
                    {
                        "category": "host-unstable",
                        "detail": diagnostic,
                        "digest": hashlib.sha256(unstable_candidate).hexdigest(),
                    }
                ],
            )

    def test_host_schedule_timeout_reduction_candidate_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            store = CampaignStore(FAKE_SPEC, workspace)
            original = fake_input("keep", "drop").encoded
            timed_out_candidate = fake_input("keep").encoded
            reduction = replace(
                FAKE_SPEC.campaign_hooks.reduction,
                candidates=lambda encoded: (
                    (timed_out_candidate,) if encoded == original else ()
                ),
            )
            hooks = replace(FAKE_SPEC.campaign_hooks, reduction=reduction)
            task_store = TaskStore(FAKE_SPEC, store.root, "minimization")
            task = task_store.claim(
                task_store.create("reject-timeout-candidate", (original,))
            )
            diagnostic = (
                "STARRY_EVENTFD_LINUX_ORACLE_SCHEDULE_TIMEOUT: "
                'line=9 operation="write 1 8 0 1"'
            )

            def observe(*args, **_kwargs):
                candidate = args[4][0].encoded
                if candidate == timed_out_candidate:
                    return driver.ExecutionObservation(
                        False,
                        "host-schedule-timeout",
                        (),
                        "",
                        diagnostic,
                    )
                return driver.ExecutionObservation(
                    True, "passed", ("region:1:1",), "e" * 64
                )

            runtime = TaskRuntime(
                FAKE_SPEC,
                hooks,
                workspace,
                store,
                workspace / "host-oracle",
                CampaignBudget(16),
                0,
                observe,
            )
            result = run_minimization_task(
                runtime,
                task_store,
                task,
                original,
                {"region:1:1"},
                workspace / "starryos",
                8,
            )

            self.assertEqual(result, original)
            completed = task_store.load(task.path)
            self.assertEqual(completed.metadata["state"], "completed")
            self.assertEqual(
                completed.metadata["result"]["candidate_rejections"],
                [
                    {
                        "category": "host-schedule-timeout",
                        "detail": diagnostic,
                        "digest": hashlib.sha256(timed_out_candidate).hexdigest(),
                    }
                ],
            )

    def test_qemu_budget_exhaustion_has_a_distinct_recoverable_category(self):
        budget = CampaignBudget(1)
        budget.charge()
        with self.assertRaisesRegex(CampaignBudgetExhausted, "QEMU budget exhausted"):
            budget.charge()

    def test_host_record_failure_does_not_charge_qemu_budget(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            host = workspace / "source-runner"
            host.write_bytes(b"ELF")
            store = CampaignStore(FAKE_SPEC, workspace)
            budget = CampaignBudget(1)

            @contextmanager
            def fail_on_host(*_args, **_kwargs):
                yield mock.Mock(
                    host_record=HostRecordResult(False, False, "host failed"),
                    guest_result=None,
                )

            with mock.patch.object(
                common_execution,
                "execute_batch",
                side_effect=fail_on_host,
            ):
                observation = common_execution.execute_inputs(
                    FAKE_SPEC,
                    workspace,
                    store,
                    host,
                    (fake_input("host-failure"),),
                    budget,
                    batch_index=0,
                )

            self.assertFalse(observation.passed)
            self.assertEqual(observation.category, "host-record-failure")
            self.assertEqual(budget.used, 0)

    def test_host_unstable_preserves_typed_category_and_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            host = workspace / "source-runner"
            host.write_bytes(b"ELF")
            store = CampaignStore(FAKE_SPEC, workspace)
            budget = CampaignBudget(1)
            diagnostic = (
                "host-unstable: scenario 3 added an alternative in the final 8 runs"
            )

            @contextmanager
            def fail_on_host(*_args, **_kwargs):
                yield mock.Mock(
                    host_record=HostRecordResult(False, False, diagnostic),
                    guest_result=None,
                )

            with mock.patch.object(
                common_execution,
                "execute_batch",
                side_effect=fail_on_host,
            ):
                observation = common_execution.execute_inputs(
                    FAKE_SPEC,
                    workspace,
                    store,
                    host,
                    (fake_input("host-unstable"),),
                    budget,
                    batch_index=0,
                )

            self.assertFalse(observation.passed)
            self.assertEqual(observation.category, "host-unstable")
            self.assertEqual(observation.detail, diagnostic)
            self.assertEqual(budget.used, 0)

    def test_host_schedule_timeout_preserves_typed_category_and_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            host = workspace / "source-runner"
            host.write_bytes(b"ELF")
            store = CampaignStore(FAKE_SPEC, workspace)
            budget = CampaignBudget(1)
            diagnostic = (
                "STARRY_PIPE_LINUX_ORACLE_SCHEDULE_TIMEOUT: "
                'line=9 operation="write 1 8 0 1"'
            )

            @contextmanager
            def fail_on_host(*_args, **_kwargs):
                yield mock.Mock(
                    host_record=HostRecordResult(False, False, diagnostic),
                    guest_result=None,
                )

            with mock.patch.object(
                common_execution,
                "execute_batch",
                side_effect=fail_on_host,
            ):
                observation = common_execution.execute_inputs(
                    FAKE_SPEC,
                    workspace,
                    store,
                    host,
                    (fake_input("host-schedule-timeout"),),
                    budget,
                    batch_index=0,
                )

            self.assertFalse(observation.passed)
            self.assertEqual(observation.category, "host-schedule-timeout")
            self.assertEqual(observation.detail, diagnostic)
            self.assertEqual(budget.used, 0)

    def test_pinned_replay_extracts_coverage_from_pinned_elf(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            host = workspace / "source-runner"
            host.write_bytes(b"host")
            active_elf = workspace / FAKE_SPEC.qemu.coverage_object_path
            active_elf.parent.mkdir(parents=True)
            active_elf.write_bytes(b"current Starry ELF")
            pinned_elf = workspace / "fixed" / "starryos"
            pinned_elf.parent.mkdir()
            pinned_elf.write_bytes(b"pinned Starry ELF")
            profraw = workspace / "faux.profraw"
            profraw.write_bytes(b"profile")
            execution = SimpleNamespace(
                prepared=SimpleNamespace(
                    document=parse_fake(fake_input("pinned").encoded)
                ),
                host_record=HostRecordResult(True, False, "recorded"),
                guest_result=SimpleNamespace(
                    passed=True,
                    category="passed",
                    log="passed",
                    profraw_paths=(profraw,),
                ),
            )

            @contextmanager
            def passed_batch(*_args, **_kwargs):
                yield execution

            store = CampaignStore(FAKE_SPEC, workspace)
            with (
                mock.patch.object(
                    common_execution,
                    "execute_batch",
                    side_effect=passed_batch,
                ),
                mock.patch.object(common_execution, "merge_profraws"),
                mock.patch.object(
                    common_execution,
                    "covered_region_set",
                    return_value={"fixed:1:1"},
                ) as covered,
            ):
                observation = common_execution.execute_inputs(
                    FAKE_SPEC,
                    workspace,
                    store,
                    host,
                    (fake_input("pinned"),),
                    CampaignBudget(1),
                    pinned_starry_elf=pinned_elf,
                    batch_index=0,
                )

            self.assertTrue(observation.passed)
            self.assertEqual(
                observation.starry_elf_digest,
                hashlib.sha256(pinned_elf.read_bytes()).hexdigest(),
            )
            self.assertEqual(covered.call_args.args[2], pinned_elf)

    def test_unexplained_concurrent_outcome_is_saved_as_a_question(self):
        spec = replace(
            FAKE_SPEC,
            outcomes=OutcomeSetHooks(
                b"FAUXOUT1",
                lambda document: tuple("0" * 64 for _item in document),
                lambda _document: (),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            host = workspace / "source-runner"
            host.write_bytes(b"host")
            kernel = workspace / spec.qemu.coverage_object_path
            kernel.parent.mkdir(parents=True)
            kernel.write_bytes(b"kernel")
            encoded = fake_input("question").encoded
            scenario = workspace / spec.artifacts.scenario_filename
            scenario.write_bytes(encoded)
            trace = workspace / spec.artifacts.trace_filename
            trace.write_bytes(b"trace")
            artifact_host = workspace / spec.artifacts.host_executable_filename
            artifact_host.write_bytes(b"artifact host")
            guest = SimpleNamespace(
                passed=False,
                category="unexplained-outcome",
                log="unexplained",
                profraw_paths=(),
                difference=SimpleNamespace(
                    scenario_index=0,
                    actual_digest="1" * 64,
                    actual_vector="00",
                ),
            )
            execution = SimpleNamespace(
                prepared=SimpleNamespace(document=parse_fake(encoded)),
                host_record=HostRecordResult(True, False, "recorded"),
                guest_result=guest,
                scenario_path=scenario,
                trace_path=trace,
                host_oracle_path=artifact_host,
            )

            @contextmanager
            def questioned_batch(*_args, **_kwargs):
                yield execution

            store = CampaignStore(spec, workspace)
            with mock.patch.object(
                common_execution,
                "execute_batch",
                side_effect=questioned_batch,
            ):
                observation = common_execution.execute_inputs(
                    spec,
                    workspace,
                    store,
                    host,
                    (fake_input("question"),),
                    CampaignBudget(1),
                    batch_index=0,
                )

            self.assertTrue(observation.passed)
            self.assertEqual(observation.category, "unexplained-outcome")
            self.assertFalse(store.failures_root.exists())
            self.assertEqual(len(tuple(store.questions_root.iterdir())), 1)

    def test_adapter_spec_is_immutable_and_has_no_intrinsic_scenario_roles(self):
        with self.assertRaises(Exception):
            FAKE_SPEC.adapter_id = "changed"
        self.assertFalse(hasattr(FAKE_SPEC, "subject"))

    def test_fake_adapter_completes_batch_and_uses_its_artifact_layout(self):
        first = fake_input("z")
        second = fake_input("a", "b")
        prepared = prepare_batch(FAKE_SPEC, (first, second))
        self.assertEqual(
            tuple(item.digest for item in prepared.inputs),
            tuple(sorted((first.digest, second.digest))),
        )
        self.assertEqual(prepared.scenario_count, 3)
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            host = workspace / "source-runner"
            host.write_bytes(b"ELF")
            completed = subprocess.CompletedProcess([], 0, "guest output", "")
            with mock.patch("linux_oracle.qemu.subprocess.run", return_value=completed) as run:
                with execute_batch(
                    FAKE_SPEC, workspace, (second,), host
                ) as execution:
                    self.assertEqual(execution.scenario_path.name, "faux.case")
                    self.assertEqual(execution.trace_path.name, "reference.bin")
                    self.assertEqual(execution.host_oracle_path.name, "faux-runner")
                    self.assertTrue(execution.guest_result.passed)
            command = run.call_args.args[0]
            self.assertEqual(command[-1], "qemu/faux-check")
            environment = run.call_args.kwargs["env"]
            self.assertIn("FAUX_ARTIFACT_DIRECTORY", environment)

    def test_fake_store_round_trips_and_rejects_adapter_tampering(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = CampaignStore(FAKE_SPEC, Path(temporary_directory))
            entry = store.save_entry(fake_input("saved").encoded, {"beta", "alpha"})
            self.assertEqual(store.load_entries(), (entry,))
            metadata_path = entry.path / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["adapter_id"] = "wrong-v1"
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            with self.assertRaises(PersistentStateError):
                store.load_entries()

    def test_fake_task_recovery_claims_in_path_order_and_preserves_context(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            tasks = TaskStore(FAKE_SPEC, root, "attribution")
            encoded = fake_input("recover").encoded
            tasks.create("task-b", (encoded,), {"regions": ["b"]})
            tasks.create("task-a", (encoded,), {"regions": ["a"]})
            resumed = []

            def resume(store, task):
                resumed.append((task.path.name, task.metadata["context"]))
                store.transition(task, "completed", {"ok": True})

            recovered = recover_tasks((tasks,), resume)
            self.assertEqual([task.path.name for task in recovered], ["task-a", "task-b"])
            self.assertEqual(resumed[0][1], {"regions": ["a"]})
            self.assertEqual(tasks.recoverable(), ())

    def test_only_known_concurrent_coverage_proofs_are_retryable(self):
        spec = replace(
            FAKE_SPEC,
            outcomes=OutcomeSetHooks(
                b"FAUXOUT1",
                lambda document: tuple("0" * 64 for _item in document),
                lambda _document: (),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            tasks = TaskStore(spec, root, "attribution")
            encoded = fake_input("recover").encoded
            retryable = tasks.create("retry-proof", (encoded,))
            tasks.transition(
                retryable,
                "unstable",
                {"category": "representative-proof"},
            )
            fatal = tasks.create("fatal-proof", (encoded,))
            tasks.transition(fatal, "unstable", {"category": "other"})

            recoverable = tasks.recoverable()
            self.assertEqual(
                tuple(task.metadata["task_id"] for task in recoverable),
                ("retry-proof",),
            )
            claimed = tasks.claim(recoverable[0])
            self.assertEqual(claimed.metadata["state"], "running")
            self.assertIsNone(claimed.metadata["result"])

            minimizations = TaskStore(spec, root, "minimization")
            retryable_minimization = minimizations.create(
                "retry-minimization-proof", (encoded,)
            )
            minimizations.transition(
                retryable_minimization,
                "unstable",
                {"reason": "initial minimization input does not reproduce"},
            )
            recovered_minimizations = minimizations.recoverable()
            self.assertEqual(
                tuple(
                    task.metadata["task_id"]
                    for task in recovered_minimizations
                ),
                ("retry-minimization-proof",),
            )
            claimed_minimization = minimizations.claim(
                recovered_minimizations[0]
            )
            self.assertEqual(
                claimed_minimization.metadata["state"], "running"
            )
            self.assertIsNone(claimed_minimization.metadata["result"])

    def test_concurrent_unreproducible_coverage_does_not_block_campaign(self):
        spec = replace(
            FAKE_SPEC,
            outcomes=OutcomeSetHooks(
                b"FAUXOUT1",
                lambda document: tuple("0" * 64 for _item in document),
                lambda _document: (),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            kernel = workspace / spec.qemu.coverage_object_path
            kernel.parent.mkdir(parents=True)
            kernel.write_bytes(b"fixed kernel")
            kernel_digest = hashlib.sha256(kernel.read_bytes()).hexdigest()
            invocation = 0

            def observe(*args, **_kwargs):
                nonlocal invocation
                invocation += 1
                args[5].charge()
                regions = ("subsystem/alpha.py:1:1",) if invocation < 3 else ()
                return driver.ExecutionObservation(
                    True,
                    "passed",
                    regions,
                    kernel_digest,
                )

            with mock.patch.object(driver, "execute_inputs", side_effect=observe):
                status = driver.run_campaign(
                    spec,
                    CampaignRequest(9, 1, 1, 8, 0, False),
                    workspace,
                )

            self.assertEqual(status, 0)
            store = CampaignStore(spec, workspace)
            self.assertEqual(store.load_entries(), ())
            self.assertEqual(store.load_coverage(kernel_digest), ())
            tasks = tuple(
                TaskStore(spec, store.root, "attribution").root.iterdir()
            )
            self.assertEqual(len(tasks), 1)
            task = TaskStore(spec, store.root, "attribution").load(tasks[0])
            self.assertEqual(task.metadata["state"], "completed")
            self.assertEqual(
                task.metadata["result"]["category"],
                "unreproducible-coverage",
            )
            self.assertEqual(
                task.metadata["result"]["missing_regions"],
                ["subsystem/alpha.py:1:1"],
            )
            self.assertEqual(task.metadata["result"]["admitted_digests"], [])
            runs = tuple(store.runs_root.iterdir())
            self.assertEqual(len(runs), 1)
            metadata = json.loads(
                (runs[0] / "metadata.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                metadata["result"],
                "passed-unreproducible-coverage",
            )

    def test_concurrent_minimization_input_may_lose_attributed_coverage(self):
        spec = replace(
            FAKE_SPEC,
            outcomes=OutcomeSetHooks(
                b"FAUXOUT1",
                lambda document: tuple("0" * 64 for _item in document),
                lambda _document: (),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            kernel = workspace / spec.qemu.coverage_object_path
            kernel.parent.mkdir(parents=True)
            kernel.write_bytes(b"fixed kernel")
            kernel_digest = hashlib.sha256(kernel.read_bytes()).hexdigest()
            invocation = 0

            def observe(*args, **_kwargs):
                nonlocal invocation
                invocation += 1
                args[5].charge()
                regions = (
                    ("subsystem/alpha.py:1:1",)
                    if invocation <= 3
                    else ()
                )
                return driver.ExecutionObservation(
                    True,
                    "passed",
                    regions,
                    kernel_digest,
                )

            with mock.patch.object(driver, "execute_inputs", side_effect=observe):
                status = driver.run_campaign(
                    spec,
                    CampaignRequest(9, 1, 1, 12, 0, True),
                    workspace,
                )

            self.assertEqual(status, 0)
            store = CampaignStore(spec, workspace)
            self.assertEqual(store.load_entries(), ())
            self.assertEqual(store.load_coverage(kernel_digest), ())
            attribution_tasks = tuple(
                TaskStore(spec, store.root, "attribution").root.iterdir()
            )
            self.assertEqual(len(attribution_tasks), 1)
            attribution = TaskStore(spec, store.root, "attribution").load(
                attribution_tasks[0]
            )
            self.assertEqual(attribution.metadata["state"], "completed")
            self.assertEqual(
                attribution.metadata["result"]["category"],
                "unreproducible-coverage",
            )
            self.assertEqual(
                attribution.metadata["result"]["missing_regions"],
                ["subsystem/alpha.py:1:1"],
            )
            minimization_tasks = tuple(
                TaskStore(spec, store.root, "minimization").root.iterdir()
            )
            self.assertEqual(len(minimization_tasks), 1)
            minimization = TaskStore(spec, store.root, "minimization").load(
                minimization_tasks[0]
            )
            self.assertEqual(minimization.metadata["state"], "completed")
            self.assertEqual(
                minimization.metadata["result"]["category"],
                "unreproducible-coverage",
            )

    def test_nonconcurrent_minimization_input_coverage_loss_remains_fatal(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            kernel = workspace / FAKE_SPEC.qemu.coverage_object_path
            kernel.parent.mkdir(parents=True)
            kernel.write_bytes(b"fixed kernel")
            kernel_digest = hashlib.sha256(kernel.read_bytes()).hexdigest()
            invocation = 0

            def observe(*args, **_kwargs):
                nonlocal invocation
                invocation += 1
                args[5].charge()
                regions = (
                    ("subsystem/alpha.py:1:1",)
                    if invocation <= 3
                    else ()
                )
                return driver.ExecutionObservation(
                    True,
                    "passed",
                    regions,
                    kernel_digest,
                )

            with (
                mock.patch.object(driver, "execute_inputs", side_effect=observe),
                self.assertRaisesRegex(
                    ValueError,
                    "initial minimization input does not reproduce",
                ),
            ):
                driver.run_campaign(
                    FAKE_SPEC,
                    CampaignRequest(9, 1, 1, 12, 0, True),
                    workspace,
                )

            store = CampaignStore(FAKE_SPEC, workspace)
            minimization_tasks = tuple(
                TaskStore(FAKE_SPEC, store.root, "minimization").root.iterdir()
            )
            self.assertEqual(len(minimization_tasks), 1)
            minimizations = TaskStore(FAKE_SPEC, store.root, "minimization")
            minimization = minimizations.load(minimization_tasks[0])
            self.assertEqual(minimization.metadata["state"], "unstable")
            self.assertEqual(
                minimization.metadata["result"],
                {"reason": "initial minimization input does not reproduce"},
            )
            self.assertEqual(minimizations.recoverable(), ())

    def test_nonconcurrent_unreproducible_coverage_remains_fatal(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            kernel = workspace / FAKE_SPEC.qemu.coverage_object_path
            kernel.parent.mkdir(parents=True)
            kernel.write_bytes(b"fixed kernel")
            kernel_digest = hashlib.sha256(kernel.read_bytes()).hexdigest()
            invocation = 0

            def observe(*args, **_kwargs):
                nonlocal invocation
                invocation += 1
                args[5].charge()
                regions = ("subsystem/alpha.py:1:1",) if invocation < 3 else ()
                return driver.ExecutionObservation(
                    True,
                    "passed",
                    regions,
                    kernel_digest,
                )

            with (
                mock.patch.object(driver, "execute_inputs", side_effect=observe),
                self.assertRaisesRegex(
                    RuntimeError,
                    "representative coverage proof failed",
                ),
            ):
                driver.run_campaign(
                    FAKE_SPEC,
                    CampaignRequest(9, 1, 1, 8, 0, False),
                    workspace,
                )

            store = CampaignStore(FAKE_SPEC, workspace)
            tasks = tuple(
                TaskStore(FAKE_SPEC, store.root, "attribution").root.iterdir()
            )
            self.assertEqual(len(tasks), 1)
            task = TaskStore(FAKE_SPEC, store.root, "attribution").load(tasks[0])
            self.assertEqual(task.metadata["state"], "unstable")
            self.assertEqual(
                task.metadata["result"],
                {"category": "representative-proof"},
            )
            self.assertEqual(
                TaskStore(FAKE_SPEC, store.root, "attribution").recoverable(),
                (),
            )

    def test_fake_adapter_completes_common_campaign_state_machine(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            kernel = workspace / FAKE_SPEC.qemu.coverage_object_path
            kernel.parent.mkdir(parents=True)
            kernel.write_bytes(b"fixed kernel")
            kernel_digest = hashlib.sha256(kernel.read_bytes()).hexdigest()

            def observe(*args, **_kwargs):
                args[5].charge()
                return driver.ExecutionObservation(
                    True,
                    "passed",
                    ("subsystem/alpha.py:1:1",),
                    kernel_digest,
                )

            with mock.patch.object(driver, "execute_inputs", side_effect=observe):
                status = driver.run_campaign(
                    FAKE_SPEC,
                    CampaignRequest(9, 1, 1, 8, 0, False),
                    workspace,
                )

            self.assertEqual(status, 0)
            store = CampaignStore(FAKE_SPEC, workspace)
            self.assertEqual(len(store.load_entries()), 1)
            runs = tuple(store.runs_root.iterdir())
            self.assertEqual(len(runs), 1)
            metadata = json.loads(
                (runs[0] / "metadata.json").read_text(encoding="utf-8")
            )
            self.assertEqual(metadata["adapter_id"], "faux-v7")
            self.assertEqual(metadata["result"], "passed-new-coverage")
            self.assertEqual(metadata["qemu_count"], 3)

    def test_background_attribution_cannot_starve_requested_batches(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            kernel = workspace / FAKE_SPEC.qemu.coverage_object_path
            kernel.parent.mkdir(parents=True)
            kernel.write_bytes(b"fixed kernel")
            kernel_digest = hashlib.sha256(kernel.read_bytes()).hexdigest()

            def observe(*args, **kwargs):
                args[5].charge()
                batch_index = kwargs["batch_index"]
                return driver.ExecutionObservation(
                    True,
                    "passed",
                    (f"subsystem/alpha.py:{batch_index + 1}:1",),
                    kernel_digest,
                )

            with mock.patch.object(driver, "execute_inputs", side_effect=observe):
                status = driver.run_campaign(
                    FAKE_SPEC,
                    CampaignRequest(9, 2, 1, 4, 0, False),
                    workspace,
                )

            self.assertEqual(status, 0)
            store = CampaignStore(FAKE_SPEC, workspace)
            self.assertEqual(len(tuple(store.runs_root.iterdir())), 2)
            pending = TaskStore(FAKE_SPEC, store.root, "attribution").recoverable()
            self.assertEqual(len(pending), 1)

    def test_failed_foreground_batch_reports_its_category(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)

            def observe(*args, **_kwargs):
                args[5].charge()
                return driver.ExecutionObservation(
                    False,
                    "host-record-failure",
                    (),
                    "",
                )

            error_output = io.StringIO()
            with (
                mock.patch.object(driver, "execute_inputs", side_effect=observe),
                redirect_stderr(error_output),
            ):
                status = driver.run_campaign(
                    FAKE_SPEC,
                    CampaignRequest(9, 1, 1, 1, 0, False),
                    workspace,
                )

            self.assertEqual(status, 1)
            self.assertIn(
                "batch=1/1 qemu=1 result=host-record-failure",
                error_output.getvalue(),
            )

    def test_failed_foreground_batch_reports_host_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            diagnostic = (
                "host-unstable: scenario 2 has an alternative observed fewer than 3 times"
            )

            def observe(*_args, **_kwargs):
                return driver.ExecutionObservation(
                    False,
                    "host-unstable",
                    (),
                    "",
                    diagnostic,
                )

            error_output = io.StringIO()
            with (
                mock.patch.object(driver, "execute_inputs", side_effect=observe),
                redirect_stderr(error_output),
            ):
                status = driver.run_campaign(
                    FAKE_SPEC,
                    CampaignRequest(9, 1, 1, 1, 0, False),
                    workspace,
                )

            self.assertEqual(status, 1)
            self.assertIn("result=host-unstable", error_output.getvalue())
            self.assertIn(diagnostic, error_output.getvalue())

    def test_fake_replay_and_coverage_are_entirely_spec_driven(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            invocation = build_replay_invocation(
                FAKE_SPEC, root / "failure", root / "kernel.elf"
            )
            self.assertEqual(invocation.command[-1], "qemu/faux-check")
            self.assertEqual(
                invocation.environment["FAUX_ARTIFACT_DIRECTORY"],
                str((root / "failure").resolve()),
            )
        exported = {
            "data": [
                {
                    "files": [
                        {
                            "filename": "/src/subsystem/beta.py",
                            "segments": [[8, 3, 1, True, True]],
                        },
                        {
                            "filename": "/src/unrelated.py",
                            "segments": [[1, 1, 1, True, True]],
                        },
                    ]
                }
            ]
        }
        self.assertEqual(
            region_ids(FAKE_SPEC.coverage, exported, covered_only=True),
            {"subsystem/beta.py:8:3"},
        )

    def test_common_package_contains_no_adapter_specific_constants(self):
        package_root = Path(__file__).resolve().parents[1]
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(package_root.glob("*.py"))
        ).lower()
        self.assertNotIn("pipe", source)
        self.assertNotIn("eventfd", source)


if __name__ == "__main__":
    unittest.main()
