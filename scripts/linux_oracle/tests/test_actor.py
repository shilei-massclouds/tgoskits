"""Unit tests for the shared controlled single-worker lifecycle."""

import sys
import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from linux_oracle.actor import (
    CONTROLLER_ACTOR,
    WORKER_ACTORS,
    WORKER_ACTOR,
    ControlledWorkers,
    SingleWorkerLifecycle,
    WorkerLifecycleError,
    WorkerLifecycleErrorKind,
)


class SingleWorkerLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lifecycle = SingleWorkerLifecycle[str, int]()

    def test_fixed_actor_identities_and_successful_join(self):
        self.assertEqual(CONTROLLER_ACTOR, 0)
        self.assertEqual(WORKER_ACTOR, 1)

        self.lifecycle.start("read", lambda: 7)
        self.lifecycle.assert_pending()
        worker = self.lifecycle.before_trigger()
        self.assertEqual((worker.operation, worker.resource), ("read", 7))
        self.lifecycle.update_completable(True)
        completed = []

        self.lifecycle.join(completed.append)

        self.assertEqual(len(completed), 1)
        self.assertTrue(completed[0].pending_confirmed)
        self.assertTrue(completed[0].completable)
        self.assertIsNone(self.lifecycle.worker)
        self.lifecycle.finish_scenario()

    def test_repeated_start_fails_before_adapter_resource_proof(self):
        self.lifecycle.start("read", lambda: 7)
        proof_called = False

        def identify_resource() -> int:
            nonlocal proof_called
            proof_called = True
            return 8

        self._assert_error(
            lambda: self.lifecycle.start("write", identify_resource),
            WorkerLifecycleErrorKind.LIFECYCLE,
            "only one worker call may be active",
        )
        self.assertFalse(proof_called)

    def test_pending_and_join_require_an_active_worker(self):
        self._assert_error(
            self.lifecycle.assert_pending,
            WorkerLifecycleErrorKind.LIFECYCLE,
            "assert-pending requires an active worker",
        )
        self._assert_error(
            lambda: self.lifecycle.join(lambda _worker: None),
            WorkerLifecycleErrorKind.LIFECYCLE,
            "join requires an active worker",
        )

    def test_trigger_requires_pending_confirmation(self):
        self.lifecycle.start("read", lambda: 7)

        self._assert_error(
            self.lifecycle.before_trigger,
            WorkerLifecycleErrorKind.LIFECYCLE,
            "worker pending state was not confirmed",
        )

    def test_completable_worker_allows_only_join(self):
        self.lifecycle.start("read", lambda: 7)
        self.lifecycle.assert_pending()
        self.lifecycle.before_trigger()
        self.lifecycle.update_completable(True)

        self._assert_error(
            self.lifecycle.before_trigger,
            WorkerLifecycleErrorKind.LIFECYCLE,
            "join must immediately follow a completing trigger",
        )
        self._assert_error(
            self.lifecycle.assert_pending,
            WorkerLifecycleErrorKind.BLOCKING_PROOF,
            "worker may complete before assert-pending",
        )

    def test_join_requires_pending_and_completion_proofs(self):
        for confirm_pending in (False, True):
            with self.subTest(confirm_pending=confirm_pending):
                lifecycle = SingleWorkerLifecycle[str, int]()
                lifecycle.start("read", lambda: 7)
                if confirm_pending:
                    lifecycle.assert_pending()
                self._assert_error(
                    lambda: lifecycle.join(lambda _worker: None),
                    WorkerLifecycleErrorKind.BLOCKING_PROOF,
                    "worker is not proven completable before join",
                )

    def test_failed_adapter_completion_retains_worker(self):
        self.lifecycle.start("read", lambda: 7)
        self.lifecycle.assert_pending()
        self.lifecycle.update_completable(True)

        def fail_completion(_worker) -> None:
            raise RuntimeError("adapter completion failed")

        with self.assertRaisesRegex(RuntimeError, "adapter completion failed"):
            self.lifecycle.join(fail_completion)
        self.assertIsNotNone(self.lifecycle.worker)

    def test_unfinished_scenario_is_rejected(self):
        self.lifecycle.start("read", lambda: 7)

        self._assert_error(
            self.lifecycle.finish_scenario,
            WorkerLifecycleErrorKind.LIFECYCLE,
            "scenario ends with an unfinished worker",
        )

    def _assert_error(self, action, kind, detail) -> None:
        with self.assertRaises(WorkerLifecycleError) as raised:
            action()
        self.assertIs(raised.exception.kind, kind)
        self.assertEqual(raised.exception.detail, detail)


class ControlledWorkersTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workers = ControlledWorkers[str, int]()

    def test_two_workers_complete_and_join_as_one_result_vector(self):
        self.assertEqual(WORKER_ACTORS, (1, 2))
        self.workers.start(1, "read-a", lambda: 7)
        self.workers.start(2, "read-b", lambda: 7)
        self.workers.assert_all_pending()
        self.workers.update_completable(1, True)
        self.workers.update_completable(2, True)
        self.workers.mark_completed(2, 1)
        self.workers.mark_completed(1, 2)
        completed = []

        self.workers.join_set((1, 2), lambda calls: completed.extend(calls))

        self.assertEqual(
            [(call.operation, call.completion_ordinal) for call in completed],
            [("read-a", 2), ("read-b", 1)],
        )
        self.workers.finish_scenario()

    def test_actor_validation_and_independent_lifecycle(self):
        self._assert_error(
            lambda: self.workers.start(0, "read", lambda: 7),
            WorkerLifecycleErrorKind.LIFECYCLE,
            "worker actor must be 1 or 2",
        )
        self.workers.start(1, "read", lambda: 7)
        self._assert_error(
            lambda: self.workers.assert_pending(2),
            WorkerLifecycleErrorKind.LIFECYCLE,
            "assert-pending actor 2 requires an active worker",
        )

    def test_grouped_pending_requires_both_workers(self):
        self.workers.start(1, "read", lambda: 7)
        self._assert_error(
            self.workers.assert_all_pending,
            WorkerLifecycleErrorKind.LIFECYCLE,
            "assert-all-pending requires active workers 1 and 2",
        )

    def test_completion_ordinals_are_positive_and_unique(self):
        for actor in WORKER_ACTORS:
            self.workers.start(actor, "read", lambda: 7)
            self.workers.assert_pending(actor)
            self.workers.update_completable(actor, True)
        self.workers.mark_completed(1, 1)
        self._assert_error(
            lambda: self.workers.mark_completed(2, 1),
            WorkerLifecycleErrorKind.LIFECYCLE,
            "completion ordinal 1 is already used",
        )
        self._assert_error(
            lambda: self.workers.mark_completed(2, 0),
            WorkerLifecycleErrorKind.LIFECYCLE,
            "completion ordinal must be positive",
        )

    def test_join_set_is_atomic_on_adapter_failure(self):
        for actor in WORKER_ACTORS:
            self.workers.start(actor, "read", lambda: 7)
            self.workers.assert_pending(actor)
            self.workers.update_completable(actor, True)
            self.workers.mark_completed(actor, actor)

        with self.assertRaisesRegex(RuntimeError, "combined transition failed"):
            self.workers.join_set(
                (1, 2),
                lambda _calls: (_ for _ in ()).throw(
                    RuntimeError("combined transition failed")
                ),
            )

        self.assertIsNotNone(self.workers.worker(1))
        self.assertIsNotNone(self.workers.worker(2))

    def test_join_set_rejects_partial_completion_and_duplicate_actor(self):
        for actor in WORKER_ACTORS:
            self.workers.start(actor, "read", lambda: 7)
            self.workers.assert_pending(actor)
            self.workers.update_completable(actor, True)
        self.workers.mark_completed(1, 1)
        self._assert_error(
            lambda: self.workers.join_set((1, 2), lambda _calls: None),
            WorkerLifecycleErrorKind.BLOCKING_PROOF,
            "worker actor 2 is not completed before grouped join",
        )
        self._assert_error(
            lambda: self.workers.join_set((1, 1), lambda _calls: None),
            WorkerLifecycleErrorKind.LIFECYCLE,
            "join-set actors must be unique",
        )

    def test_unfinished_scenario_lists_active_actors(self):
        self.workers.start(2, "read", lambda: 7)
        self._assert_error(
            self.workers.finish_scenario,
            WorkerLifecycleErrorKind.LIFECYCLE,
            "scenario ends with unfinished workers: 2",
        )

    def _assert_error(self, action, kind, detail) -> None:
        with self.assertRaises(WorkerLifecycleError) as raised:
            action()
        self.assertIs(raised.exception.kind, kind)
        self.assertEqual(raised.exception.detail, detail)


if __name__ == "__main__":
    unittest.main()
