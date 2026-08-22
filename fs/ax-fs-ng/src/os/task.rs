use alloc::{boxed::Box, string::String, sync::Arc};
use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use ax_errno::{AxError, AxResult};
use ax_sync::SpinRwLock as RwLock;

/// Wait/notify object created and owned by the block runtime.
pub trait BlockNotification: Send + Sync + 'static {
    /// Publishes work from normal task context.
    fn notify(&self);

    /// Publishes work from hard IRQ context without allocation or sleeping.
    fn notify_from_irq(&self);

    /// Blocks until a notification is pending and consumes that notification.
    #[track_caller]
    fn wait(&self);

    /// Blocks until notified or the duration expires.
    ///
    /// Returns `true` when the wait timed out.
    #[track_caller]
    fn wait_timeout(&self, duration: Duration) -> bool;
}

/// Join token for one block maintenance task.
pub trait BlockThread: Send + Sync + 'static {
    /// Waits for the maintenance task to exit.
    fn join(&self);
}

/// One-shot filesystem-initialization boundary exposed to an OS observer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FilesystemInitCheckpoint {
    /// All filesystem OS capability adapters were installed.
    RuntimeAdapterInstalled = 0,
    /// Direct RDIF block-device collection returned.
    BlockDevicesDrained = 1,
    /// RDIF block-group collection returned.
    BlockGroupsDrained  = 2,
    /// Block-runtime construction and installation is about to begin.
    RuntimeInstallEntered = 3,
    /// The direct-device controller loop is about to begin.
    DirectDeviceLoopEntered = 4,
    /// The complete direct-device loop returned.
    DirectDeviceLoopReturned = 5,
    /// The first observed group controller is about to start.
    FirstGroupControllerEntered = 6,
    /// The first observed group-controller start returned.
    FirstGroupControllerReturned = 7,
    /// The first observed group member is about to bootstrap.
    FirstGroupMemberBootstrapEntered = 8,
    /// The first observed group-member bootstrap returned.
    FirstGroupMemberBootstrapReturned = 9,
    /// The first observed group IRQ setup branch is about to begin.
    FirstGroupIrqSetupEntered = 10,
    /// The first observed group IRQ setup branch returned.
    FirstGroupIrqSetupReturned = 11,
    /// The first observed bootstrapped group member is about to become ready.
    FirstGroupMemberReadyEntered = 12,
    /// The first observed group-member ready operation returned.
    FirstGroupMemberReadyReturned = 13,
    /// The complete direct/group runtime was published.
    RuntimePublished    = 14,
    /// Root discovery and mounting is about to begin.
    RootInitEntered     = 15,
    /// Discovered-disk collection is about to begin.
    DiskCollectionEntered = 16,
    /// The first observed disk volume scan is about to begin.
    FirstVolumeScanEntered = 17,
    /// The first observed disk volume scan returned.
    FirstVolumeScanReturned = 18,
    /// Root selection returned a concrete disk and optional partition.
    RootCandidateSelected = 19,
    /// Root filesystem construction and mount publication returned.
    RootMounted         = 20,
    /// Every additional partition mount attempt returned.
    AdditionalMountsReturned = 21,
    /// The complete root-initialization entry point returned.
    RootInitReturned    = 22,
    /// The first block maintenance task is about to be inserted.
    FirstBlockWorkerSpawnEntered = 23,
    /// The first block maintenance task insertion returned.
    FirstBlockWorkerSpawnReturned = 24,
    /// The first observed block worker began its entry closure.
    FirstBlockWorkerEntered = 25,
    /// The first observed block worker's affinity operation returned.
    FirstBlockWorkerAffinityReturned = 26,
}

/// Scheduler and CPU-affinity capabilities consumed by the block runtime.
pub trait BlockRuntimeOps: Send + Sync {
    /// Observes a one-shot filesystem initialization boundary.
    ///
    /// The default implementation is empty. `ax-fs-ng` calls this method only
    /// when its `kerndiff-fault-observer` feature is enabled.
    fn filesystem_init_checkpoint(&self, checkpoint: FilesystemInitCheckpoint) {
        let _ = checkpoint;
    }

    /// Returns the logical CPU executing the caller.
    fn current_cpu(&self) -> usize;

    /// Returns the number of CPUs whose scheduler, IPI, and local IRQ path are
    /// fully online.
    fn online_cpu_count(&self) -> usize;

    /// Returns whether the current context may block.
    fn can_block(&self) -> bool;

    /// Creates an independent lost-wakeup-safe wait/notify object.
    fn notification(&self) -> Arc<dyn BlockNotification>;

    /// Starts a maintenance task and binds it to one online CPU.
    ///
    /// # Errors
    ///
    /// Returns an error when the task cannot be created or the requested CPU
    /// cannot be used. On error, `entry` has not run.
    fn spawn_pinned(
        &self,
        name: String,
        cpu: usize,
        entry: Box<dyn FnOnce() + Send + 'static>,
    ) -> AxResult<Box<dyn BlockThread>>;
}

#[inline]
pub(crate) fn record_filesystem_init_checkpoint(
    ops: &dyn BlockRuntimeOps,
    checkpoint: FilesystemInitCheckpoint,
) {
    #[cfg(feature = "kerndiff-fault-observer")]
    ops.filesystem_init_checkpoint(checkpoint);
    #[cfg(not(feature = "kerndiff-fault-observer"))]
    let _ = (ops, checkpoint);
}

static RUNTIME_OPS: RwLock<Option<&'static dyn BlockRuntimeOps>> = RwLock::new(None);
static RUNTIME_READY: AtomicBool = AtomicBool::new(false);

/// Installs the runtime task capability implementation.
pub fn set_runtime_ops(ops: &'static dyn BlockRuntimeOps) {
    *RUNTIME_OPS.write() = Some(ops);
    RUNTIME_READY.store(true, Ordering::Release);
}

/// Returns the installed block runtime capabilities.
///
/// # Errors
///
/// Returns [`AxError::BadState`] before `axruntime` installs the adapter.
pub fn runtime_ops() -> AxResult<&'static dyn BlockRuntimeOps> {
    RUNTIME_OPS
        .read()
        .as_ref()
        .copied()
        .ok_or(AxError::BadState)
}

/// Returns whether the runtime adapter has been installed.
pub fn has_runtime_ops() -> bool {
    RUNTIME_READY.load(Ordering::Acquire)
}

#[cfg(test)]
pub(crate) fn install_test_runtime_ops() {
    set_runtime_ops(&tests::TEST_RUNTIME_OPS);
    crate::os::time::set_time_provider(&tests::TEST_TIME_PROVIDER);
}

#[cfg(test)]
pub(crate) fn reset_test_wait_timeout_count() {
    tests::TEST_WAIT_TIMEOUTS.store(0, Ordering::Relaxed);
}

#[cfg(test)]
pub(crate) fn test_wait_timeout_count() -> usize {
    tests::TEST_WAIT_TIMEOUTS.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, string::String, sync::Arc};
    use core::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use std::{
        sync::{Condvar, Mutex, OnceLock},
        thread::{self, JoinHandle},
        time::Instant,
    };

    use ax_errno::AxResult;

    use super::{
        BlockNotification, BlockRuntimeOps, BlockThread, FilesystemInitCheckpoint,
        record_filesystem_init_checkpoint,
    };
    use crate::os::time::BlockTimeProvider;

    pub(super) static TEST_RUNTIME_OPS: TestRuntimeOps = TestRuntimeOps;
    pub(super) static TEST_TIME_PROVIDER: TestTimeProvider = TestTimeProvider;
    pub(super) static TEST_WAIT_TIMEOUTS: AtomicUsize = AtomicUsize::new(0);
    static TEST_FILESYSTEM_INIT_CHECKPOINT: AtomicUsize = AtomicUsize::new(usize::MAX);
    static TEST_START: OnceLock<Instant> = OnceLock::new();

    pub(super) struct TestRuntimeOps;
    pub(super) struct TestTimeProvider;

    struct TestNotification {
        pending: Mutex<bool>,
        ready: Condvar,
    }

    struct TestThread {
        join: Mutex<Option<JoinHandle<()>>>,
    }

    impl TestNotification {
        const fn new() -> Self {
            Self {
                pending: Mutex::new(false),
                ready: Condvar::new(),
            }
        }

        fn publish(&self) {
            *self.pending.lock().unwrap() = true;
            self.ready.notify_one();
        }
    }

    impl BlockNotification for TestNotification {
        fn notify(&self) {
            self.publish();
        }

        fn notify_from_irq(&self) {
            self.publish();
        }

        #[track_caller]
        fn wait(&self) {
            let mut pending = self.pending.lock().unwrap();
            while !*pending {
                pending = self.ready.wait(pending).unwrap();
            }
            *pending = false;
        }

        #[track_caller]
        fn wait_timeout(&self, duration: Duration) -> bool {
            TEST_WAIT_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            let mut pending = self.pending.lock().unwrap();
            if !*pending {
                let (next, timeout) = self.ready.wait_timeout(pending, duration).unwrap();
                pending = next;
                if timeout.timed_out() && !*pending {
                    return true;
                }
            }
            *pending = false;
            false
        }
    }

    impl BlockThread for TestThread {
        fn join(&self) {
            if let Some(join) = self.join.lock().unwrap().take() {
                join.join().unwrap();
            }
        }
    }

    impl BlockRuntimeOps for TestRuntimeOps {
        fn filesystem_init_checkpoint(&self, checkpoint: FilesystemInitCheckpoint) {
            TEST_FILESYSTEM_INIT_CHECKPOINT.store(checkpoint as usize, Ordering::Release);
        }

        fn current_cpu(&self) -> usize {
            0
        }

        fn online_cpu_count(&self) -> usize {
            1
        }

        fn can_block(&self) -> bool {
            true
        }

        fn notification(&self) -> Arc<dyn BlockNotification> {
            Arc::new(TestNotification::new())
        }

        fn spawn_pinned(
            &self,
            name: String,
            _cpu: usize,
            entry: Box<dyn FnOnce() + Send + 'static>,
        ) -> AxResult<Box<dyn BlockThread>> {
            let join = thread::Builder::new().name(name).spawn(entry).unwrap();
            Ok(Box::new(TestThread {
                join: Mutex::new(Some(join)),
            }))
        }
    }

    impl BlockTimeProvider for TestTimeProvider {
        fn wall_time(&self) -> Duration {
            TEST_START.get_or_init(Instant::now).elapsed()
        }
    }

    #[cfg(feature = "kerndiff-fault-observer")]
    #[test]
    fn opt_in_filesystem_observer_invokes_the_runtime_callback() {
        TEST_FILESYSTEM_INIT_CHECKPOINT.store(usize::MAX, Ordering::Release);
        record_filesystem_init_checkpoint(
            &TEST_RUNTIME_OPS,
            FilesystemInitCheckpoint::RuntimeAdapterInstalled,
        );
        assert_eq!(TEST_FILESYSTEM_INIT_CHECKPOINT.load(Ordering::Acquire), 0);
    }
}
