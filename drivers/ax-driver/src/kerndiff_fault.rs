//! KernDiff-only i6300ESB watchdog and pvpanic transport.
//!
//! This module deliberately does not expose `/dev/watchdog`.  Its sole caller
//! is axruntime's feature-gated two-stage liveness coordinator.

use core::{
    ptr::{read_volatile, write_volatile},
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
};

use pcie::CommandRegister;
use rdrive::probe::{
    OnProbeError,
    pci::{FnOnProbe, ProbePci},
};

const INTEL_VENDOR_ID: u16 = 0x8086;
const I6300ESB_DEVICE_ID: u16 = 0x25ab;
const REDHAT_VENDOR_ID: u16 = 0x1b36;
const PVPANIC_DEVICE_ID: u16 = 0x0011;
#[cfg(target_arch = "x86_64")]
const PVPANIC_IO_PORT: u16 = 0x505;

const ESB_CONFIG_OFFSET: u16 = 0x60;
const ESB_LOCK_OFFSET: u16 = 0x68;
const ESB_TIMER1_OFFSET: usize = 0x00;
const ESB_TIMER2_OFFSET: usize = 0x04;
const ESB_RELOAD_OFFSET: usize = 0x0c;
const ESB_UNLOCK1: u16 = 0x80;
const ESB_UNLOCK2: u16 = 0x86;
const ESB_RELOAD: u16 = 0x100;
const ESB_CONFIG_VALUE: u16 = 0x0003;
const ESB_ENABLE: u8 = 0x02;

pub const WATCHDOG_STAGE_SECONDS: u64 = 30;
pub const WATCHDOG_TIMEOUT_SECONDS: u64 = WATCHDOG_STAGE_SECONDS * 2;
pub const LIVENESS_STALE_SECONDS: u64 = 15;
pub const DIAGNOSTIC_PAGE_BYTES: usize = 4096;
// The configured heartbeat is split evenly across the two hardware stages.
const TIMER_TICKS: u32 = (WATCHDOG_TIMEOUT_SECONDS as u32) << 9;
const MAX_CPUS: usize = 64;
const DIAGNOSTIC_MAGIC: u32 = 0x4b44_5744;
const DIAGNOSTIC_VERSION: u32 = 5;
pub const BOOT_PHASE_COUNT: usize = 12;
const BOOTSTRAP_CHECKPOINT_COUNT: usize = 6;
const BOOTSTRAP_FOLLOWUP_CHECKPOINT_COUNT: usize = 6;
const INIT_TASK_CHECKPOINT_COUNT: usize = 14;
const INIT_TASK_REQUIRED_PHASE_SEQUENCE: u64 = 11;

static WATCHDOG_MMIO: AtomicUsize = AtomicUsize::new(0);
static WATCHDOG_CONFIG_ADDRESS: AtomicU32 = AtomicU32::new(0);
static PVPANIC_MMIO: AtomicUsize = AtomicUsize::new(0);
static WATCHDOG_ARMED: AtomicBool = AtomicBool::new(false);
static PVPANIC_NOTIFIED: AtomicBool = AtomicBool::new(false);
static FORCED_STALE_MASK: AtomicU64 = AtomicU64::new(0);
static BOOTSTRAP_FEEDER_TASK_ID: AtomicU64 = AtomicU64::new(0);
static INIT_TASK_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
struct SchedulerTaskIds {
    bootstrap_feeder: u64,
    init: u64,
}

impl SchedulerTaskIds {
    const fn new(bootstrap_feeder: u64, init: u64) -> Self {
        Self {
            bootstrap_feeder,
            init,
        }
    }

    const fn contains(self, task_id: u64) -> bool {
        task_id != 0 && (task_id == self.bootstrap_feeder || task_id == self.init)
    }
}

#[repr(C, align(4096))]
struct DiagnosticPage {
    magic: u32,
    version: u32,
    size: u32,
    max_cpus: u32,
    boot_epoch: AtomicU64,
    online_mask: AtomicU64,
    stale_mask: AtomicU64,
    scheduler_epoch: [AtomicU64; MAX_CPUS],
    irq_epoch: [AtomicU64; MAX_CPUS],
    last_progress_ns: [AtomicU64; MAX_CPUS],
    reached_phase_bitmap: AtomicU64,
    last_phase: AtomicU32,
    reserved: u32,
    phase_sequence: AtomicU64,
    phase_elapsed_ns: [AtomicU64; BOOT_PHASE_COUNT],
    bootstrap_checkpoint_bitmap: AtomicU64,
    bootstrap_checkpoint_elapsed_ns: [AtomicU64; BOOTSTRAP_CHECKPOINT_COUNT],
    bootstrap_followup_checkpoint_bitmap: AtomicU64,
    bootstrap_followup_checkpoint_elapsed_ns: [AtomicU64; BOOTSTRAP_FOLLOWUP_CHECKPOINT_COUNT],
    init_task_checkpoint_bitmap: AtomicU64,
    init_task_checkpoint_elapsed_ns: [AtomicU64; INIT_TASK_CHECKPOINT_COUNT],
}

impl DiagnosticPage {
    const fn new() -> Self {
        Self {
            magic: DIAGNOSTIC_MAGIC,
            version: DIAGNOSTIC_VERSION,
            size: size_of::<Self>() as u32,
            max_cpus: MAX_CPUS as u32,
            boot_epoch: AtomicU64::new(0),
            online_mask: AtomicU64::new(0),
            stale_mask: AtomicU64::new(0),
            scheduler_epoch: [const { AtomicU64::new(0) }; MAX_CPUS],
            irq_epoch: [const { AtomicU64::new(0) }; MAX_CPUS],
            last_progress_ns: [const { AtomicU64::new(0) }; MAX_CPUS],
            reached_phase_bitmap: AtomicU64::new(0),
            last_phase: AtomicU32::new(u32::MAX),
            reserved: 0,
            phase_sequence: AtomicU64::new(0),
            phase_elapsed_ns: [const { AtomicU64::new(0) }; BOOT_PHASE_COUNT],
            bootstrap_checkpoint_bitmap: AtomicU64::new(0),
            bootstrap_checkpoint_elapsed_ns: [const { AtomicU64::new(0) };
                BOOTSTRAP_CHECKPOINT_COUNT],
            bootstrap_followup_checkpoint_bitmap: AtomicU64::new(0),
            bootstrap_followup_checkpoint_elapsed_ns: [const { AtomicU64::new(0) };
                BOOTSTRAP_FOLLOWUP_CHECKPOINT_COUNT],
            init_task_checkpoint_bitmap: AtomicU64::new(0),
            init_task_checkpoint_elapsed_ns: [const { AtomicU64::new(0) };
                INIT_TASK_CHECKPOINT_COUNT],
        }
    }
}

static DIAGNOSTIC: DiagnosticPage = DiagnosticPage::new();

/// A persistent boundary in bootstrap watchdog-feeder creation or first execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BootstrapCheckpoint {
    /// The armed marker was emitted and task construction is about to start.
    FeederSpawnRequested = 0,
    /// The task has a stable reference but is not registered or runnable yet.
    FeederTaskInitialized = 1,
    /// Task registration and runqueue insertion returned to the spawning task.
    FeederSpawnReturned  = 2,
    /// The feeder task began executing its entry closure.
    FeederEntered        = 3,
    /// The feeder's CPU0 affinity operation returned.
    FeederAffinityReady  = 4,
    /// The feeder completed its first watchdog poll.
    FeederFirstPollComplete = 5,
}

impl BootstrapCheckpoint {
    const fn required_bitmap(self) -> u64 {
        match self {
            Self::FeederSpawnRequested => 0,
            Self::FeederTaskInitialized => 0b00_0001,
            Self::FeederSpawnReturned | Self::FeederEntered => 0b00_0011,
            Self::FeederAffinityReady => 0b00_1011,
            Self::FeederFirstPollComplete => 0b01_1011,
        }
    }
}

/// A persistent boundary after bootstrap feeder creation has returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BootstrapFollowupCheckpoint {
    /// The scheduler selected the feeder for its first context switch.
    FeederSchedulerSelected = 0,
    /// The spawning function returned to the runtime boot sequence.
    MainBootstrapReturned = 1,
    /// Serial runtime initialization is about to begin.
    SerialInitEntered  = 2,
    /// Serial runtime initialization returned to the boot sequence.
    SerialInitReturned = 3,
    /// The RTC boot-time output call is about to begin.
    RtcOutputEntered   = 4,
    /// The RTC boot-time output call returned.
    RtcOutputReturned  = 5,
}

impl BootstrapFollowupCheckpoint {
    const fn required_bootstrap_bitmap(self) -> u64 {
        match self {
            Self::FeederSchedulerSelected => 0b00_0010,
            Self::MainBootstrapReturned
            | Self::SerialInitEntered
            | Self::SerialInitReturned
            | Self::RtcOutputEntered
            | Self::RtcOutputReturned => 0b00_0100,
        }
    }

    const fn required_followup_bitmap(self) -> u64 {
        match self {
            Self::FeederSchedulerSelected | Self::MainBootstrapReturned => 0,
            Self::SerialInitEntered => 0b00_0010,
            Self::SerialInitReturned => 0b00_0110,
            Self::RtcOutputEntered => 0b00_1110,
            Self::RtcOutputReturned => 0b01_1110,
        }
    }
}

/// A persistent boundary in PID 1 task setup or first execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InitTaskCheckpoint {
    /// Init task construction is about to begin after its image was loaded.
    TaskCreateRequested  = 0,
    /// Task construction and page-table-root assignment returned.
    TaskConstructed      = 1,
    /// Process, stdio, thread, and task-extension setup completed.
    ProcessReady         = 2,
    /// The main task is about to call `spawn_task_with`.
    SpawnRequested       = 3,
    /// The init task has a stable reference but is not runnable yet.
    TaskInitialized      = 4,
    /// Registry and runqueue insertion returned to the main task.
    SpawnReturned        = 5,
    /// Console IRQ arming returned to the main task.
    ConsoleIrqArmed      = 6,
    /// The main task is about to join the init task.
    JoinEntered          = 7,
    /// PID 1's task-extension switch hook began before scope acquisition.
    TaskExtEntered       = 8,
    /// PID 1's task-extension switch hook completed scope installation.
    TaskExtReturned      = 9,
    /// The scheduler tracepoint selected the registered init task.
    SchedulerSelected    = 10,
    /// The init task began executing its user-task closure.
    TaskEntered          = 11,
    /// The init task is about to enter user mode for the first time.
    FirstUserRunEntered  = 12,
    /// The init task returned from its first user-mode interval.
    FirstUserRunReturned = 13,
}

impl InitTaskCheckpoint {
    const fn required_bitmap(self) -> u64 {
        match self {
            Self::TaskCreateRequested => 0,
            Self::TaskConstructed => 0x0001,
            Self::ProcessReady => 0x0003,
            Self::SpawnRequested => 0x0007,
            Self::TaskInitialized => 0x000f,
            Self::SpawnReturned => 0x001f,
            Self::ConsoleIrqArmed => 0x003f,
            Self::JoinEntered => 0x007f,
            Self::TaskExtEntered => 0x001f,
            Self::TaskExtReturned => 0x011f,
            Self::SchedulerSelected => 0x031f,
            Self::TaskEntered => 0x071f,
            Self::FirstUserRunEntered => 0x0f1f,
            Self::FirstUserRunReturned => 0x1f1f,
        }
    }
}

mod i6300_driver {
    use super::*;

    crate::model_register!(
        name: "KernDiff i6300ESB watchdog",
        level: ProbeLevel::PostKernel,
        priority: ProbePriority::DEFAULT,
        probe_kinds: &[ProbeKind::Pci {
            on_probe: probe as FnOnProbe,
        }],
    );

    fn probe(mut probe: ProbePci<'_>) -> Result<(), OnProbeError> {
        let endpoint = probe.endpoint_mut();
        if endpoint.vendor_id() != INTEL_VENDOR_ID || endpoint.device_id() != I6300ESB_DEVICE_ID {
            return Err(OnProbeError::NotMatch);
        }
        let Some(bar) = endpoint.bar_mmio(0) else {
            return Err(OnProbeError::other("i6300ESB BAR0 MMIO region missing"));
        };
        endpoint.update_command(|mut command| {
            command.insert(CommandRegister::MEMORY_ENABLE);
            command
        });
        let mmio = crate::mmio::iomap(bar.start, bar.count().max(16))?;

        let address = endpoint.address();
        let config_address = 0x8000_0000
            | (u32::from(address.bus()) << 16)
            | (u32::from(address.device()) << 11)
            | (u32::from(address.function()) << 8);
        WATCHDOG_CONFIG_ADDRESS.store(config_address, Ordering::Release);
        WATCHDOG_MMIO.store(mmio.as_ptr() as usize, Ordering::Release);
        log::info!(
            "KernDiff i6300ESB watchdog discovered at {}",
            endpoint.address()
        );
        Ok(())
    }
}

mod pvpanic_driver {
    use super::*;

    crate::model_register!(
        name: "KernDiff pvpanic",
        level: ProbeLevel::PostKernel,
        priority: ProbePriority::DEFAULT,
        probe_kinds: &[ProbeKind::Pci {
            on_probe: probe as FnOnProbe,
        }],
    );

    fn probe(mut probe: ProbePci<'_>) -> Result<(), OnProbeError> {
        let endpoint = probe.endpoint_mut();
        if endpoint.vendor_id() != REDHAT_VENDOR_ID || endpoint.device_id() != PVPANIC_DEVICE_ID {
            return Err(OnProbeError::NotMatch);
        }
        let Some(bar) = endpoint.bar_mmio(0) else {
            return Err(OnProbeError::other("pvpanic BAR0 MMIO region missing"));
        };
        endpoint.update_command(|mut command| {
            command.insert(CommandRegister::MEMORY_ENABLE);
            command
        });
        let mmio = crate::mmio::iomap(bar.start, bar.count().max(1))?;
        PVPANIC_MMIO.store(mmio.as_ptr() as usize, Ordering::Release);
        log::info!("KernDiff pvpanic discovered at {}", endpoint.address());
        Ok(())
    }
}

/// Arms the two-stage watchdog and initializes its host-readable page.
pub fn arm_watchdog(online_mask: u64, boot_epoch: u64) -> bool {
    let base = WATCHDOG_MMIO.load(Ordering::Acquire);
    if base == 0 || online_mask == 0 || !configure_watchdog() {
        return false;
    }
    reset_diagnostic_page(&DIAGNOSTIC, boot_epoch, online_mask);
    FORCED_STALE_MASK.store(0, Ordering::Release);
    unsafe {
        apply_programming_sequence(base, &watchdog_programming_sequence());
    }
    if !enable_watchdog() {
        return false;
    }
    WATCHDOG_ARMED.store(true, Ordering::Release);
    true
}

/// Records one stable early-boot phase before its serial marker is emitted.
///
/// The single boot CPU publishes the phases in exact numeric order.  A caller
/// that duplicates or skips a phase gets no record and must not emit a marker.
pub fn record_boot_phase(phase: u32, now_ns: u64) -> Option<(u64, u64)> {
    record_boot_phase_in(
        &DIAGNOSTIC,
        WATCHDOG_ARMED.load(Ordering::Acquire),
        phase,
        now_ns,
    )
}

fn record_boot_phase_in(
    diagnostic: &DiagnosticPage,
    watchdog_armed: bool,
    phase: u32,
    now_ns: u64,
) -> Option<(u64, u64)> {
    if !watchdog_armed
        || usize::try_from(phase).ok()? >= BOOT_PHASE_COUNT
        || diagnostic.phase_sequence.load(Ordering::Acquire) != u64::from(phase)
    {
        return None;
    }
    let elapsed_ns = now_ns.saturating_sub(diagnostic.boot_epoch.load(Ordering::Acquire));
    diagnostic.phase_elapsed_ns[phase as usize].store(elapsed_ns, Ordering::Relaxed);
    diagnostic
        .reached_phase_bitmap
        .fetch_or(1u64 << phase, Ordering::Release);
    diagnostic.last_phase.store(phase, Ordering::Release);
    let sequence = u64::from(phase) + 1;
    diagnostic.phase_sequence.store(sequence, Ordering::Release);
    Some((sequence, elapsed_ns))
}

/// Records one bootstrap feeder checkpoint without allocating, locking, or logging.
///
/// Each checkpoint has one producer. The elapsed value is stored before its bit
/// is published with release ordering. Task-entry checkpoints deliberately do
/// not depend on `FeederSpawnReturned` because the new task may run before the
/// spawning task returns from runqueue insertion.
pub fn record_bootstrap_checkpoint(checkpoint: BootstrapCheckpoint, now_ns: u64) -> Option<u64> {
    record_bootstrap_checkpoint_in(
        &DIAGNOSTIC,
        WATCHDOG_ARMED.load(Ordering::Acquire),
        checkpoint,
        now_ns,
    )
}

/// Publishes the feeder task identity before the task becomes runnable.
pub fn register_bootstrap_feeder_task(task_id: u64) -> bool {
    if task_id == 0
        || !WATCHDOG_ARMED.load(Ordering::Acquire)
        || DIAGNOSTIC
            .bootstrap_checkpoint_bitmap
            .load(Ordering::Acquire)
            & (1u64 << BootstrapCheckpoint::FeederTaskInitialized as usize)
            == 0
    {
        return false;
    }
    BOOTSTRAP_FEEDER_TASK_ID
        .compare_exchange(0, task_id, Ordering::Release, Ordering::Acquire)
        .is_ok()
}

/// Records the first eligible diagnostic task selected by the scheduler.
///
/// The clock callback is evaluated only after the task identity, watchdog state,
/// checkpoint dependencies, and unpublished selection bit have been verified.
/// Ordinary context switches therefore perform at most the two registered-task
/// identity loads and do not read the clock.
pub fn record_scheduler_selection(task_id: u64, read_now_ns: impl FnOnce() -> u64) -> Option<u64> {
    let task_ids = SchedulerTaskIds::new(
        BOOTSTRAP_FEEDER_TASK_ID.load(Ordering::Acquire),
        INIT_TASK_ID.load(Ordering::Acquire),
    );
    if !task_ids.contains(task_id) {
        return None;
    }
    record_scheduler_selection_in(
        &DIAGNOSTIC,
        WATCHDOG_ARMED.load(Ordering::Acquire),
        task_ids,
        task_id,
        read_now_ns,
    )
}

fn record_scheduler_selection_in(
    diagnostic: &DiagnosticPage,
    watchdog_armed: bool,
    task_ids: SchedulerTaskIds,
    task_id: u64,
    read_now_ns: impl FnOnce() -> u64,
) -> Option<u64> {
    if task_id != 0 && task_id == task_ids.bootstrap_feeder {
        return record_bootstrap_followup_checkpoint_with_clock_in(
            diagnostic,
            watchdog_armed,
            BootstrapFollowupCheckpoint::FeederSchedulerSelected,
            read_now_ns,
        );
    }
    if task_id != 0 && task_id == task_ids.init {
        return record_init_task_checkpoint_with_clock_in(
            diagnostic,
            watchdog_armed,
            InitTaskCheckpoint::SchedulerSelected,
            read_now_ns,
        );
    }
    None
}

/// Records the scheduler selecting the registered feeder for the first time.
pub fn record_bootstrap_scheduler_selection(task_id: u64, now_ns: u64) -> Option<u64> {
    let feeder_task_id = BOOTSTRAP_FEEDER_TASK_ID.load(Ordering::Acquire);
    record_bootstrap_scheduler_selection_in(
        &DIAGNOSTIC,
        WATCHDOG_ARMED.load(Ordering::Acquire),
        feeder_task_id,
        task_id,
        now_ns,
    )
}

fn record_bootstrap_scheduler_selection_in(
    diagnostic: &DiagnosticPage,
    watchdog_armed: bool,
    feeder_task_id: u64,
    task_id: u64,
    now_ns: u64,
) -> Option<u64> {
    if feeder_task_id == 0 || task_id != feeder_task_id {
        return None;
    }
    record_bootstrap_followup_checkpoint_in(
        diagnostic,
        watchdog_armed,
        BootstrapFollowupCheckpoint::FeederSchedulerSelected,
        now_ns,
    )
}

/// Records one post-spawn bootstrap boundary without allocating, locking, or logging.
pub fn record_bootstrap_followup_checkpoint(
    checkpoint: BootstrapFollowupCheckpoint,
    now_ns: u64,
) -> Option<u64> {
    record_bootstrap_followup_checkpoint_in(
        &DIAGNOSTIC,
        WATCHDOG_ARMED.load(Ordering::Acquire),
        checkpoint,
        now_ns,
    )
}

fn record_bootstrap_checkpoint_in(
    diagnostic: &DiagnosticPage,
    watchdog_armed: bool,
    checkpoint: BootstrapCheckpoint,
    now_ns: u64,
) -> Option<u64> {
    if !watchdog_armed {
        return None;
    }
    let bit = 1u64 << checkpoint as usize;
    let observed = diagnostic
        .bootstrap_checkpoint_bitmap
        .load(Ordering::Acquire);
    let required = checkpoint.required_bitmap();
    if observed & bit != 0 || observed & required != required {
        return None;
    }
    let elapsed_ns = now_ns.saturating_sub(diagnostic.boot_epoch.load(Ordering::Acquire));
    diagnostic.bootstrap_checkpoint_elapsed_ns[checkpoint as usize]
        .store(elapsed_ns, Ordering::Relaxed);
    diagnostic
        .bootstrap_checkpoint_bitmap
        .fetch_or(bit, Ordering::Release);
    Some(elapsed_ns)
}

fn record_bootstrap_followup_checkpoint_in(
    diagnostic: &DiagnosticPage,
    watchdog_armed: bool,
    checkpoint: BootstrapFollowupCheckpoint,
    now_ns: u64,
) -> Option<u64> {
    record_bootstrap_followup_checkpoint_with_clock_in(
        diagnostic,
        watchdog_armed,
        checkpoint,
        || now_ns,
    )
}

fn record_bootstrap_followup_checkpoint_with_clock_in(
    diagnostic: &DiagnosticPage,
    watchdog_armed: bool,
    checkpoint: BootstrapFollowupCheckpoint,
    read_now_ns: impl FnOnce() -> u64,
) -> Option<u64> {
    if !watchdog_armed {
        return None;
    }
    let bootstrap = diagnostic
        .bootstrap_checkpoint_bitmap
        .load(Ordering::Acquire);
    let required_bootstrap = checkpoint.required_bootstrap_bitmap();
    if bootstrap & required_bootstrap != required_bootstrap {
        return None;
    }
    let bit = 1u64 << checkpoint as usize;
    let observed = diagnostic
        .bootstrap_followup_checkpoint_bitmap
        .load(Ordering::Acquire);
    let required_followup = checkpoint.required_followup_bitmap();
    if observed & bit != 0 || observed & required_followup != required_followup {
        return None;
    }
    let now_ns = read_now_ns();
    let elapsed_ns = now_ns.saturating_sub(diagnostic.boot_epoch.load(Ordering::Acquire));
    diagnostic.bootstrap_followup_checkpoint_elapsed_ns[checkpoint as usize]
        .store(elapsed_ns, Ordering::Relaxed);
    diagnostic
        .bootstrap_followup_checkpoint_bitmap
        .fetch_or(bit, Ordering::Release);
    Some(elapsed_ns)
}

/// Records one init-task boundary without allocating, locking, or logging.
pub fn record_init_task_checkpoint(checkpoint: InitTaskCheckpoint, now_ns: u64) -> Option<u64> {
    record_init_task_checkpoint_in(
        &DIAGNOSTIC,
        WATCHDOG_ARMED.load(Ordering::Acquire),
        checkpoint,
        now_ns,
    )
}

/// Publishes the init task identity before the task becomes runnable.
pub fn register_init_task(task_id: u64) -> bool {
    if task_id == 0
        || !WATCHDOG_ARMED.load(Ordering::Acquire)
        || DIAGNOSTIC
            .init_task_checkpoint_bitmap
            .load(Ordering::Acquire)
            & (1u64 << InitTaskCheckpoint::TaskInitialized as usize)
            == 0
    {
        return false;
    }
    INIT_TASK_ID
        .compare_exchange(0, task_id, Ordering::Release, Ordering::Acquire)
        .is_ok()
}

/// Records the scheduler selecting the registered init task for the first time.
pub fn record_init_scheduler_selection(task_id: u64, now_ns: u64) -> Option<u64> {
    let init_task_id = INIT_TASK_ID.load(Ordering::Acquire);
    record_init_scheduler_selection_in(
        &DIAGNOSTIC,
        WATCHDOG_ARMED.load(Ordering::Acquire),
        init_task_id,
        task_id,
        now_ns,
    )
}

fn record_init_scheduler_selection_in(
    diagnostic: &DiagnosticPage,
    watchdog_armed: bool,
    init_task_id: u64,
    task_id: u64,
    now_ns: u64,
) -> Option<u64> {
    if init_task_id == 0 || task_id != init_task_id {
        return None;
    }
    record_init_task_checkpoint_in(
        diagnostic,
        watchdog_armed,
        InitTaskCheckpoint::SchedulerSelected,
        now_ns,
    )
}

fn record_init_task_checkpoint_in(
    diagnostic: &DiagnosticPage,
    watchdog_armed: bool,
    checkpoint: InitTaskCheckpoint,
    now_ns: u64,
) -> Option<u64> {
    record_init_task_checkpoint_with_clock_in(diagnostic, watchdog_armed, checkpoint, || now_ns)
}

fn record_init_task_checkpoint_with_clock_in(
    diagnostic: &DiagnosticPage,
    watchdog_armed: bool,
    checkpoint: InitTaskCheckpoint,
    read_now_ns: impl FnOnce() -> u64,
) -> Option<u64> {
    if !watchdog_armed
        || diagnostic.phase_sequence.load(Ordering::Acquire) < INIT_TASK_REQUIRED_PHASE_SEQUENCE
    {
        return None;
    }
    let bit = 1u64 << checkpoint as usize;
    let observed = diagnostic
        .init_task_checkpoint_bitmap
        .load(Ordering::Acquire);
    let required = checkpoint.required_bitmap();
    if observed & bit != 0 || observed & required != required {
        return None;
    }
    let now_ns = read_now_ns();
    let elapsed_ns = now_ns.saturating_sub(diagnostic.boot_epoch.load(Ordering::Acquire));
    diagnostic.init_task_checkpoint_elapsed_ns[checkpoint as usize]
        .store(elapsed_ns, Ordering::Relaxed);
    diagnostic
        .init_task_checkpoint_bitmap
        .fetch_or(bit, Ordering::Release);
    Some(elapsed_ns)
}

fn reset_diagnostic_page(diagnostic: &DiagnosticPage, boot_epoch: u64, online_mask: u64) {
    BOOTSTRAP_FEEDER_TASK_ID.store(0, Ordering::Release);
    INIT_TASK_ID.store(0, Ordering::Release);
    diagnostic.boot_epoch.store(boot_epoch, Ordering::Release);
    diagnostic.online_mask.store(online_mask, Ordering::Release);
    diagnostic.stale_mask.store(0, Ordering::Release);
    for cpu in 0..MAX_CPUS {
        diagnostic.scheduler_epoch[cpu].store(0, Ordering::Relaxed);
        diagnostic.irq_epoch[cpu].store(0, Ordering::Relaxed);
        diagnostic.last_progress_ns[cpu].store(0, Ordering::Relaxed);
    }
    diagnostic.reached_phase_bitmap.store(0, Ordering::Release);
    diagnostic.last_phase.store(u32::MAX, Ordering::Release);
    diagnostic.phase_sequence.store(0, Ordering::Release);
    for elapsed in &diagnostic.phase_elapsed_ns {
        elapsed.store(0, Ordering::Relaxed);
    }
    diagnostic
        .bootstrap_checkpoint_bitmap
        .store(0, Ordering::Release);
    for elapsed in &diagnostic.bootstrap_checkpoint_elapsed_ns {
        elapsed.store(0, Ordering::Relaxed);
    }
    diagnostic
        .bootstrap_followup_checkpoint_bitmap
        .store(0, Ordering::Release);
    for elapsed in &diagnostic.bootstrap_followup_checkpoint_elapsed_ns {
        elapsed.store(0, Ordering::Relaxed);
    }
    diagnostic
        .init_task_checkpoint_bitmap
        .store(0, Ordering::Release);
    for elapsed in &diagnostic.init_task_checkpoint_elapsed_ns {
        elapsed.store(0, Ordering::Relaxed);
    }
}

/// Updates the diagnostic page for the completed SMP handoff.
///
/// Seeding every online CPU with the handoff timestamp gives each pinned task
/// one full stale interval to run for the first time.
pub fn configure_online_mask(online_mask: u64, now_ns: u64) {
    if !WATCHDOG_ARMED.load(Ordering::Acquire) || online_mask == 0 {
        return;
    }
    for cpu in 0..MAX_CPUS {
        if online_mask & (1u64 << cpu) != 0 {
            DIAGNOSTIC.last_progress_ns[cpu].store(now_ns, Ordering::Release);
        }
    }
    DIAGNOSTIC.online_mask.store(online_mask, Ordering::Release);
    DIAGNOSTIC.stale_mask.store(0, Ordering::Release);
    FORCED_STALE_MASK.store(0, Ordering::Release);
}

/// Records and feeds the bootstrap CPU before the full SMP policy is active.
pub fn bootstrap_poll(scheduler_epoch: u64, now_ns: u64) {
    if !WATCHDOG_ARMED.load(Ordering::Acquire) {
        return;
    }
    record_liveness(0, scheduler_epoch, now_ns);
    DIAGNOSTIC.stale_mask.store(0, Ordering::Release);
    ping_watchdog();
}

/// Records one pinned CPU's scheduler-task epoch.
pub fn record_liveness(cpu: usize, scheduler_epoch: u64, now_ns: u64) {
    if cpu >= MAX_CPUS {
        return;
    }
    DIAGNOSTIC.scheduler_epoch[cpu].store(scheduler_epoch, Ordering::Relaxed);
    DIAGNOSTIC.last_progress_ns[cpu].store(now_ns, Ordering::Release);
}

/// Records a timer interrupt without allocating, locking, or consulting tasks.
pub fn record_timer_irq(cpu: usize) {
    if cpu < MAX_CPUS {
        DIAGNOSTIC.irq_epoch[cpu].fetch_add(1, Ordering::Relaxed);
    }
}

/// Pings only while every online CPU has advanced within the stale deadline.
pub fn coordinator_poll(now_ns: u64) -> u64 {
    if !WATCHDOG_ARMED.load(Ordering::Acquire) {
        return 0;
    }
    let online = DIAGNOSTIC.online_mask.load(Ordering::Acquire);
    let observed = stale_mask(online, now_ns, |cpu| {
        DIAGNOSTIC.last_progress_ns[cpu].load(Ordering::Acquire)
    });
    let stale = combined_stale_mask(online, observed, FORCED_STALE_MASK.load(Ordering::Acquire));
    DIAGNOSTIC.stale_mask.store(stale, Ordering::Release);
    if stale == 0 {
        ping_watchdog();
    }
    stale
}

/// Forces supporting stale-CPU diagnostics for a deliberate validation hang.
///
/// This does not arm, ping, or otherwise change the watchdog.  The subsequent
/// WATCHDOG QMP event remains the only authoritative kernel-hang evidence.
pub fn force_stale_mask(requested_mask: u64) -> u64 {
    let online = DIAGNOSTIC.online_mask.load(Ordering::Acquire);
    let stale = forced_stale_mask(online, requested_mask);
    FORCED_STALE_MASK.store(stale, Ordering::Release);
    DIAGNOSTIC.stale_mask.store(stale, Ordering::Release);
    stale
}

pub fn diagnostic_page_physical_address() -> u64 {
    axklib::mem::virt_to_phys((&DIAGNOSTIC as *const DiagnosticPage as usize).into()).as_usize()
        as u64
}

/// Sends PVPANIC_PANICKED once, without allocation or locking.
pub fn notify_panic() {
    if PVPANIC_NOTIFIED.swap(true, Ordering::AcqRel) {
        return;
    }
    let address = PVPANIC_MMIO.load(Ordering::Acquire);
    if address != 0 {
        unsafe { write_pvpanic_panicked(address) };
        return;
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        write_pvpanic_panicked_port(PVPANIC_IO_PORT);
    }
}

unsafe fn write_pvpanic_panicked(address: usize) {
    unsafe { write_volatile(address as *mut u8, 1) };
}

#[cfg(target_arch = "x86_64")]
unsafe fn write_pvpanic_panicked_port(port: u16) {
    unsafe { x86::io::outb(port, 1) };
}

fn stale_mask(online_mask: u64, now_ns: u64, last_progress: impl Fn(usize) -> u64) -> u64 {
    let deadline_ns = LIVENESS_STALE_SECONDS * 1_000_000_000;
    let mut stale = 0;
    for cpu in 0..MAX_CPUS {
        let bit = 1u64 << cpu;
        if online_mask & bit == 0 {
            continue;
        }
        let last = last_progress(cpu);
        if last == 0 || now_ns.saturating_sub(last) >= deadline_ns {
            stale |= bit;
        }
    }
    stale
}

const fn forced_stale_mask(online_mask: u64, requested_mask: u64) -> u64 {
    online_mask & requested_mask
}

const fn combined_stale_mask(online_mask: u64, observed: u64, forced: u64) -> u64 {
    online_mask & (observed | forced)
}

fn ping_watchdog() {
    let base = WATCHDOG_MMIO.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    unsafe {
        write_volatile((base + ESB_RELOAD_OFFSET) as *mut u16, ESB_UNLOCK1);
        write_volatile((base + ESB_RELOAD_OFFSET) as *mut u16, ESB_UNLOCK2);
        write_volatile((base + ESB_RELOAD_OFFSET) as *mut u16, ESB_RELOAD);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProgrammingOperation {
    Write16(usize, u16),
    Write32(usize, u32),
}

const fn watchdog_programming_sequence() -> [ProgrammingOperation; 12] {
    use ProgrammingOperation::{Write16, Write32};
    [
        Write16(ESB_RELOAD_OFFSET, ESB_UNLOCK1),
        Write16(ESB_RELOAD_OFFSET, ESB_UNLOCK2),
        Write32(ESB_TIMER1_OFFSET, TIMER_TICKS),
        Write16(ESB_RELOAD_OFFSET, ESB_UNLOCK1),
        Write16(ESB_RELOAD_OFFSET, ESB_UNLOCK2),
        Write32(ESB_TIMER2_OFFSET, TIMER_TICKS),
        Write16(ESB_RELOAD_OFFSET, ESB_UNLOCK1),
        Write16(ESB_RELOAD_OFFSET, ESB_UNLOCK2),
        Write16(ESB_RELOAD_OFFSET, ESB_RELOAD),
        Write16(ESB_RELOAD_OFFSET, ESB_UNLOCK1),
        Write16(ESB_RELOAD_OFFSET, ESB_UNLOCK2),
        Write16(ESB_RELOAD_OFFSET, ESB_RELOAD),
    ]
}

unsafe fn apply_programming_sequence(base: usize, operations: &[ProgrammingOperation]) {
    for operation in operations {
        match *operation {
            ProgrammingOperation::Write16(offset, value) => unsafe {
                write_volatile((base + offset) as *mut u16, value)
            },
            ProgrammingOperation::Write32(offset, value) => unsafe {
                write_volatile((base + offset) as *mut u32, value)
            },
        }
    }
    // Enable after both stages are programmed.  BAR reads flush posted writes.
    unsafe {
        let _ = read_volatile((base + ESB_RELOAD_OFFSET) as *const u16);
    }
}

#[cfg(target_arch = "x86_64")]
fn configure_watchdog() -> bool {
    let config_address = WATCHDOG_CONFIG_ADDRESS.load(Ordering::Acquire);
    if config_address == 0 {
        return false;
    }
    unsafe {
        pci_config_write_u16(config_address, ESB_CONFIG_OFFSET, ESB_CONFIG_VALUE);
        pci_config_write_u8(config_address, ESB_LOCK_OFFSET, 0);
        pci_config_read_u16(config_address, ESB_CONFIG_OFFSET) == ESB_CONFIG_VALUE
            && pci_config_read_u8(config_address, ESB_LOCK_OFFSET) == 0
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn configure_watchdog() -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
fn enable_watchdog() -> bool {
    let config_address = WATCHDOG_CONFIG_ADDRESS.load(Ordering::Acquire);
    if config_address == 0 {
        return false;
    }
    unsafe {
        pci_config_write_u8(config_address, ESB_LOCK_OFFSET, ESB_ENABLE);
        pci_config_read_u8(config_address, ESB_LOCK_OFFSET) & ESB_ENABLE != 0
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn enable_watchdog() -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
unsafe fn pci_config_write_u8(config_address: u32, offset: u16, value: u8) {
    unsafe {
        x86::io::outl(0xcf8, pci_config_selector(config_address, offset));
        x86::io::outb(pci_config_data_port(offset), value);
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn pci_config_write_u16(config_address: u32, offset: u16, value: u16) {
    unsafe {
        x86::io::outl(0xcf8, pci_config_selector(config_address, offset));
        x86::io::outw(pci_config_data_port(offset), value);
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn pci_config_read_u8(config_address: u32, offset: u16) -> u8 {
    unsafe {
        x86::io::outl(0xcf8, pci_config_selector(config_address, offset));
        x86::io::inb(pci_config_data_port(offset))
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn pci_config_read_u16(config_address: u32, offset: u16) -> u16 {
    unsafe {
        x86::io::outl(0xcf8, pci_config_selector(config_address, offset));
        x86::io::inw(pci_config_data_port(offset))
    }
}

#[cfg(target_arch = "x86_64")]
const fn pci_config_selector(config_address: u32, offset: u16) -> u32 {
    config_address | (offset & !3) as u32
}

#[cfg(target_arch = "x86_64")]
const fn pci_config_data_port(offset: u16) -> u16 {
    0xcfc + (offset & 3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programs_two_thirty_second_stages_with_required_unlocks() {
        let operations = watchdog_programming_sequence();
        assert_eq!(TIMER_TICKS, 60 << 9);
        assert_eq!(
            operations[0..3],
            [
                ProgrammingOperation::Write16(ESB_RELOAD_OFFSET, ESB_UNLOCK1),
                ProgrammingOperation::Write16(ESB_RELOAD_OFFSET, ESB_UNLOCK2),
                ProgrammingOperation::Write32(ESB_TIMER1_OFFSET, 60 << 9),
            ]
        );
        assert!(operations.contains(&ProgrammingOperation::Write32(ESB_TIMER2_OFFSET, 60 << 9)));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn uses_exact_width_pci_config_ports_for_qemu_watchdog_registers() {
        let address = 0x8000_2800;
        assert_eq!(pci_config_selector(address, ESB_CONFIG_OFFSET), 0x8000_2860);
        assert_eq!(pci_config_selector(address, ESB_LOCK_OFFSET), 0x8000_2868);
        assert_eq!(pci_config_data_port(ESB_CONFIG_OFFSET), 0xcfc);
        assert_eq!(pci_config_data_port(ESB_LOCK_OFFSET), 0xcfc);
    }

    #[test]
    fn any_online_stale_cpu_stops_feeding() {
        let now = 20_000_000_000;
        let stale = stale_mask(0b1111, now, |cpu| {
            if cpu == 2 {
                1_000_000_000
            } else {
                19_000_000_000
            }
        });
        assert_eq!(stale, 0b0100);
    }

    #[test]
    fn forced_stale_diagnostic_is_limited_to_online_cpus() {
        assert_eq!(forced_stale_mask(0b1110, 0b0101), 0b0100);
        assert_eq!(forced_stale_mask(0b1111, 1), 1);
        assert_eq!(combined_stale_mask(0b1110, 0b0010, 0b0101), 0b0110);
    }

    #[test]
    fn diagnostic_layout_fits_one_qmp_memsave_page() {
        assert!(size_of::<DiagnosticPage>() <= DIAGNOSTIC_PAGE_BYTES);
        assert_eq!(DIAGNOSTIC.magic, DIAGNOSTIC_MAGIC);
        assert_eq!(DIAGNOSTIC.version, 5);
        assert_eq!(size_of::<DiagnosticPage>(), 4096);
        assert_eq!(
            core::mem::offset_of!(DiagnosticPage, reached_phase_bitmap),
            1576
        );
        assert_eq!(
            core::mem::offset_of!(DiagnosticPage, phase_elapsed_ns),
            1600
        );
        assert_eq!(
            core::mem::offset_of!(DiagnosticPage, bootstrap_checkpoint_bitmap),
            1696
        );
        assert_eq!(
            core::mem::offset_of!(DiagnosticPage, bootstrap_checkpoint_elapsed_ns),
            1704
        );
        assert_eq!(
            core::mem::offset_of!(DiagnosticPage, bootstrap_followup_checkpoint_bitmap),
            1752
        );
        assert_eq!(
            core::mem::offset_of!(DiagnosticPage, bootstrap_followup_checkpoint_elapsed_ns),
            1760
        );
        assert_eq!(
            core::mem::offset_of!(DiagnosticPage, init_task_checkpoint_bitmap),
            1808
        );
        assert_eq!(
            core::mem::offset_of!(DiagnosticPage, init_task_checkpoint_elapsed_ns),
            1816
        );
    }

    #[test]
    fn boot_phase_records_are_ordered_and_published() {
        let diagnostic = DiagnosticPage::new();
        diagnostic.boot_epoch.store(100, Ordering::Release);

        assert_eq!(record_boot_phase_in(&diagnostic, true, 1, 120), None);
        assert_eq!(
            record_boot_phase_in(&diagnostic, true, 0, 125),
            Some((1, 25))
        );
        assert_eq!(record_boot_phase_in(&diagnostic, true, 0, 130), None);
        assert_eq!(
            record_boot_phase_in(&diagnostic, true, 1, 150),
            Some((2, 50))
        );
        assert_eq!(
            diagnostic.reached_phase_bitmap.load(Ordering::Acquire),
            0b11
        );
        assert_eq!(diagnostic.last_phase.load(Ordering::Acquire), 1);
        assert_eq!(diagnostic.phase_sequence.load(Ordering::Acquire), 2);
        assert_eq!(diagnostic.phase_elapsed_ns[0].load(Ordering::Acquire), 25);
        assert_eq!(diagnostic.phase_elapsed_ns[1].load(Ordering::Acquire), 50);
        assert_eq!(record_boot_phase_in(&diagnostic, false, 2, 175), None);
    }

    #[test]
    fn bootstrap_checkpoints_publish_elapsed_time_before_their_bits() {
        let diagnostic = DiagnosticPage::new();
        diagnostic.boot_epoch.store(100, Ordering::Release);

        assert_eq!(
            record_bootstrap_checkpoint_in(
                &diagnostic,
                true,
                BootstrapCheckpoint::FeederSpawnRequested,
                125,
            ),
            Some(25)
        );
        assert_eq!(
            diagnostic
                .bootstrap_checkpoint_bitmap
                .load(Ordering::Acquire),
            1
        );
        assert_eq!(
            diagnostic.bootstrap_checkpoint_elapsed_ns[0].load(Ordering::Acquire),
            25
        );
        assert_eq!(
            record_bootstrap_checkpoint_in(
                &diagnostic,
                true,
                BootstrapCheckpoint::FeederSpawnRequested,
                150,
            ),
            None
        );
    }

    #[test]
    fn bootstrap_checkpoint_dependencies_allow_task_entry_before_spawn_returns() {
        let diagnostic = DiagnosticPage::new();
        diagnostic.boot_epoch.store(100, Ordering::Release);

        assert_eq!(
            record_bootstrap_checkpoint_in(
                &diagnostic,
                true,
                BootstrapCheckpoint::FeederEntered,
                101,
            ),
            None
        );
        for (checkpoint, now_ns) in [
            (BootstrapCheckpoint::FeederSpawnRequested, 110),
            (BootstrapCheckpoint::FeederTaskInitialized, 120),
            (BootstrapCheckpoint::FeederEntered, 130),
            (BootstrapCheckpoint::FeederAffinityReady, 140),
            (BootstrapCheckpoint::FeederFirstPollComplete, 150),
            (BootstrapCheckpoint::FeederSpawnReturned, 160),
        ] {
            assert_eq!(
                record_bootstrap_checkpoint_in(&diagnostic, true, checkpoint, now_ns),
                Some(now_ns - 100)
            );
        }
        assert_eq!(
            diagnostic
                .bootstrap_checkpoint_bitmap
                .load(Ordering::Acquire),
            0b11_1111
        );
    }

    #[test]
    fn bootstrap_followup_checkpoints_split_scheduler_and_main_thread_progress() {
        let diagnostic = DiagnosticPage::new();
        diagnostic.boot_epoch.store(100, Ordering::Release);

        for (checkpoint, now_ns) in [
            (BootstrapCheckpoint::FeederSpawnRequested, 110),
            (BootstrapCheckpoint::FeederTaskInitialized, 120),
            (BootstrapCheckpoint::FeederSpawnReturned, 130),
        ] {
            assert_eq!(
                record_bootstrap_checkpoint_in(&diagnostic, true, checkpoint, now_ns),
                Some(now_ns - 100)
            );
        }
        for (checkpoint, now_ns) in [
            (BootstrapFollowupCheckpoint::MainBootstrapReturned, 140),
            (BootstrapFollowupCheckpoint::SerialInitEntered, 150),
            (BootstrapFollowupCheckpoint::FeederSchedulerSelected, 160),
            (BootstrapFollowupCheckpoint::SerialInitReturned, 170),
            (BootstrapFollowupCheckpoint::RtcOutputEntered, 180),
            (BootstrapFollowupCheckpoint::RtcOutputReturned, 190),
        ] {
            assert_eq!(
                record_bootstrap_followup_checkpoint_in(&diagnostic, true, checkpoint, now_ns,),
                Some(now_ns - 100)
            );
        }
        assert_eq!(
            diagnostic
                .bootstrap_followup_checkpoint_bitmap
                .load(Ordering::Acquire),
            0b11_1111
        );
    }

    #[test]
    fn scheduler_selection_records_only_the_registered_feeder() {
        let diagnostic = DiagnosticPage::new();
        diagnostic.boot_epoch.store(100, Ordering::Release);
        for (checkpoint, now_ns) in [
            (BootstrapCheckpoint::FeederSpawnRequested, 110),
            (BootstrapCheckpoint::FeederTaskInitialized, 120),
        ] {
            assert!(
                record_bootstrap_checkpoint_in(&diagnostic, true, checkpoint, now_ns).is_some()
            );
        }

        assert_eq!(
            record_bootstrap_scheduler_selection_in(&diagnostic, true, 41, 40, 130),
            None
        );
        assert_eq!(
            record_bootstrap_scheduler_selection_in(&diagnostic, true, 41, 41, 140),
            Some(40)
        );
        assert_eq!(
            diagnostic
                .bootstrap_followup_checkpoint_bitmap
                .load(Ordering::Acquire),
            1
        );
    }

    #[test]
    fn lazy_scheduler_selection_skips_clock_until_a_checkpoint_is_eligible() {
        let missing_dependencies = DiagnosticPage::new();
        let eligible = DiagnosticPage::new();
        eligible.boot_epoch.store(100, Ordering::Release);
        for (checkpoint, now_ns) in [
            (BootstrapCheckpoint::FeederSpawnRequested, 110),
            (BootstrapCheckpoint::FeederTaskInitialized, 120),
        ] {
            assert!(record_bootstrap_checkpoint_in(&eligible, true, checkpoint, now_ns).is_some());
        }
        let clock_reads = core::cell::Cell::new(0);

        for (diagnostic, watchdog_armed, task_ids, task_id) in [
            (&missing_dependencies, true, SchedulerTaskIds::new(0, 0), 41),
            (
                &missing_dependencies,
                true,
                SchedulerTaskIds::new(41, 42),
                43,
            ),
            (
                &missing_dependencies,
                true,
                SchedulerTaskIds::new(41, 0),
                41,
            ),
            (
                &missing_dependencies,
                true,
                SchedulerTaskIds::new(0, 42),
                42,
            ),
            (&eligible, false, SchedulerTaskIds::new(41, 0), 41),
        ] {
            assert_eq!(
                record_scheduler_selection_in(
                    diagnostic,
                    watchdog_armed,
                    task_ids,
                    task_id,
                    || {
                        clock_reads.set(clock_reads.get() + 1);
                        999
                    },
                ),
                None
            );
        }
        assert_eq!(clock_reads.get(), 0);
    }

    #[test]
    fn lazy_scheduler_selection_reads_clock_once_for_the_bootstrap_feeder() {
        let diagnostic = DiagnosticPage::new();
        diagnostic.boot_epoch.store(100, Ordering::Release);
        for (checkpoint, now_ns) in [
            (BootstrapCheckpoint::FeederSpawnRequested, 110),
            (BootstrapCheckpoint::FeederTaskInitialized, 120),
        ] {
            assert!(
                record_bootstrap_checkpoint_in(&diagnostic, true, checkpoint, now_ns).is_some()
            );
        }
        let clock_reads = core::cell::Cell::new(0);
        let task_ids = SchedulerTaskIds::new(41, 0);

        assert_eq!(
            record_scheduler_selection_in(&diagnostic, true, task_ids, 41, || {
                clock_reads.set(clock_reads.get() + 1);
                140
            }),
            Some(40)
        );
        assert_eq!(clock_reads.get(), 1);
        assert_eq!(
            diagnostic.bootstrap_followup_checkpoint_elapsed_ns
                [BootstrapFollowupCheckpoint::FeederSchedulerSelected as usize]
                .load(Ordering::Acquire),
            40
        );
        assert_eq!(
            diagnostic
                .bootstrap_followup_checkpoint_bitmap
                .load(Ordering::Acquire),
            1
        );

        assert_eq!(
            record_scheduler_selection_in(&diagnostic, true, task_ids, 41, || {
                clock_reads.set(clock_reads.get() + 1);
                150
            }),
            None
        );
        assert_eq!(clock_reads.get(), 1);
    }

    #[test]
    fn bootstrap_followup_rejects_missing_main_thread_boundaries() {
        let diagnostic = DiagnosticPage::new();
        diagnostic.boot_epoch.store(100, Ordering::Release);
        for (checkpoint, now_ns) in [
            (BootstrapCheckpoint::FeederSpawnRequested, 110),
            (BootstrapCheckpoint::FeederTaskInitialized, 120),
        ] {
            assert!(
                record_bootstrap_checkpoint_in(&diagnostic, true, checkpoint, now_ns).is_some()
            );
        }
        assert_eq!(
            record_bootstrap_followup_checkpoint_in(
                &diagnostic,
                true,
                BootstrapFollowupCheckpoint::MainBootstrapReturned,
                130,
            ),
            None
        );
        assert!(
            record_bootstrap_checkpoint_in(
                &diagnostic,
                true,
                BootstrapCheckpoint::FeederSpawnReturned,
                140,
            )
            .is_some()
        );
        assert_eq!(
            record_bootstrap_followup_checkpoint_in(
                &diagnostic,
                true,
                BootstrapFollowupCheckpoint::SerialInitReturned,
                150,
            ),
            None
        );
    }

    #[test]
    fn init_task_checkpoints_allow_the_scheduled_chain_before_spawn_returns() {
        let diagnostic = DiagnosticPage::new();
        diagnostic.boot_epoch.store(100, Ordering::Release);
        assert_eq!(
            record_init_task_checkpoint_in(
                &diagnostic,
                true,
                InitTaskCheckpoint::TaskCreateRequested,
                105,
            ),
            None
        );
        diagnostic
            .phase_sequence
            .store(INIT_TASK_REQUIRED_PHASE_SEQUENCE, Ordering::Release);

        for (checkpoint, now_ns) in [
            (InitTaskCheckpoint::TaskCreateRequested, 110),
            (InitTaskCheckpoint::TaskConstructed, 120),
            (InitTaskCheckpoint::ProcessReady, 130),
            (InitTaskCheckpoint::SpawnRequested, 140),
            (InitTaskCheckpoint::TaskInitialized, 150),
            (InitTaskCheckpoint::TaskExtEntered, 160),
            (InitTaskCheckpoint::TaskExtReturned, 170),
            (InitTaskCheckpoint::SchedulerSelected, 180),
            (InitTaskCheckpoint::TaskEntered, 190),
            (InitTaskCheckpoint::FirstUserRunEntered, 200),
            (InitTaskCheckpoint::FirstUserRunReturned, 210),
            (InitTaskCheckpoint::SpawnReturned, 220),
            (InitTaskCheckpoint::ConsoleIrqArmed, 230),
            (InitTaskCheckpoint::JoinEntered, 240),
        ] {
            assert_eq!(
                record_init_task_checkpoint_in(&diagnostic, true, checkpoint, now_ns),
                Some(now_ns - 100)
            );
        }
        assert_eq!(
            diagnostic
                .init_task_checkpoint_bitmap
                .load(Ordering::Acquire),
            0x3fff
        );
    }

    #[test]
    fn init_scheduler_selection_records_only_the_registered_task() {
        let diagnostic = DiagnosticPage::new();
        diagnostic.boot_epoch.store(100, Ordering::Release);
        diagnostic
            .phase_sequence
            .store(INIT_TASK_REQUIRED_PHASE_SEQUENCE, Ordering::Release);
        for (checkpoint, now_ns) in [
            (InitTaskCheckpoint::TaskCreateRequested, 110),
            (InitTaskCheckpoint::TaskConstructed, 120),
            (InitTaskCheckpoint::ProcessReady, 130),
            (InitTaskCheckpoint::SpawnRequested, 140),
            (InitTaskCheckpoint::TaskInitialized, 150),
            (InitTaskCheckpoint::TaskExtEntered, 160),
            (InitTaskCheckpoint::TaskExtReturned, 170),
        ] {
            assert!(
                record_init_task_checkpoint_in(&diagnostic, true, checkpoint, now_ns).is_some()
            );
        }

        assert_eq!(
            record_init_scheduler_selection_in(&diagnostic, true, 41, 40, 180),
            None
        );
        assert_eq!(
            record_init_scheduler_selection_in(&diagnostic, true, 41, 41, 190),
            Some(90)
        );
    }

    #[test]
    fn lazy_scheduler_selection_reads_clock_once_for_the_init_task() {
        let diagnostic = DiagnosticPage::new();
        diagnostic.boot_epoch.store(100, Ordering::Release);
        diagnostic
            .phase_sequence
            .store(INIT_TASK_REQUIRED_PHASE_SEQUENCE, Ordering::Release);
        for (checkpoint, now_ns) in [
            (InitTaskCheckpoint::TaskCreateRequested, 110),
            (InitTaskCheckpoint::TaskConstructed, 120),
            (InitTaskCheckpoint::ProcessReady, 130),
            (InitTaskCheckpoint::SpawnRequested, 140),
            (InitTaskCheckpoint::TaskInitialized, 150),
            (InitTaskCheckpoint::TaskExtEntered, 160),
            (InitTaskCheckpoint::TaskExtReturned, 170),
        ] {
            assert!(
                record_init_task_checkpoint_in(&diagnostic, true, checkpoint, now_ns).is_some()
            );
        }
        let clock_reads = core::cell::Cell::new(0);
        let task_ids = SchedulerTaskIds::new(0, 42);

        assert_eq!(
            record_scheduler_selection_in(&diagnostic, true, task_ids, 42, || {
                clock_reads.set(clock_reads.get() + 1);
                190
            }),
            Some(90)
        );
        assert_eq!(clock_reads.get(), 1);
        assert_eq!(
            diagnostic.init_task_checkpoint_elapsed_ns
                [InitTaskCheckpoint::SchedulerSelected as usize]
                .load(Ordering::Acquire),
            90
        );
        assert_eq!(
            diagnostic
                .init_task_checkpoint_bitmap
                .load(Ordering::Acquire),
            0x071f
        );

        assert_eq!(
            record_scheduler_selection_in(&diagnostic, true, task_ids, 42, || {
                clock_reads.set(clock_reads.get() + 1);
                200
            }),
            None
        );
        assert_eq!(clock_reads.get(), 1);
    }

    #[test]
    fn watchdog_reset_clears_boot_phases_and_all_checkpoints() {
        let diagnostic = DiagnosticPage::new();
        diagnostic.boot_epoch.store(100, Ordering::Release);
        assert!(record_boot_phase_in(&diagnostic, true, 0, 110).is_some());
        assert!(
            record_bootstrap_checkpoint_in(
                &diagnostic,
                true,
                BootstrapCheckpoint::FeederSpawnRequested,
                120,
            )
            .is_some()
        );
        diagnostic
            .bootstrap_followup_checkpoint_bitmap
            .store(1, Ordering::Release);
        diagnostic.bootstrap_followup_checkpoint_elapsed_ns[0].store(30, Ordering::Release);
        diagnostic
            .init_task_checkpoint_bitmap
            .store(1, Ordering::Release);
        diagnostic.init_task_checkpoint_elapsed_ns[0].store(40, Ordering::Release);

        reset_diagnostic_page(&diagnostic, 500, 1);

        assert_eq!(diagnostic.boot_epoch.load(Ordering::Acquire), 500);
        assert_eq!(diagnostic.online_mask.load(Ordering::Acquire), 1);
        assert_eq!(diagnostic.phase_sequence.load(Ordering::Acquire), 0);
        assert_eq!(
            diagnostic
                .bootstrap_checkpoint_bitmap
                .load(Ordering::Acquire),
            0
        );
        assert!(
            diagnostic
                .bootstrap_checkpoint_elapsed_ns
                .iter()
                .all(|elapsed| elapsed.load(Ordering::Acquire) == 0)
        );
        assert_eq!(
            diagnostic
                .bootstrap_followup_checkpoint_bitmap
                .load(Ordering::Acquire),
            0
        );
        assert!(
            diagnostic
                .bootstrap_followup_checkpoint_elapsed_ns
                .iter()
                .all(|elapsed| elapsed.load(Ordering::Acquire) == 0)
        );
        assert_eq!(
            diagnostic
                .init_task_checkpoint_bitmap
                .load(Ordering::Acquire),
            0
        );
        assert!(
            diagnostic
                .init_task_checkpoint_elapsed_ns
                .iter()
                .all(|elapsed| elapsed.load(Ordering::Acquire) == 0)
        );
    }

    #[test]
    fn pvpanic_writes_panicked_event_byte() {
        let mut event = 0u8;
        unsafe { write_pvpanic_panicked((&mut event as *mut u8) as usize) };
        assert_eq!(event, 1);
    }
}
