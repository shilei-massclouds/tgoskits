//! Two-stage KernDiff kernel liveness policy.
//!
//! The i6300ESB is armed immediately after device discovery.  A CPU0-only
//! feeder protects the remainder of runtime initialization, then hands off to
//! pinned per-CPU liveness tasks once every CPU is online.

use alloc::{format, string::String};
use core::{
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};

const PERIOD: Duration = Duration::from_secs(5);
const MAX_CPUS: usize = 64;
const PHASE_DISABLED: u8 = 0;
const PHASE_BOOTSTRAP: u8 = 1;
const PHASE_HANDOFF: u8 = 2;
const PHASE_PERCPU: u8 = 3;

static PHASE: AtomicU8 = AtomicU8::new(PHASE_DISABLED);

/// Arms the hardware immediately after PCI probing and starts the CPU0 feeder.
pub(super) fn start_bootstrap() {
    let boot_epoch = ax_hal::time::monotonic_time_nanos().max(1);
    if !ax_driver::kerndiff_fault::arm_watchdog(1, boot_epoch) {
        warn!("KernDiff watchdog not armed: i6300ESB unavailable");
        return;
    }
    PHASE.store(PHASE_BOOTSTRAP, Ordering::Release);
    let diagnostic_page = ax_driver::kerndiff_fault::diagnostic_page_physical_address();
    ax_println!(
        "STARRY_KERNEL_WATCHDOG version=1 state=armed timeout_seconds={} online_mask={:#x} \
         diagnostic_page_pa={:#x} boot_epoch={}",
        ax_driver::kerndiff_fault::WATCHDOG_TIMEOUT_SECONDS,
        1u64,
        diagnostic_page,
        boot_epoch,
    );
    ax_task::spawn_raw(
        bootstrap_loop,
        String::from("kerndiff-watchdog-bootstrap"),
        ax_task::default_task_stack_size(),
    );
}

/// Switches from the early CPU0 feeder to the complete per-CPU policy.
pub(super) fn handoff_to_percpu() {
    if PHASE
        .compare_exchange(
            PHASE_BOOTSTRAP,
            PHASE_HANDOFF,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return;
    }

    let online_cpus = ax_hal::cpu_num().min(MAX_CPUS);
    if online_cpus == 0 {
        warn!("KernDiff watchdog handoff failed: no online CPUs");
        PHASE.store(PHASE_BOOTSTRAP, Ordering::Release);
        return;
    }
    let online_mask = if online_cpus == MAX_CPUS {
        u64::MAX
    } else {
        (1u64 << online_cpus) - 1
    };
    ax_driver::kerndiff_fault::configure_online_mask(
        online_mask,
        ax_hal::time::monotonic_time_nanos(),
    );

    for cpu in 0..online_cpus {
        ax_task::spawn_raw(
            move || liveness_loop(cpu),
            format!("kerndiff-live-{cpu}"),
            ax_task::default_task_stack_size(),
        );
    }
    ax_task::spawn_raw(
        coordinator_loop,
        String::from("kerndiff-watchdog"),
        ax_task::default_task_stack_size(),
    );
    PHASE.store(PHASE_PERCPU, Ordering::Release);
    ax_println!(
        "STARRY_KERNEL_WATCHDOG_HANDOFF version=1 state=monitoring online_mask={:#x} \
         stale_seconds={}",
        online_mask,
        ax_driver::kerndiff_fault::LIVENESS_STALE_SECONDS,
    );
}

fn bootstrap_loop() {
    if !ax_task::set_current_affinity(ax_task::AxCpuMask::one_shot(0)) {
        warn!("KernDiff bootstrap feeder could not pin itself to CPU0");
        return;
    }
    let mut epoch = 0u64;
    while PHASE.load(Ordering::Acquire) == PHASE_BOOTSTRAP {
        epoch = epoch.wrapping_add(1);
        ax_driver::kerndiff_fault::bootstrap_poll(epoch, ax_hal::time::monotonic_time_nanos());
        ax_task::sleep(PERIOD);
    }
}

fn liveness_loop(cpu: usize) {
    if !ax_task::set_current_affinity(ax_task::AxCpuMask::one_shot(cpu)) {
        warn!("KernDiff liveness task could not pin itself to CPU{cpu}");
        return;
    }
    let mut epoch = 0u64;
    loop {
        epoch = epoch.wrapping_add(1);
        ax_driver::kerndiff_fault::record_liveness(
            cpu,
            epoch,
            ax_hal::time::monotonic_time_nanos(),
        );
        ax_task::sleep(PERIOD);
    }
}

fn coordinator_loop() {
    if !ax_task::set_current_affinity(ax_task::AxCpuMask::one_shot(0)) {
        warn!("KernDiff watchdog coordinator could not pin itself to CPU0");
        return;
    }
    loop {
        ax_task::sleep(PERIOD);
        let stale =
            ax_driver::kerndiff_fault::coordinator_poll(ax_hal::time::monotonic_time_nanos());
        if stale != 0 {
            warn!("KernDiff watchdog stopped feeding: stale CPU mask={stale:#x}");
        }
    }
}
