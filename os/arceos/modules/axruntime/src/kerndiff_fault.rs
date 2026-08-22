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

use ax_driver::kerndiff_fault::{
    BootstrapCheckpoint, BootstrapFollowupCheckpoint, SerialInitCheckpoint,
};

use crate::KernDiffBootPhase;

const PERIOD: Duration = Duration::from_secs(5);
const MAX_CPUS: usize = 64;
const PHASE_DISABLED: u8 = 0;
const PHASE_BOOTSTRAP: u8 = 1;
const PHASE_HANDOFF: u8 = 2;
const PHASE_PERCPU: u8 = 3;

static PHASE: AtomicU8 = AtomicU8::new(PHASE_DISABLED);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValidationFault {
    ApplicationSigsegv,
    ApplicationNoProgress,
    KernelPanic,
    KernelWatchdog,
    PreWatchdogHang,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InjectionStage {
    BeforeWatchdogArm,
    AfterPerCpuHandoff,
}

fn configured_validation_fault() -> Option<ValidationFault> {
    parse_validation_fault(option_env!("KERNDIFF_VALIDATION_FAULT"))
}

fn parse_validation_fault(value: Option<&str>) -> Option<ValidationFault> {
    match value {
        Some("application-sigsegv") => Some(ValidationFault::ApplicationSigsegv),
        Some("application-no-progress") => Some(ValidationFault::ApplicationNoProgress),
        Some("kernel-panic") => Some(ValidationFault::KernelPanic),
        Some("kernel-watchdog") => Some(ValidationFault::KernelWatchdog),
        Some("pre-watchdog-hang") => Some(ValidationFault::PreWatchdogHang),
        _ => None,
    }
}

fn injection_stage(fault: ValidationFault) -> Option<InjectionStage> {
    match fault {
        ValidationFault::KernelPanic | ValidationFault::KernelWatchdog => {
            Some(InjectionStage::AfterPerCpuHandoff)
        }
        ValidationFault::PreWatchdogHang => Some(InjectionStage::BeforeWatchdogArm),
        ValidationFault::ApplicationSigsegv | ValidationFault::ApplicationNoProgress => None,
    }
}

/// Stops before the hardware watchdog is armed, leaving only the outer QEMU
/// deadline able to terminate the validation run.
pub(super) fn inject_before_watchdog_arm() {
    let Some(fault) = configured_validation_fault() else {
        return;
    };
    if injection_stage(fault) != Some(InjectionStage::BeforeWatchdogArm) {
        return;
    }
    ax_println!(
        "STARRY_KERNDIFF_VALIDATION_FAULT version=1 fault=pre-watchdog-hang \
         phase=before-watchdog-arm"
    );
    ax_hal::asm::disable_irqs();
    loop {
        core::hint::spin_loop();
    }
}

/// Injects kernel faults only after the complete per-CPU watchdog handoff.
pub(super) fn inject_after_percpu_handoff() {
    let Some(fault) = configured_validation_fault() else {
        return;
    };
    if injection_stage(fault) != Some(InjectionStage::AfterPerCpuHandoff) {
        return;
    }
    match fault {
        ValidationFault::KernelPanic => {
            ax_println!(
                "STARRY_KERNDIFF_VALIDATION_FAULT version=1 fault=kernel-panic \
                 phase=after-percpu-handoff"
            );
            panic!("KernDiff validation kernel panic");
        }
        ValidationFault::KernelWatchdog => {
            let stale = ax_driver::kerndiff_fault::force_stale_mask(1);
            ax_println!(
                "STARRY_KERNDIFF_VALIDATION_FAULT version=1 fault=kernel-watchdog \
                 phase=after-percpu-handoff stale_mask={stale:#x}"
            );
            ax_hal::asm::disable_irqs();
            loop {
                core::hint::spin_loop();
            }
        }
        ValidationFault::ApplicationSigsegv
        | ValidationFault::ApplicationNoProgress
        | ValidationFault::PreWatchdogHang => {}
    }
}

/// Arms the hardware immediately after PCI probing and starts the CPU0 feeder.
pub(super) fn start_bootstrap() {
    let boot_epoch = ax_hal::time::monotonic_time_nanos().max(1);
    if !ax_driver::kerndiff_fault::arm_watchdog(1, boot_epoch) {
        warn!("KernDiff watchdog not armed: i6300ESB unavailable");
        return;
    }
    PHASE.store(PHASE_BOOTSTRAP, Ordering::Release);
    publish_boot_phase(KernDiffBootPhase::WatchdogArmed);
    let diagnostic_page = ax_driver::kerndiff_fault::diagnostic_page_physical_address();
    ax_println!(
        "STARRY_KERNEL_WATCHDOG version=1 state=armed timeout_seconds={} online_mask={:#x} \
         diagnostic_page_pa={:#x} boot_epoch={}",
        ax_driver::kerndiff_fault::WATCHDOG_TIMEOUT_SECONDS,
        1u64,
        diagnostic_page,
        boot_epoch,
    );
    record_bootstrap_checkpoint(BootstrapCheckpoint::FeederSpawnRequested);
    let task = ax_task::TaskInner::new(
        bootstrap_loop,
        String::from("kerndiff-watchdog-bootstrap"),
        ax_task::default_task_stack_size(),
    );
    ax_task::spawn_task_with(task, |task| {
        record_bootstrap_checkpoint(BootstrapCheckpoint::FeederTaskInitialized);
        let _ = ax_driver::kerndiff_fault::register_bootstrap_feeder_task(task.id().as_u64());
    });
    record_bootstrap_checkpoint(BootstrapCheckpoint::FeederSpawnReturned);
}

pub(super) fn publish_boot_phase(phase: KernDiffBootPhase) {
    let Some((sequence, elapsed_ns)) = ax_driver::kerndiff_fault::record_boot_phase(
        phase as u32,
        ax_hal::time::monotonic_time_nanos(),
    ) else {
        warn!("KernDiff boot phase rejected: {}", phase.as_str());
        return;
    };
    ax_println!(
        "STARRY_BOOT_STAGE version=2 sequence={} stage={} elapsed_ns={}",
        sequence,
        phase.as_str(),
        elapsed_ns,
    );
    if matches!(
        phase,
        KernDiffBootPhase::KernelMain
            | KernDiffBootPhase::UserspaceInit
            | KernDiffBootPhase::ShellReady
    ) {
        ax_println!("STARRY_BOOT_STAGE version=1 stage={}", phase.as_str());
    }
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
    publish_boot_phase(KernDiffBootPhase::WatchdogHandoff);
    ax_println!(
        "STARRY_KERNEL_WATCHDOG_HANDOFF version=1 state=monitoring online_mask={:#x} \
         stale_seconds={}",
        online_mask,
        ax_driver::kerndiff_fault::LIVENESS_STALE_SECONDS,
    );
}

fn bootstrap_loop() {
    record_bootstrap_checkpoint(BootstrapCheckpoint::FeederEntered);
    let affinity_ready = ax_task::set_current_affinity(ax_task::AxCpuMask::one_shot(0));
    record_bootstrap_checkpoint(BootstrapCheckpoint::FeederAffinityReady);
    if !affinity_ready {
        warn!("KernDiff bootstrap feeder could not pin itself to CPU0");
        return;
    }
    let mut epoch = 0u64;
    let mut first_poll_complete = false;
    while PHASE.load(Ordering::Acquire) == PHASE_BOOTSTRAP {
        epoch = epoch.wrapping_add(1);
        ax_driver::kerndiff_fault::bootstrap_poll(epoch, ax_hal::time::monotonic_time_nanos());
        if !first_poll_complete {
            record_bootstrap_checkpoint(BootstrapCheckpoint::FeederFirstPollComplete);
            first_poll_complete = true;
        }
        ax_task::sleep(PERIOD);
    }
}

fn record_bootstrap_checkpoint(checkpoint: BootstrapCheckpoint) {
    let _ = ax_driver::kerndiff_fault::record_bootstrap_checkpoint(
        checkpoint,
        ax_hal::time::monotonic_time_nanos(),
    );
}

pub(super) fn record_bootstrap_followup_checkpoint(checkpoint: BootstrapFollowupCheckpoint) {
    let _ = ax_driver::kerndiff_fault::record_bootstrap_followup_checkpoint(
        checkpoint,
        ax_hal::time::monotonic_time_nanos(),
    );
}

pub(super) fn record_serial_init_checkpoint(checkpoint: SerialInitCheckpoint) {
    let _ = ax_driver::kerndiff_fault::record_serial_init_checkpoint(checkpoint, || {
        ax_hal::time::monotonic_time_nanos()
    });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_persisted_validation_fault() {
        assert_eq!(
            parse_validation_fault(Some("application-sigsegv")),
            Some(ValidationFault::ApplicationSigsegv)
        );
        assert_eq!(
            parse_validation_fault(Some("application-no-progress")),
            Some(ValidationFault::ApplicationNoProgress)
        );
        assert_eq!(
            parse_validation_fault(Some("kernel-panic")),
            Some(ValidationFault::KernelPanic)
        );
        assert_eq!(
            parse_validation_fault(Some("kernel-watchdog")),
            Some(ValidationFault::KernelWatchdog)
        );
        assert_eq!(
            parse_validation_fault(Some("pre-watchdog-hang")),
            Some(ValidationFault::PreWatchdogHang)
        );
        assert_eq!(parse_validation_fault(Some("unknown")), None);
    }

    #[test]
    fn selects_only_kernel_injection_stages() {
        assert_eq!(
            injection_stage(ValidationFault::PreWatchdogHang),
            Some(InjectionStage::BeforeWatchdogArm)
        );
        assert_eq!(
            injection_stage(ValidationFault::KernelPanic),
            Some(InjectionStage::AfterPerCpuHandoff)
        );
        assert_eq!(
            injection_stage(ValidationFault::KernelWatchdog),
            Some(InjectionStage::AfterPerCpuHandoff)
        );
        assert_eq!(injection_stage(ValidationFault::ApplicationSigsegv), None);
        assert_eq!(
            injection_stage(ValidationFault::ApplicationNoProgress),
            None
        );
    }

    #[test]
    fn normal_build_has_no_validation_injection() {
        assert_eq!(configured_validation_fault(), None);
    }
}
