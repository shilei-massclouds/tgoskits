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
const ESB_ENABLE: u32 = 0x02;

pub const WATCHDOG_STAGE_SECONDS: u64 = 30;
pub const WATCHDOG_TIMEOUT_SECONDS: u64 = WATCHDOG_STAGE_SECONDS * 2;
pub const LIVENESS_STALE_SECONDS: u64 = 15;
pub const DIAGNOSTIC_PAGE_BYTES: usize = 4096;
const TIMER_TICKS: u32 = (WATCHDOG_STAGE_SECONDS as u32) << 9;
const MAX_CPUS: usize = 64;
const DIAGNOSTIC_MAGIC: u32 = 0x4b44_5744;
const DIAGNOSTIC_VERSION: u32 = 1;

static WATCHDOG_MMIO: AtomicUsize = AtomicUsize::new(0);
static WATCHDOG_CONFIG_ADDRESS: AtomicU32 = AtomicU32::new(0);
static PVPANIC_MMIO: AtomicUsize = AtomicUsize::new(0);
static WATCHDOG_ARMED: AtomicBool = AtomicBool::new(false);
static PVPANIC_NOTIFIED: AtomicBool = AtomicBool::new(false);
static FORCED_STALE_MASK: AtomicU64 = AtomicU64::new(0);

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
        }
    }
}

static DIAGNOSTIC: DiagnosticPage = DiagnosticPage::new();

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

        // 1 kHz, WDT output enabled, timer-one interrupt disabled.
        let old_config = endpoint.read(ESB_CONFIG_OFFSET);
        endpoint.write(ESB_CONFIG_OFFSET, (old_config & 0xffff_0000) | 0x0003);
        let old_lock = endpoint.read(ESB_LOCK_OFFSET);
        endpoint.write(ESB_LOCK_OFFSET, old_lock & !0xff);
        let address = endpoint.address();
        let config_address = 0x8000_0000
            | (u32::from(address.bus()) << 16)
            | (u32::from(address.device()) << 11)
            | (u32::from(address.function()) << 8)
            | u32::from(ESB_LOCK_OFFSET & !3);
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
    if base == 0 || online_mask == 0 {
        return false;
    }
    DIAGNOSTIC.boot_epoch.store(boot_epoch, Ordering::Release);
    DIAGNOSTIC.online_mask.store(online_mask, Ordering::Release);
    DIAGNOSTIC.stale_mask.store(0, Ordering::Release);
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
fn enable_watchdog() -> bool {
    use core::arch::asm;

    let config_address = WATCHDOG_CONFIG_ADDRESS.load(Ordering::Acquire);
    if config_address == 0 {
        return false;
    }
    let mut value: u32;
    unsafe {
        asm!("out dx, eax", in("dx") 0xcf8u16, in("eax") config_address, options(nostack));
        asm!("in eax, dx", in("dx") 0xcfcu16, out("eax") value, options(nostack));
        value = (value & !0xff) | ESB_ENABLE;
        asm!("out dx, eax", in("dx") 0xcf8u16, in("eax") config_address, options(nostack));
        asm!("out dx, eax", in("dx") 0xcfcu16, in("eax") value, options(nostack));
    }
    true
}

#[cfg(not(target_arch = "x86_64"))]
fn enable_watchdog() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programs_two_thirty_second_stages_with_required_unlocks() {
        let operations = watchdog_programming_sequence();
        assert_eq!(TIMER_TICKS, 30 << 9);
        assert_eq!(
            operations[0..3],
            [
                ProgrammingOperation::Write16(ESB_RELOAD_OFFSET, ESB_UNLOCK1),
                ProgrammingOperation::Write16(ESB_RELOAD_OFFSET, ESB_UNLOCK2),
                ProgrammingOperation::Write32(ESB_TIMER1_OFFSET, 30 << 9),
            ]
        );
        assert!(operations.contains(&ProgrammingOperation::Write32(ESB_TIMER2_OFFSET, 30 << 9)));
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
        assert_eq!(DIAGNOSTIC.version, 1);
    }

    #[test]
    fn pvpanic_writes_panicked_event_byte() {
        let mut event = 0u8;
        unsafe { write_pvpanic_panicked((&mut event as *mut u8) as usize) };
        assert_eq!(event, 1);
    }
}
