//! arceos_ex generic RISC-V64 SBI/FDT platform skeleton.
//!
//! The implementation must derive platform facts from the boot ABI and FDT.
//! Fixed QEMU values in `axconfig.toml` are temporary build-tool defaults and
//! must not be used as runtime truth for arceos_ex startup.

#![no_std]

#[macro_use]
extern crate ax_plat;

pub mod config {
    //! Platform configuration module.
    ax_config_macros::include_configs!(path_env = "AX_CONFIG_PATH", fallback = "axconfig.toml");
    assert_str_eq!(
        PACKAGE,
        env!("CARGO_PKG_NAME"),
        "`PACKAGE` field in the configuration does not match the Package name. Please check your \
         configuration file."
    );
}

mod sbi {
    const EID_LEGACY_CONSOLE_PUTCHAR: usize = 1;
    const EID_SRST: usize = 0x5352_5354;
    const FID_SYSTEM_RESET: usize = 0;
    const RESET_TYPE_SHUTDOWN: usize = 0;
    const RESET_REASON_NONE: usize = 0;

    pub fn legacy_console_putchar(byte: u8) {
        let _ = sbi_call_1(EID_LEGACY_CONSOLE_PUTCHAR, 0, byte as usize);
    }

    pub fn system_shutdown() -> ! {
        let _ = sbi_call_2(
            EID_SRST,
            FID_SYSTEM_RESET,
            RESET_TYPE_SHUTDOWN,
            RESET_REASON_NONE,
        );
        loop {
            core::hint::spin_loop();
        }
    }

    #[inline(always)]
    fn sbi_call_1(eid: usize, fid: usize, arg0: usize) -> (usize, usize) {
        let error: usize;
        let value: usize;

        // SAFETY: this is the RISC-V SBI ecall ABI boundary for legacy console
        // output; a0 carries one byte, a6/a7 carry fid/eid.
        unsafe {
            core::arch::asm!(
                "ecall",
                inlateout("a0") arg0 => error,
                lateout("a1") value,
                in("a6") fid,
                in("a7") eid,
                options(nostack)
            );
        }

        (error, value)
    }

    #[inline(always)]
    fn sbi_call_2(eid: usize, fid: usize, arg0: usize, arg1: usize) -> (usize, usize) {
        let error: usize;
        let value: usize;

        // SAFETY: this is the RISC-V SBI ecall ABI boundary for platform
        // shutdown; a0/a1 carry reset type and reason, a6/a7 carry fid/eid.
        unsafe {
            core::arch::asm!(
                "ecall",
                inlateout("a0") arg0 => error,
                inlateout("a1") arg1 => value,
                in("a6") fid,
                in("a7") eid,
                options(nostack)
            );
        }

        (error, value)
    }
}

pub mod console {
    use ax_plat::console::ConsoleIf;
    #[cfg(feature = "irq")]
    use ax_plat::console::ConsoleIrqEvent;

    struct ConsoleIfImpl;

    #[impl_plat_interface]
    impl ConsoleIf for ConsoleIfImpl {
        fn write_bytes(bytes: &[u8]) {
            for byte in bytes {
                crate::sbi::legacy_console_putchar(*byte);
            }
        }

        fn read_bytes(_bytes: &mut [u8]) -> usize {
            0
        }

        #[cfg(feature = "irq")]
        fn irq_num() -> Option<usize> {
            None
        }

        #[cfg(feature = "irq")]
        fn set_input_irq_enabled(_enabled: bool) {}

        #[cfg(feature = "irq")]
        fn handle_irq() -> ConsoleIrqEvent {
            ConsoleIrqEvent::empty()
        }
    }
}

pub mod mem {
    use ax_plat::mem::{MemIf, PhysAddr, RawRange, VirtAddr};

    struct MemIfImpl;

    #[impl_plat_interface]
    impl MemIf for MemIfImpl {
        fn phys_ram_ranges() -> &'static [RawRange] {
            &[]
        }

        fn reserved_phys_ram_ranges() -> &'static [RawRange] {
            &[]
        }

        fn mmio_ranges() -> &'static [RawRange] {
            &[]
        }

        fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
            VirtAddr::from_usize(paddr.as_usize())
        }

        fn virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
            PhysAddr::from_usize(vaddr.as_usize())
        }

        fn kernel_aspace() -> (VirtAddr, usize) {
            (VirtAddr::from_usize(0), 0)
        }
    }
}

pub mod power {
    use ax_plat::power::PowerIf;

    struct PowerIfImpl;

    #[impl_plat_interface]
    impl PowerIf for PowerIfImpl {
        #[cfg(feature = "smp")]
        fn cpu_boot(_cpu_id: usize, _stack_top_paddr: usize) {}

        fn system_off() -> ! {
            crate::sbi::system_shutdown()
        }

        fn cpu_num() -> usize {
            1
        }
    }
}

pub mod time {
    use ax_plat::time::{NANOS_PER_SEC, TimeIf};

    const NANOS_PER_TICK: u64 = NANOS_PER_SEC / crate::config::devices::TIMER_FREQUENCY as u64;

    struct TimeIfImpl;

    #[impl_plat_interface]
    impl TimeIf for TimeIfImpl {
        fn current_ticks() -> u64 {
            let ticks: usize;

            // SAFETY: `rdtime` reads the RISC-V time CSR and has no memory side
            // effects. It is the minimal timer source required by ax-std.
            unsafe {
                core::arch::asm!("rdtime {ticks}", ticks = out(reg) ticks, options(nomem, nostack));
            }

            ticks as u64
        }

        fn ticks_to_nanos(ticks: u64) -> u64 {
            ticks.saturating_mul(NANOS_PER_TICK)
        }

        fn nanos_to_ticks(nanos: u64) -> u64 {
            nanos / NANOS_PER_TICK
        }

        fn epochoffset_nanos() -> u64 {
            0
        }

        #[cfg(feature = "irq")]
        fn irq_num() -> usize {
            crate::config::devices::TIMER_IRQ
        }

        #[cfg(feature = "irq")]
        fn set_oneshot_timer(_deadline_ns: u64) {}
    }
}
