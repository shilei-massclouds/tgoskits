//! arceos_ex generic RISC-V64 SBI/FDT platform skeleton.
//!
//! The implementation must derive platform facts from the boot ABI and FDT.
//! Fixed QEMU values in `axconfig.toml` are temporary build-tool defaults and
//! must not be used as runtime truth for arceos_ex startup.

#![no_std]

#[macro_use]
extern crate ax_plat;

pub mod console {
    use ax_plat::console::ConsoleIf;

    struct ConsoleIfImpl;

    #[impl_plat_interface]
    impl ConsoleIf for ConsoleIfImpl {
        fn write_bytes(_bytes: &[u8]) {}

        fn read_bytes(_bytes: &mut [u8]) -> usize {
            0
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
            sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::NoReason);
            loop {
                core::hint::spin_loop();
            }
        }

        fn cpu_num() -> usize {
            1
        }
    }
}
