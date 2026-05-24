//! arceos_ex hardware abstraction layer skeleton.
//!
//! This crate is intentionally minimal while the arceos-ex overlay workspace is
//! being wired into xtask. Startup implementation must be filled according to
//! the componentized kernel specification before it is used as a real HAL.

#![no_std]

pub use ax_cpu::asm;

#[cfg(all(target_os = "none", target_arch = "riscv64", feature = "defplat"))]
extern crate ax_plat_riscv64_generic;

pub mod boot;
pub mod cmdline;
pub mod console {
    pub use ax_plat::console::{read_bytes, write_bytes, write_text_bytes};
}

pub mod checkpoint;
pub mod cpu;
pub mod early_dtb;
pub mod early_ioremap;
pub mod earlycon;
#[cfg(target_arch = "riscv64")]
mod entry;
pub mod fdt;
pub mod fixmap;
pub mod init_mm;
pub mod interrupt;
pub mod kernel_param;
pub mod mem;
pub mod memblock;
pub mod printk;
pub mod raw_dtb;
pub mod sbi;
pub mod stack;
pub mod task;
pub mod vm;

pub mod power {
    pub use ax_plat::power::system_off;
}

pub mod time {
    pub use ax_plat::time::{
        Duration, MICROS_PER_SEC, MILLIS_PER_SEC, NANOS_PER_MICROS, NANOS_PER_MILLIS,
        NANOS_PER_SEC, TimeValue, busy_wait, busy_wait_until, current_ticks, epochoffset_nanos,
        monotonic_time, monotonic_time_nanos, nanos_to_ticks, ticks_to_nanos, wall_time,
        wall_time_nanos,
    };
}

pub fn cpu_num() -> usize {
    1
}
