//! Early CPU lifecycle facts for arceos_ex.

use crate::{boot, early_dtb};

// SAFETY: these symbols expose early CPU lifecycle facts to entry assembly and
// later checks while no safe global initializer exists for this boot boundary.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.cpu_id_map")]
pub static mut __arceos_ex_logical_cpu0_hartid: usize = 0;

// SAFETY: see `__arceos_ex_logical_cpu0_hartid`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot_cpu")]
pub static mut __arceos_ex_boot_cpu_present: usize = 0;

// SAFETY: see `__arceos_ex_logical_cpu0_hartid`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot_cpu")]
pub static mut __arceos_ex_boot_cpu_active: usize = 0;

// SAFETY: see `__arceos_ex_logical_cpu0_hartid`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot_cpu")]
pub static mut __arceos_ex_boot_cpu_online: usize = 0;

// SAFETY: exported C ABI entry is required so the naked startup assembly can
// drive CpuIdMap.Preset before Rust can own the call stack in a normal way.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_cpu_id_map_preset() -> usize {
    let hartid = boot::boot_cpu().hartid;
    if !early_dtb::platform_hart_exists(hartid) {
        return 0;
    }

    // SAFETY: CpuIdMap.Preset runs once in the boot root flow before CPU
    // concurrency exists; the exported scalar records logical CPU 0's hartid.
    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_logical_cpu0_hartid, hartid);
    }

    1
}

// SAFETY: exported C ABI entry is required so the naked startup assembly can
// drive BootCPU.Setup at the model boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_boot_cpu_setup() -> usize {
    let hartid = boot::boot_cpu().hartid;
    if !early_dtb::platform_hart_exists(hartid) {
        return 0;
    }

    // SAFETY: BootCPU.Setup runs once before SMP or interrupts are enabled, so
    // these boot CPU state facts cannot race with another writer.
    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_boot_cpu_present, 1);
        core::ptr::write_volatile(&raw mut __arceos_ex_boot_cpu_active, 1);
    }

    1
}

// SAFETY: exported C ABI entry is required so the naked startup assembly can
// drive BootCPU.Enable at the model boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_boot_cpu_enable() -> usize {
    // SAFETY: BootCPU.Enable is still in the single-root boot flow; the online
    // fact is published once after present/active have been established.
    unsafe {
        if core::ptr::read_volatile(&raw const __arceos_ex_boot_cpu_present) == 0
            || core::ptr::read_volatile(&raw const __arceos_ex_boot_cpu_active) == 0
        {
            return 0;
        }
        core::ptr::write_volatile(&raw mut __arceos_ex_boot_cpu_online, 1);
    }

    1
}
