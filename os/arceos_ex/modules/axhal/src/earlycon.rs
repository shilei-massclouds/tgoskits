//! Early console lifecycle facts.

use crate::{cmdline, printk, sbi};

// SAFETY: fixed boot-storage symbols expose EarlyCon state facts before the
// regular console subsystem exists.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.earlycon")]
pub static mut __arceos_ex_earlycon_prepared: usize = 0;

// SAFETY: see `__arceos_ex_earlycon_prepared`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.earlycon")]
pub static mut __arceos_ex_earlycon_ready: usize = 0;

// SAFETY: see `__arceos_ex_earlycon_prepared`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.earlycon")]
pub static mut __arceos_ex_earlycon_online: usize = 0;

pub fn preset_from_cmdline() -> bool {
    if !cmdline::kernel_cmdline_has_arg(b"earlycon=sbi") {
        return false;
    }

    // SAFETY: KernelParam.Setup drives EarlyCon.Preset once in the single-root
    // boot flow.
    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_earlycon_prepared, 1);
    }

    true
}

pub fn setup_from_sbi() -> bool {
    if !sbi::legacy_console_available() && !sbi::dbcn_available() {
        return false;
    }

    // SAFETY: EarlyCon.Setup runs once after SBI.Ready and before console
    // concurrency exists.
    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_earlycon_ready, 1);
    }

    true
}

pub fn enable_with_printk_buffer() -> bool {
    if !printk::is_prepared() {
        return false;
    }

    // SAFETY: EarlyCon.Enable runs once while still in the exclusive boot flow.
    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_earlycon_online, 1);
    }

    true
}
