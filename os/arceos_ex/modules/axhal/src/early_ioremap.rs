//! Early ioremap lifecycle facts.

use crate::fixmap;

// SAFETY: fixed boot-storage symbol used to publish EarlyIoremap.Ready before
// the full virtual memory service is available.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.early_ioremap")]
pub static mut __arceos_ex_early_ioremap_ready: usize = 0;

// SAFETY: exported C ABI entry is required so naked startup assembly can drive
// EarlyIoremap.Setup at the model boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_early_ioremap_setup() -> usize {
    if fixmap::fdt_slot().is_none() {
        return 0;
    }

    // SAFETY: EarlyIoremap.Setup runs once before concurrent mapping users
    // exist, so the readiness fact has a single writer.
    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_early_ioremap_ready, 1);
    }

    1
}
