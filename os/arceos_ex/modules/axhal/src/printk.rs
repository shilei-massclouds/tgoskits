//! Early printk buffer lifecycle facts.

// SAFETY: this symbol is a fixed boot-storage ABI name used to publish
// PrintkBuffer.Prepared before the regular runtime initializes logging.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.printk_buffer")]
pub static mut __arceos_ex_printk_buffer_prepared: usize = 0;

// SAFETY: exported C ABI entry is required so the naked startup assembly can
// drive PrintkBuffer.Preset at the model boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_printk_buffer_preset() -> usize {
    // SAFETY: PrintkBuffer.Preset runs before interrupt and task concurrency,
    // so this static boot fact has a single writer.
    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_printk_buffer_prepared, 1);
    }

    1
}

pub fn is_prepared() -> bool {
    // SAFETY: this reads the boot-time fact published by PrintkBuffer.Preset.
    unsafe { core::ptr::read_volatile(&raw const __arceos_ex_printk_buffer_prepared) != 0 }
}
