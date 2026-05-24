//! Early kernel parameter dispatch facts.

use crate::earlycon;

// SAFETY: fixed boot-storage symbol used to publish KernelParam.Ready before
// the regular parameter subsystem exists.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.kernel_param")]
pub static mut __arceos_ex_kernel_param_ready: usize = 0;

// SAFETY: exported C ABI entry is required so naked startup assembly can drive
// KernelParam.Setup at the model boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_kernel_param_setup() -> usize {
    if !earlycon::preset_from_cmdline() {
        return 0;
    }
    if !earlycon::setup_from_sbi() {
        return 0;
    }
    if !earlycon::enable_with_printk_buffer() {
        return 0;
    }

    // SAFETY: KernelParam.Setup runs once in the exclusive boot flow after it
    // has dispatched the required earlycon=sbi handler chain.
    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_kernel_param_ready, 1);
    }

    1
}
