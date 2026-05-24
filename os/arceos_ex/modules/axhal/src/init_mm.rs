//! InitMM lifecycle facts.

use crate::task;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct InitMmBounds {
    pub text_start: usize,
    pub text_end: usize,
    pub data_end: usize,
    pub kernel_end: usize,
}

// SAFETY: fixed boot-storage symbols make InitMM.Ready observable before the
// regular runtime owns allocator-backed address-space metadata.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.init_mm")]
pub static mut __arceos_ex_init_mm_bounds: InitMmBounds = InitMmBounds {
    text_start: 0,
    text_end: 0,
    data_end: 0,
    kernel_end: 0,
};

// SAFETY: see `__arceos_ex_init_mm_bounds`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.init_mm")]
pub static mut __arceos_ex_init_task_active_mm: usize = 0;

// SAFETY: linker symbols are the only source of the section boundaries that
// InitMM.Setup must publish.
unsafe extern "C" {
    safe static _stext: u8;
    safe static _etext: u8;
    safe static _edata: u8;
    safe static _end: u8;
}

// SAFETY: exported C ABI entry is required so naked startup assembly can drive
// InitMM.Setup at the model boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_init_mm_setup() -> usize {
    let bounds = InitMmBounds {
        text_start: &raw const _stext as usize,
        text_end: &raw const _etext as usize,
        data_end: &raw const _edata as usize,
        kernel_end: &raw const _end as usize,
    };
    if bounds.text_start == 0
        || bounds.text_end <= bounds.text_start
        || bounds.data_end < bounds.text_end
        || bounds.kernel_end < bounds.data_end
    {
        return 0;
    }

    // SAFETY: InitMM.Setup runs once in the single-root boot flow; no task or
    // address-space concurrency exists while these facts are published.
    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_init_mm_bounds, bounds);
        core::ptr::write_volatile(
            &raw mut __arceos_ex_init_task_active_mm,
            &raw const __arceos_ex_init_mm_bounds as usize,
        );
    }

    if task::init_task_addr() == 0 {
        return 0;
    }

    1
}
