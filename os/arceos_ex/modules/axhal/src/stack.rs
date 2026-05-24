const INIT_STACK_CANARY: usize = 0x57ac_6b0d_eca1_57ac;

unsafe extern "C" {
    safe static boot_stack: u8;
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.init_stack")]
pub static mut __arceos_ex_init_stack_canary_addr: usize = 0;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_init_stack_enable(stack_start: usize) -> usize {
    if stack_start == 0 || stack_start & (core::mem::size_of::<usize>() - 1) != 0 {
        return 0;
    }

    unsafe {
        let canary = stack_start as *mut usize;
        core::ptr::write_volatile(canary, INIT_STACK_CANARY);
        core::ptr::write_volatile(&raw mut __arceos_ex_init_stack_canary_addr, stack_start);
    }

    1
}

pub fn init_stack_enable() -> bool {
    let stack_start = &raw const boot_stack as usize;

    // SAFETY: `boot_stack` is a linker-provided symbol for the unique boot
    // stack storage. EntrySuccessorPhase owns InitStack.Enable in the primary
    // boot flow, so this wrapper preserves the same single-call boundary as the
    // exported C ABI event function.
    unsafe { __arceos_ex_init_stack_enable(stack_start) != 0 }
}

pub fn init_stack_canary_ready() -> bool {
    let canary_addr =
        unsafe { core::ptr::read_volatile(&raw const __arceos_ex_init_stack_canary_addr) };
    if canary_addr == 0 {
        return false;
    }

    unsafe { core::ptr::read_volatile(canary_addr as *const usize) == INIT_STACK_CANARY }
}
