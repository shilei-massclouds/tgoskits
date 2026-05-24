//! Early interrupt stream lifecycle.

// SAFETY: this symbol is a fixed boot-storage ABI name used to publish
// InterruptStream.Ready before the regular runtime can initialize globals.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.interrupt_stream")]
pub static mut __arceos_ex_interrupt_stream_ready: usize = 0;

#[cfg(target_arch = "riscv64")]
// SAFETY: exported C ABI entry is required so the naked startup assembly can
// drive InterruptStream.Setup at the model boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_interrupt_stream_setup() -> usize {
    use core::arch::asm;

    // SAFETY: this is the RISC-V privileged instruction boundary for
    // InterruptStream.Setup; it defensively closes supervisor interrupt paths.
    unsafe {
        asm!("csrw sie, zero", "csrw sip, zero", "csrci sstatus, 0x2");
        core::ptr::write_volatile(&raw mut __arceos_ex_interrupt_stream_ready, 1);
    }

    1
}
