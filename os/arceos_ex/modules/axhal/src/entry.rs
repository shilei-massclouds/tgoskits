use crate::checkpoint::Checkpoint;

const BOOT_STACK_SIZE: usize = 4096 * 16;

#[unsafe(link_section = ".bss.stack")]
static mut BOOT_STACK: [u8; BOOT_STACK_SIZE] = [0; BOOT_STACK_SIZE];

#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.boot")]
unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "
        la      sp, {boot_stack}
        li      t0, {boot_stack_size}
        add     sp, sp, t0
        tail    {entry}
        ",
        boot_stack = sym BOOT_STACK,
        boot_stack_size = const BOOT_STACK_SIZE,
        entry = sym entry_boot_args,
    )
}

extern "C" fn entry_boot_args(boot_hartid: usize, dtb_pa: usize) -> ! {
    crate::boot::init_boot_args(boot_hartid, dtb_pa);
    crate::checkpoint::hit(Checkpoint::BootArgsReady);
    loop {
        core::hint::spin_loop();
    }
}
