use crate::checkpoint::Checkpoint;

const BOOT_STACK_SIZE: usize = 4096 * 16;
const SSTATUS_FS_VS_MASK: usize = (0b11 << 13) | (0b11 << 9);

#[used]
#[unsafe(link_section = ".bss.stack")]
static mut BOOT_STACK: [u8; BOOT_STACK_SIZE] = [0; BOOT_STACK_SIZE];

#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.boot.entry")]
unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "
        .option push
        .option norelax
        la      t0, {boot_hartid}
        sd      a0, 0(t0)
        la      t0, {dtb_pa}
        sd      a1, 0(t0)
        .option pop
        li      a0, {checkpoint_boot_args_ready}
        call    {early_checkpoint}

        csrw    sie, zero
        csrw    sip, zero
        li      a0, {checkpoint_interrupt_stream_prepared}
        call    {early_checkpoint}

        .option push
        .option norelax
        la      gp, __global_pointer$
        .option pop
        li      a0, {checkpoint_kernel_image_prepared}
        call    {early_checkpoint}

        li      t0, {sstatus_fs_vs_mask}
        csrc    sstatus, t0
        li      a0, {checkpoint_root_stream_prepared}
        call    {early_checkpoint}

        la      t0, _sbss
        la      t1, _ebss
2:
        bgeu    t0, t1, 3f
        sd      zero, 0(t0)
        addi    t0, t0, 8
        j       2b
3:
        li      a0, {checkpoint_kernel_image_ready}
        call    {early_checkpoint}

4:
        j       4b
        ",
        boot_hartid = sym crate::boot::__arceos_ex_boot_hartid,
        dtb_pa = sym crate::boot::__arceos_ex_dtb_pa,
        early_checkpoint = sym early_checkpoint,
        checkpoint_boot_args_ready = const Checkpoint::BootArgsReady as usize,
        checkpoint_interrupt_stream_prepared = const Checkpoint::InterruptStreamPrepared as usize,
        checkpoint_kernel_image_prepared = const Checkpoint::KernelImagePrepared as usize,
        checkpoint_root_stream_prepared = const Checkpoint::RootStreamPrepared as usize,
        checkpoint_kernel_image_ready = const Checkpoint::KernelImageReady as usize,
        sstatus_fs_vs_mask = const SSTATUS_FS_VS_MASK,
    )
}

#[cfg(all(target_arch = "riscv64", feature = "checkpoint-sbi-char"))]
#[unsafe(naked)]
#[unsafe(link_section = ".text.boot")]
unsafe extern "C" fn early_checkpoint() {
    core::arch::naked_asm!(
        "
        li      a7, 1
        ecall
        ret
        "
    )
}

#[cfg(not(all(target_arch = "riscv64", feature = "checkpoint-sbi-char")))]
#[unsafe(naked)]
#[unsafe(link_section = ".text.boot")]
unsafe extern "C" fn early_checkpoint() {
    core::arch::naked_asm!("ret")
}
