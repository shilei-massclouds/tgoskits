use crate::checkpoint::Checkpoint;

const BOOT_STACK_SIZE: usize = 4096 * 16;
const PT_SIZE_ON_STACK: usize = 36 * core::mem::size_of::<usize>();
const SSTATUS_FS_VS_MASK: usize = (0b11 << 13) | (0b11 << 9);

core::arch::global_asm!(
    r#"
    .pushsection .text.boot, "ax"
    .balign 4
    .globl __arceos_ex_early_event_entry
__arceos_ex_early_event_entry:
1:
    j       1b
    .popsection
"#
);

unsafe extern "C" {
    fn __arceos_ex_early_event_entry();
    fn trap_vector_base();
}

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

        .option push
        .option norelax
        la      t0, {boot_hartid}
        ld      t1, 0(t0)
        la      t0, {boot_cpu_hartid}
        sd      t1, 0(t0)
        .option pop
        li      a0, {checkpoint_boot_cpu_prepared}
        call    {early_checkpoint}

        .option push
        .option norelax
        la      tp, {init_task}
        .option pop
        li      a0, {checkpoint_init_task_prepared}
        call    {early_checkpoint}

        la      sp, boot_stack_top
        li      t0, {pt_size_on_stack}
        sub     sp, sp, t0
        li      a0, {checkpoint_init_stack_prepared}
        call    {early_checkpoint}

        .option push
        .option norelax
        la      t0, {early_event_entry}
        .option pop
        csrw    stvec, t0
        li      a0, {checkpoint_event_stream_prepared}
        call    {early_checkpoint}

        call    {trampoline_vm_setup}
        beqz    a0, 5f
        li      a0, {checkpoint_trampoline_vm_ready}
        call    {early_checkpoint}

        call    {raw_dtb_preset_setup}
        beqz    a0, 5f
        li      a0, {checkpoint_raw_dtb_ready}
        call    {early_checkpoint}

        call    {fixmap_preset}
        beqz    a0, 5f
        li      a0, {checkpoint_fixmap_ready}
        call    {early_checkpoint}

        call    {early_vm_setup}
        beqz    a0, 5f
        li      a0, {checkpoint_early_vm_ready}
        call    {early_checkpoint}

        sfence.vma
        .option push
        .option norelax
        la      t0, {trampoline_pg_dir}
        .option pop
        srli    t0, t0, 12
        li      t1, {satp_mode_sv39}
        or      t0, t0, t1
        csrw    satp, t0
        sfence.vma

        la      t0, 6f
        li      t1, {phys_virt_offset}
        add     t0, t0, t1
        jr      t0
6:
        .option push
        .option norelax
        la      t0, {early_pg_dir}
        .option pop
        li      t1, {phys_virt_offset}
        sub     t0, t0, t1
        srli    t0, t0, 12
        li      t1, {satp_mode_sv39}
        or      t0, t0, t1
        csrw    satp, t0
        sfence.vma

        .option push
        .option norelax
        la      gp, __global_pointer$
        .option pop
        li      a0, {checkpoint_vm_ready}
        call    {early_checkpoint}

        la      t0, {formal_event_entry}
        csrw    stvec, t0
        csrw    sscratch, zero
        li      a0, {checkpoint_event_stream_online}
        call    {early_checkpoint}

        .option push
        .option norelax
        la      tp, {init_task}
        .option pop
        li      a0, {checkpoint_init_task_online}
        call    {early_checkpoint}

        la      sp, boot_stack_top
        li      t0, {pt_size_on_stack}
        sub     sp, sp, t0
        li      a0, {checkpoint_init_stack_ready}
        call    {early_checkpoint}

        li      a0, {checkpoint_soc_prepared}
        call    {early_checkpoint}

        li      a0, {checkpoint_entry_prelude_ready}
        call    {early_checkpoint}

        li      a0, {checkpoint_entry_prelude_destroyed}
        call    {early_checkpoint}

        la      a0, boot_stack
        call    {init_stack_enable}
        beqz    a0, 5f
        li      a0, {checkpoint_init_stack_online}
        call    {early_checkpoint}

        call    {early_dtb_preset}
        beqz    a0, 5f
        li      a0, {checkpoint_platform_cpu_info_online}
        call    {early_checkpoint}
        li      a0, {checkpoint_physical_memory_online}
        call    {early_checkpoint}
        li      a0, {checkpoint_early_dtb_prepared}
        call    {early_checkpoint}

        call    {cpu_id_map_preset}
        beqz    a0, 5f
        li      a0, {checkpoint_cpu_id_map_ready}
        call    {early_checkpoint}

        call    {interrupt_stream_setup}
        beqz    a0, 5f
        li      a0, {checkpoint_interrupt_stream_ready}
        call    {early_checkpoint}

        call    {boot_cpu_setup}
        beqz    a0, 5f
        li      a0, {checkpoint_boot_cpu_ready}
        call    {early_checkpoint}

        call    {boot_cpu_enable}
        beqz    a0, 5f
        li      a0, {checkpoint_boot_cpu_online}
        call    {early_checkpoint}

        call    {printk_buffer_preset}
        beqz    a0, 5f
        li      a0, {checkpoint_printk_buffer_prepared}
        call    {early_checkpoint}

        call    {early_dtb_setup}
        beqz    a0, 5f
        li      a0, {checkpoint_kernel_cmdline_ready}
        call    {early_checkpoint}
        li      a0, {checkpoint_memblock_prepared}
        call    {early_checkpoint}
        li      a0, {checkpoint_early_dtb_ready}
        call    {early_checkpoint}

4:
        j       4b
5:
        j       5b
        ",
        boot_hartid = sym crate::boot::__arceos_ex_boot_hartid,
        dtb_pa = sym crate::boot::__arceos_ex_dtb_pa,
        boot_cpu_hartid = sym crate::boot::__arceos_ex_boot_cpu_hartid,
        init_task = sym crate::task::__arceos_ex_init_task,
        early_event_entry = sym __arceos_ex_early_event_entry,
        formal_event_entry = sym trap_vector_base,
        trampoline_vm_setup = sym crate::vm::__arceos_ex_trampoline_vm_setup,
        raw_dtb_preset_setup = sym crate::raw_dtb::__arceos_ex_raw_dtb_preset_setup,
        fixmap_preset = sym crate::fixmap::__arceos_ex_fixmap_preset,
        early_vm_setup = sym crate::vm::__arceos_ex_early_vm_setup,
        init_stack_enable = sym crate::stack::__arceos_ex_init_stack_enable,
        early_dtb_preset = sym crate::early_dtb::__arceos_ex_early_dtb_preset,
        cpu_id_map_preset = sym crate::cpu::__arceos_ex_cpu_id_map_preset,
        interrupt_stream_setup = sym crate::interrupt::__arceos_ex_interrupt_stream_setup,
        boot_cpu_setup = sym crate::cpu::__arceos_ex_boot_cpu_setup,
        boot_cpu_enable = sym crate::cpu::__arceos_ex_boot_cpu_enable,
        printk_buffer_preset = sym crate::printk::__arceos_ex_printk_buffer_preset,
        early_dtb_setup = sym crate::early_dtb::__arceos_ex_early_dtb_setup,
        trampoline_pg_dir = sym crate::vm::__arceos_ex_trampoline_pg_dir,
        early_pg_dir = sym crate::vm::__arceos_ex_early_pg_dir,
        early_checkpoint = sym early_checkpoint,
        checkpoint_boot_args_ready = const Checkpoint::BootArgsReady as usize,
        checkpoint_interrupt_stream_prepared = const Checkpoint::InterruptStreamPrepared as usize,
        checkpoint_kernel_image_prepared = const Checkpoint::KernelImagePrepared as usize,
        checkpoint_root_stream_prepared = const Checkpoint::RootStreamPrepared as usize,
        checkpoint_kernel_image_ready = const Checkpoint::KernelImageReady as usize,
        checkpoint_boot_cpu_prepared = const Checkpoint::BootCpuPrepared as usize,
        checkpoint_init_task_prepared = const Checkpoint::InitTaskPrepared as usize,
        checkpoint_init_stack_prepared = const Checkpoint::InitStackPrepared as usize,
        checkpoint_event_stream_prepared = const Checkpoint::EventStreamPrepared as usize,
        checkpoint_trampoline_vm_ready = const Checkpoint::TrampolineVmReady as usize,
        checkpoint_raw_dtb_ready = const Checkpoint::RawDtbReady as usize,
        checkpoint_fixmap_ready = const Checkpoint::FixMapReady as usize,
        checkpoint_early_vm_ready = const Checkpoint::EarlyVmReady as usize,
        checkpoint_vm_ready = const Checkpoint::VmReady as usize,
        checkpoint_event_stream_online = const Checkpoint::EventStreamOnline as usize,
        checkpoint_init_task_online = const Checkpoint::InitTaskOnline as usize,
        checkpoint_init_stack_ready = const Checkpoint::InitStackReady as usize,
        checkpoint_soc_prepared = const Checkpoint::SocPrepared as usize,
        checkpoint_entry_prelude_ready = const Checkpoint::EntryPreludeReady as usize,
        checkpoint_entry_prelude_destroyed = const Checkpoint::EntryPreludeDestroyed as usize,
        checkpoint_init_stack_online = const Checkpoint::InitStackOnline as usize,
        checkpoint_platform_cpu_info_online = const Checkpoint::PlatformCpuInfoOnline as usize,
        checkpoint_physical_memory_online = const Checkpoint::PhysicalMemoryOnline as usize,
        checkpoint_early_dtb_prepared = const Checkpoint::EarlyDtbPrepared as usize,
        checkpoint_cpu_id_map_ready = const Checkpoint::CpuIdMapReady as usize,
        checkpoint_interrupt_stream_ready = const Checkpoint::InterruptStreamReady as usize,
        checkpoint_boot_cpu_ready = const Checkpoint::BootCpuReady as usize,
        checkpoint_boot_cpu_online = const Checkpoint::BootCpuOnline as usize,
        checkpoint_printk_buffer_prepared = const Checkpoint::PrintkBufferPrepared as usize,
        checkpoint_kernel_cmdline_ready = const Checkpoint::KernelCmdlineReady as usize,
        checkpoint_memblock_prepared = const Checkpoint::MemBlockPrepared as usize,
        checkpoint_early_dtb_ready = const Checkpoint::EarlyDtbReady as usize,
        satp_mode_sv39 = const crate::vm::RISCV_SATP_MODE_SV39,
        phys_virt_offset = const crate::vm::PHYS_VIRT_OFFSET,
        pt_size_on_stack = const PT_SIZE_ON_STACK,
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
