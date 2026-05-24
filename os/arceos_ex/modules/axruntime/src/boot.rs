use ax_hal::{checkpoint, checkpoint::Checkpoint};

pub fn entry_successor_phase_setup(_cpu_id: usize, _arg: usize) -> bool {
    checkpoint!(Checkpoint::EntryPreludeDestroyed);

    if !ax_hal::stack::init_stack_enable() {
        return false;
    }
    checkpoint!(Checkpoint::InitStackOnline);

    if !call_event(ax_hal::early_dtb::__arceos_ex_early_dtb_preset) {
        return false;
    }
    checkpoint!(Checkpoint::PlatformCpuInfoOnline);
    checkpoint!(Checkpoint::PhysicalMemoryOnline);
    checkpoint!(Checkpoint::EarlyDtbPrepared);

    if !call_event(ax_hal::cpu::__arceos_ex_cpu_id_map_preset) {
        return false;
    }
    checkpoint!(Checkpoint::CpuIdMapReady);

    if !call_event(ax_hal::interrupt::__arceos_ex_interrupt_stream_setup) {
        return false;
    }
    checkpoint!(Checkpoint::InterruptStreamReady);

    if !call_event(ax_hal::cpu::__arceos_ex_boot_cpu_setup) {
        return false;
    }
    checkpoint!(Checkpoint::BootCpuReady);

    if !call_event(ax_hal::cpu::__arceos_ex_boot_cpu_enable) {
        return false;
    }
    checkpoint!(Checkpoint::BootCpuOnline);

    if !call_event(ax_hal::printk::__arceos_ex_printk_buffer_preset) {
        return false;
    }
    checkpoint!(Checkpoint::PrintkBufferPrepared);

    if !call_event(ax_hal::early_dtb::__arceos_ex_early_dtb_setup) {
        return false;
    }
    checkpoint!(Checkpoint::KernelCmdlineReady);
    checkpoint!(Checkpoint::MemBlockPrepared);
    checkpoint!(Checkpoint::EarlyDtbReady);

    if !call_event(ax_hal::init_mm::__arceos_ex_init_mm_setup) {
        return false;
    }
    checkpoint!(Checkpoint::InitMmReady);

    if !call_event(ax_hal::early_ioremap::__arceos_ex_early_ioremap_setup) {
        return false;
    }
    checkpoint!(Checkpoint::EarlyIoremapReady);

    if !call_event(ax_hal::sbi::__arceos_ex_sbi_setup) {
        return false;
    }
    checkpoint!(Checkpoint::SbiReady);

    if !call_event(ax_hal::kernel_param::__arceos_ex_kernel_param_setup) {
        return false;
    }
    checkpoint!(Checkpoint::EarlyConOnline);
    checkpoint!(Checkpoint::KernelParamReady);

    if !call_event(ax_hal::memblock::__arceos_ex_memblock_setup) {
        return false;
    }
    checkpoint!(Checkpoint::MemBlockReady);

    if !call_event(ax_hal::vm::__arceos_ex_vm_enable) {
        return false;
    }
    checkpoint!(Checkpoint::SwapperVmOnline);
    checkpoint!(Checkpoint::VmOnline);
    checkpoint!(Checkpoint::EarlyVmDestroyed);

    if !call_event(ax_hal::memblock::__arceos_ex_memblock_enable) {
        return false;
    }
    checkpoint!(Checkpoint::MemBlockOnline);

    if !call_event(ax_hal::early_dtb::__arceos_ex_early_dtb_cleanup) {
        return false;
    }
    checkpoint!(Checkpoint::EarlyDtbDestroyed);

    checkpoint!(Checkpoint::EntrySuccessorReady);
    true
}

fn call_event(event: unsafe extern "C" fn() -> usize) -> bool {
    // SAFETY: each exported function is a single-object startup lifecycle event.
    // The runtime phase driver calls them once and in model order.
    unsafe { event() != 0 }
}

#[cfg(feature = "alloc")]
pub fn init_allocator() {
    const PAGE_SIZE: usize = 4096;

    let mut initialized = false;
    for index in 0..ax_hal::memblock::usable_range_count() {
        let Some(range) = ax_hal::memblock::usable_range(index) else {
            ax_hal::power::system_off()
        };
        let Some(start) = align_up(range.start, PAGE_SIZE) else {
            ax_hal::power::system_off()
        };
        let end = align_down(range.start.saturating_add(range.size), PAGE_SIZE);
        if end <= start {
            continue;
        }

        let Some(start_vaddr) = start.checked_add(ax_hal::vm::PHYS_VIRT_OFFSET) else {
            ax_hal::power::system_off()
        };
        let size = end - start;
        if !initialized {
            if ax_alloc::global_init(start_vaddr, size).is_err() {
                ax_hal::power::system_off()
            }
            initialized = true;
        } else if ax_alloc::global_add_memory(start_vaddr, size).is_err() {
            ax_hal::power::system_off()
        }
    }

    if !initialized {
        ax_hal::power::system_off()
    }
}

#[cfg(feature = "alloc")]
const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

#[cfg(feature = "alloc")]
const fn align_up(value: usize, align: usize) -> Option<usize> {
    let mask = align - 1;
    let Some(value) = value.checked_add(mask) else {
        return None;
    };
    Some(value & !mask)
}
