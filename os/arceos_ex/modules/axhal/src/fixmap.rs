use crate::raw_dtb;

const PAGE_SIZE: usize = 4096;
const FDT_SLOT_SIZE: usize = 2 * 1024 * 1024;
const FDT_SLOT_PAGE_COUNT: usize = FDT_SLOT_SIZE / PAGE_SIZE;
const FDT_SLOT_VADDR_END: usize = ax_config::plat::KERNEL_BASE_VADDR;
const FDT_SLOT_VADDR_START: usize = FDT_SLOT_VADDR_END - FDT_SLOT_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixMapSlot {
    pub virt_start: usize,
    pub virt_end: usize,
    pub phys_start: usize,
    pub phys_end: usize,
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.fixmap")]
pub static mut __arceos_ex_fixmap_fdt_virt_start: usize = 0;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.fixmap")]
pub static mut __arceos_ex_fixmap_fdt_virt_end: usize = 0;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.fixmap")]
pub static mut __arceos_ex_fixmap_fdt_phys_start: usize = 0;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.fixmap")]
pub static mut __arceos_ex_fixmap_fdt_phys_end: usize = 0;

pub fn fdt_slot() -> Option<FixMapSlot> {
    let virt_start =
        unsafe { core::ptr::read_volatile(&raw const __arceos_ex_fixmap_fdt_virt_start) };
    let virt_end = unsafe { core::ptr::read_volatile(&raw const __arceos_ex_fixmap_fdt_virt_end) };
    let phys_start =
        unsafe { core::ptr::read_volatile(&raw const __arceos_ex_fixmap_fdt_phys_start) };
    let phys_end = unsafe { core::ptr::read_volatile(&raw const __arceos_ex_fixmap_fdt_phys_end) };

    if virt_start == 0 || virt_end <= virt_start || phys_start == 0 || phys_end <= phys_start {
        return None;
    }

    Some(FixMapSlot {
        virt_start,
        virt_end,
        phys_start,
        phys_end,
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_fixmap_preset() -> usize {
    let Some(raw_dtb) = raw_dtb::raw_dtb() else {
        return 0;
    };

    if FDT_SLOT_VADDR_START == 0
        || FDT_SLOT_VADDR_START >= FDT_SLOT_VADDR_END
        || !is_aligned(FDT_SLOT_VADDR_START, PAGE_SIZE)
        || !is_aligned(FDT_SLOT_VADDR_END, PAGE_SIZE)
    {
        return 0;
    }

    let phys_start = align_down(raw_dtb.start, PAGE_SIZE);
    let Some(phys_end) = align_up(raw_dtb.end, PAGE_SIZE) else {
        return 0;
    };
    if phys_end <= phys_start {
        return 0;
    }

    let page_count = (phys_end - phys_start) / PAGE_SIZE;
    if page_count == 0 || page_count > FDT_SLOT_PAGE_COUNT {
        return 0;
    }

    unsafe {
        core::ptr::write_volatile(
            &raw mut __arceos_ex_fixmap_fdt_virt_start,
            FDT_SLOT_VADDR_START,
        );
        core::ptr::write_volatile(&raw mut __arceos_ex_fixmap_fdt_virt_end, FDT_SLOT_VADDR_END);
        core::ptr::write_volatile(&raw mut __arceos_ex_fixmap_fdt_phys_start, phys_start);
        core::ptr::write_volatile(&raw mut __arceos_ex_fixmap_fdt_phys_end, phys_end);
    }

    1
}

const fn is_aligned(value: usize, align: usize) -> bool {
    value & (align - 1) == 0
}

const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

const fn align_up(value: usize, align: usize) -> Option<usize> {
    let mask = align - 1;
    let Some(value) = value.checked_add(mask) else {
        return None;
    };
    Some(value & !mask)
}
