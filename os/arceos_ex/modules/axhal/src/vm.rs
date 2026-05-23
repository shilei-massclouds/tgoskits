use crate::fixmap;

const SV39_ENTRY_COUNT: usize = 512;
const SV39_PAGE_SIZE: usize = 4096;
const SV39_PMD_SIZE: usize = 2 * 1024 * 1024;
const PTE_V: usize = 1 << 0;
const PTE_R: usize = 1 << 1;
const PTE_W: usize = 1 << 2;
const PTE_X: usize = 1 << 3;
const PTE_G: usize = 1 << 5;
const PTE_A: usize = 1 << 6;
const PTE_D: usize = 1 << 7;
const PTE_TABLE: usize = PTE_V;
const PTE_KERNEL_LEAF: usize = PTE_V | PTE_R | PTE_W | PTE_X | PTE_G | PTE_A | PTE_D;

#[repr(C, align(4096))]
pub struct Sv39PageTable {
    entries: [usize; SV39_ENTRY_COUNT],
}

impl Sv39PageTable {
    pub const fn zero() -> Self {
        Self {
            entries: [0; SV39_ENTRY_COUNT],
        }
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.boot_page_table")]
pub static mut __arceos_ex_trampoline_pg_dir: Sv39PageTable = Sv39PageTable::zero();

#[unsafe(link_section = ".data.boot_page_table")]
static mut TRAMPOLINE_PHYS_PMD: Sv39PageTable = Sv39PageTable::zero();

#[unsafe(link_section = ".data.boot_page_table")]
static mut TRAMPOLINE_VIRT_PMD: Sv39PageTable = Sv39PageTable::zero();

#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.boot_page_table")]
pub static mut __arceos_ex_early_pg_dir: Sv39PageTable = Sv39PageTable::zero();

#[unsafe(link_section = ".data.boot_page_table")]
static mut EARLY_KERNEL_IMAGE_PMD: Sv39PageTable = Sv39PageTable::zero();

#[unsafe(link_section = ".data.boot_page_table")]
static mut EARLY_FIXMAP_PTE: Sv39PageTable = Sv39PageTable::zero();

unsafe extern "C" {
    static _skernel: u8;
    static _ekernel: u8;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_trampoline_vm_setup() -> usize {
    let current_kernel_start = &raw const _skernel as usize;
    let kernel_pa = ax_config::plat::KERNEL_BASE_PADDR;
    let kernel_va = ax_config::plat::KERNEL_BASE_VADDR;
    if current_kernel_start != kernel_pa
        || !is_aligned(kernel_pa, SV39_PMD_SIZE)
        || !is_aligned(kernel_va, SV39_PMD_SIZE)
    {
        return 0;
    }

    // This function is called before satp is enabled, so PC-relative symbol
    // addresses below are the current physical load addresses.
    let root = &raw mut __arceos_ex_trampoline_pg_dir;
    let phys_pmd = &raw mut TRAMPOLINE_PHYS_PMD;
    let virt_pmd = &raw mut TRAMPOLINE_VIRT_PMD;

    unsafe {
        zero_table(root);
        zero_table(phys_pmd);
        zero_table(virt_pmd);

        write_pte(root, vpn2(kernel_pa), table_pte(phys_pmd as usize));
        write_pte(phys_pmd, vpn1(kernel_pa), leaf_pte(kernel_pa));

        write_pte(root, vpn2(kernel_va), table_pte(virt_pmd as usize));
        write_pte(virt_pmd, vpn1(kernel_va), leaf_pte(kernel_pa));
    }

    1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_early_vm_setup() -> usize {
    let kernel_start_pa = &raw const _skernel as usize;
    let kernel_end_pa = &raw const _ekernel as usize;
    let kernel_base_pa = ax_config::plat::KERNEL_BASE_PADDR;
    let kernel_base_va = ax_config::plat::KERNEL_BASE_VADDR;
    let Some(fdt_slot) = fixmap::fdt_slot() else {
        return 0;
    };

    if kernel_start_pa != kernel_base_pa
        || kernel_end_pa <= kernel_start_pa
        || !is_aligned(kernel_base_pa, SV39_PMD_SIZE)
        || !is_aligned(kernel_base_va, SV39_PMD_SIZE)
        || vpn2(fdt_slot.virt_start) != vpn2(kernel_base_va)
        || vpn2(fdt_slot.virt_end - 1) != vpn2(kernel_base_va)
        || vpn1(fdt_slot.virt_start) == vpn1(kernel_base_va)
        || !is_aligned(fdt_slot.virt_start, SV39_PAGE_SIZE)
        || !is_aligned(fdt_slot.phys_start, SV39_PAGE_SIZE)
    {
        return 0;
    }

    let Some(kernel_map_end_pa) = align_up(kernel_end_pa, SV39_PMD_SIZE) else {
        return 0;
    };
    if kernel_map_end_pa <= kernel_base_pa {
        return 0;
    }

    let Some(fdt_map_size) = fdt_slot.phys_end.checked_sub(fdt_slot.phys_start) else {
        return 0;
    };
    let Some(fdt_slot_size) = fdt_slot.virt_end.checked_sub(fdt_slot.virt_start) else {
        return 0;
    };
    if fdt_map_size == 0
        || fdt_map_size > fdt_slot_size
        || !is_aligned(fdt_map_size, SV39_PAGE_SIZE)
    {
        return 0;
    }

    let root = &raw mut __arceos_ex_early_pg_dir;
    let kernel_pmd = &raw mut EARLY_KERNEL_IMAGE_PMD;
    let fixmap_pte = &raw mut EARLY_FIXMAP_PTE;

    unsafe {
        zero_table(root);
        zero_table(kernel_pmd);
        zero_table(fixmap_pte);

        write_pte(root, vpn2(kernel_base_va), table_pte(kernel_pmd as usize));
        if !map_pmd_range(
            kernel_pmd,
            kernel_base_va,
            kernel_base_pa,
            kernel_map_end_pa - kernel_base_pa,
        ) {
            return 0;
        }

        write_pte(
            kernel_pmd,
            vpn1(fdt_slot.virt_start),
            table_pte(fixmap_pte as usize),
        );
        if !map_page_range(
            fixmap_pte,
            fdt_slot.virt_start,
            fdt_slot.phys_start,
            fdt_map_size,
        ) {
            return 0;
        }
    }

    1
}

const fn is_aligned(value: usize, align: usize) -> bool {
    value & (align - 1) == 0
}

const fn vpn2(vaddr: usize) -> usize {
    (vaddr >> 30) & 0x1ff
}

const fn vpn1(vaddr: usize) -> usize {
    (vaddr >> 21) & 0x1ff
}

const fn vpn0(vaddr: usize) -> usize {
    (vaddr >> 12) & 0x1ff
}

const fn pte_addr(paddr: usize) -> usize {
    (paddr / SV39_PAGE_SIZE) << 10
}

const fn table_pte(paddr: usize) -> usize {
    pte_addr(paddr) | PTE_TABLE
}

const fn leaf_pte(paddr: usize) -> usize {
    pte_addr(paddr) | PTE_KERNEL_LEAF
}

unsafe fn zero_table(table: *mut Sv39PageTable) {
    let entries = unsafe { core::ptr::addr_of_mut!((*table).entries).cast::<usize>() };
    for i in 0..SV39_ENTRY_COUNT {
        unsafe { core::ptr::write_volatile(entries.add(i), 0) };
    }
}

unsafe fn write_pte(table: *mut Sv39PageTable, index: usize, value: usize) {
    let entries = unsafe { core::ptr::addr_of_mut!((*table).entries).cast::<usize>() };
    unsafe { core::ptr::write_volatile(entries.add(index), value) };
}

unsafe fn map_pmd_range(
    pmd: *mut Sv39PageTable,
    virt_start: usize,
    phys_start: usize,
    size: usize,
) -> bool {
    if size == 0
        || !is_aligned(virt_start, SV39_PMD_SIZE)
        || !is_aligned(phys_start, SV39_PMD_SIZE)
        || !is_aligned(size, SV39_PMD_SIZE)
    {
        return false;
    }

    let mut offset = 0;
    while offset < size {
        let Some(virt) = virt_start.checked_add(offset) else {
            return false;
        };
        let Some(phys) = phys_start.checked_add(offset) else {
            return false;
        };
        if vpn2(virt) != vpn2(virt_start) {
            return false;
        }

        unsafe { write_pte(pmd, vpn1(virt), leaf_pte(phys)) };
        offset += SV39_PMD_SIZE;
    }

    true
}

unsafe fn map_page_range(
    pte: *mut Sv39PageTable,
    virt_start: usize,
    phys_start: usize,
    size: usize,
) -> bool {
    if size == 0
        || !is_aligned(virt_start, SV39_PAGE_SIZE)
        || !is_aligned(phys_start, SV39_PAGE_SIZE)
        || !is_aligned(size, SV39_PAGE_SIZE)
    {
        return false;
    }

    let mut offset = 0;
    while offset < size {
        let Some(virt) = virt_start.checked_add(offset) else {
            return false;
        };
        let Some(phys) = phys_start.checked_add(offset) else {
            return false;
        };
        if vpn1(virt) != vpn1(virt_start) {
            return false;
        }

        unsafe { write_pte(pte, vpn0(virt), leaf_pte(phys)) };
        offset += SV39_PAGE_SIZE;
    }

    true
}

const fn align_up(value: usize, align: usize) -> Option<usize> {
    let mask = align - 1;
    let Some(value) = value.checked_add(mask) else {
        return None;
    };
    Some(value & !mask)
}
