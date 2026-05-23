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

unsafe extern "C" {
    static _skernel: u8;
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

const fn is_aligned(value: usize, align: usize) -> bool {
    value & (align - 1) == 0
}

const fn vpn2(vaddr: usize) -> usize {
    (vaddr >> 30) & 0x1ff
}

const fn vpn1(vaddr: usize) -> usize {
    (vaddr >> 21) & 0x1ff
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
