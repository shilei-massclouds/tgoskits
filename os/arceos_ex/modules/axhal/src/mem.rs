//! Physical memory interfaces for arceos_ex.

pub use ax_memory_addr::{PAGE_SIZE_4K, PhysAddr, VirtAddr, pa, va};
pub use ax_plat::mem::{
    MemRegionFlags, PhysMemRegion, kernel_aspace, mmio_ranges, phys_ram_ranges, phys_to_virt,
    reserved_phys_ram_ranges, total_ram_size, virt_to_phys,
};

