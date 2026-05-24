//! Early MemBlock facts.

use crate::{early_dtb, raw_dtb};

const MAX_MEMBLOCK_RANGES: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct MemBlockRange {
    pub start: usize,
    pub size: usize,
}

// SAFETY: these symbols expose MemBlock.Preset facts from fixed boot storage
// before allocator-backed Rust storage is available.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.memblock")]
pub static mut __arceos_ex_memblock_candidate_range_count: usize = 0;

// SAFETY: see `__arceos_ex_memblock_candidate_range_count`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.memblock")]
pub static mut __arceos_ex_memblock_candidate_ranges: [MemBlockRange; MAX_MEMBLOCK_RANGES] =
    [MemBlockRange { start: 0, size: 0 }; MAX_MEMBLOCK_RANGES];

pub fn preset_from_physical_memory() -> bool {
    if raw_dtb::raw_dtb().is_none() {
        return false;
    }

    let count = early_dtb::physical_memory_range_count();
    if count == 0 || count > MAX_MEMBLOCK_RANGES {
        return false;
    }

    for index in 0..count {
        let Some(range) = early_dtb::physical_memory_range(index) else {
            return false;
        };

        // SAFETY: MemBlock.Preset runs once before the allocator or concurrent
        // boot flows exist; candidate ranges are copied from PhysicalMemory.
        unsafe {
            core::ptr::write_volatile(
                (&raw mut __arceos_ex_memblock_candidate_ranges)
                    .cast::<MemBlockRange>()
                    .add(index),
                MemBlockRange {
                    start: range.start,
                    size: range.size,
                },
            );
        }
    }

    // SAFETY: see the per-range write above; this publishes the copied count.
    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_memblock_candidate_range_count, count);
    }

    true
}

pub fn candidate_range_count() -> usize {
    // SAFETY: this reads the boot-time fact published by MemBlock.Preset.
    unsafe { core::ptr::read_volatile(&raw const __arceos_ex_memblock_candidate_range_count) }
}
