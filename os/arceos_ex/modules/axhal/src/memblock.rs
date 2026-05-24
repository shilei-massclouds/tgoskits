//! Early MemBlock facts.

use crate::{early_dtb, raw_dtb, vm};

const MAX_MEMBLOCK_RANGES: usize = 4;
const PAGE_SIZE: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct MemBlockRange {
    pub start: usize,
    pub size: usize,
}

impl MemBlockRange {
    pub const fn end(self) -> Option<usize> {
        self.start.checked_add(self.size)
    }
}

// SAFETY: linker symbols are the only source of the loaded kernel image
// physical range once the code is running at its virtual address.
unsafe extern "C" {
    safe static _skernel: u8;
    safe static _ekernel: u8;
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

// SAFETY: these symbols expose MemBlock.Ready facts after setup_bootmem-style
// constraints have been applied to the candidate ranges.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.memblock")]
pub static mut __arceos_ex_memblock_reserved_range_count: usize = 0;

// SAFETY: see `__arceos_ex_memblock_reserved_range_count`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.memblock")]
pub static mut __arceos_ex_memblock_reserved_ranges: [MemBlockRange; MAX_MEMBLOCK_RANGES] =
    [MemBlockRange { start: 0, size: 0 }; MAX_MEMBLOCK_RANGES];

// SAFETY: see `__arceos_ex_memblock_reserved_range_count`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.memblock")]
pub static mut __arceos_ex_memblock_usable_range_count: usize = 0;

// SAFETY: see `__arceos_ex_memblock_reserved_range_count`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.memblock")]
pub static mut __arceos_ex_memblock_usable_ranges: [MemBlockRange; MAX_MEMBLOCK_RANGES * 2] =
    [MemBlockRange { start: 0, size: 0 }; MAX_MEMBLOCK_RANGES * 2];

// SAFETY: scalar lifecycle facts are written once by the exclusive boot flow.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.memblock")]
pub static mut __arceos_ex_memblock_ready: usize = 0;

// SAFETY: see `__arceos_ex_memblock_ready`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.memblock")]
pub static mut __arceos_ex_memblock_resize_allowed: usize = 0;

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

// SAFETY: exported C ABI entry is required so naked startup assembly can drive
// MemBlock.Setup at the model boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_memblock_setup() -> usize {
    if candidate_range_count() == 0 || raw_dtb::raw_dtb().is_none() {
        return 0;
    }

    let Some(kernel_start) = kernel_virt_to_phys(&raw const _skernel as usize) else {
        return 0;
    };
    let Some(kernel_end) = kernel_virt_to_phys(&raw const _ekernel as usize) else {
        return 0;
    };
    if kernel_end <= kernel_start {
        return 0;
    }

    let Some(raw_dtb) = raw_dtb::raw_dtb() else {
        return 0;
    };
    let mut reserved = [MemBlockRange { start: 0, size: 0 }; MAX_MEMBLOCK_RANGES];
    let mut reserved_count = 0;
    if !push_reserved_range(&mut reserved, &mut reserved_count, kernel_start, kernel_end) {
        return 0;
    }
    if !push_reserved_range(
        &mut reserved,
        &mut reserved_count,
        raw_dtb.start,
        raw_dtb.end,
    ) {
        return 0;
    }
    sort_ranges(&mut reserved, reserved_count);

    for index in 0..reserved_count {
        let range = reserved[index];
        if !range_is_inside_candidate(range) {
            return 0;
        }
        // SAFETY: MemBlock.Setup is the only writer of reserved range facts.
        unsafe {
            core::ptr::write_volatile(
                (&raw mut __arceos_ex_memblock_reserved_ranges)
                    .cast::<MemBlockRange>()
                    .add(index),
                range,
            );
        }
    }

    let Some(usable_count) = publish_usable_ranges(&reserved, reserved_count) else {
        return 0;
    };
    if usable_count == 0 {
        return 0;
    }

    // SAFETY: MemBlock.Setup runs once before allocator concurrency exists and
    // publishes plain setup facts for later VM construction.
    unsafe {
        core::ptr::write_volatile(
            &raw mut __arceos_ex_memblock_reserved_range_count,
            reserved_count,
        );
        core::ptr::write_volatile(&raw mut __arceos_ex_memblock_ready, 1);
    }

    1
}

// SAFETY: exported C ABI entry is required so naked startup assembly can drive
// MemBlock.Enable after SwapperVm has become the current address space.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_memblock_enable() -> usize {
    if !is_ready() || !vm::is_online() || !vm::swapper_vm_is_online() {
        return 0;
    }

    // SAFETY: MemBlock.Enable runs once in the exclusive boot flow; it only
    // publishes that metadata resize is allowed from this point.
    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_memblock_resize_allowed, 1);
    }

    1
}

pub fn candidate_range_count() -> usize {
    // SAFETY: this reads the boot-time fact published by MemBlock.Preset.
    unsafe { core::ptr::read_volatile(&raw const __arceos_ex_memblock_candidate_range_count) }
}

pub fn candidate_range(index: usize) -> Option<MemBlockRange> {
    if index >= candidate_range_count() {
        return None;
    }

    // SAFETY: MemBlock.Preset published this entry before SwapperVm.Setup can
    // consume it as a linear-map input.
    Some(unsafe {
        core::ptr::read_volatile(
            (&raw const __arceos_ex_memblock_candidate_ranges)
                .cast::<MemBlockRange>()
                .add(index),
        )
    })
}

pub fn is_ready() -> bool {
    // SAFETY: this reads the boot-time fact published by MemBlock.Setup.
    unsafe { core::ptr::read_volatile(&raw const __arceos_ex_memblock_ready) != 0 }
}

pub fn resize_allowed() -> bool {
    // SAFETY: this reads the boot-time fact published by MemBlock.Enable.
    unsafe { core::ptr::read_volatile(&raw const __arceos_ex_memblock_resize_allowed) != 0 }
}

fn kernel_virt_to_phys(vaddr: usize) -> Option<usize> {
    vaddr.checked_sub(vm::PHYS_VIRT_OFFSET)
}

fn push_reserved_range(
    reserved: &mut [MemBlockRange; MAX_MEMBLOCK_RANGES],
    count: &mut usize,
    start: usize,
    end: usize,
) -> bool {
    let start = align_down(start, PAGE_SIZE);
    let Some(end) = align_up(end, PAGE_SIZE) else {
        return false;
    };
    if end <= start || *count >= MAX_MEMBLOCK_RANGES {
        return false;
    }
    reserved[*count] = MemBlockRange {
        start,
        size: end - start,
    };
    *count += 1;
    true
}

fn publish_usable_ranges(
    reserved: &[MemBlockRange; MAX_MEMBLOCK_RANGES],
    reserved_count: usize,
) -> Option<usize> {
    let mut usable_count = 0;
    for candidate_index in 0..candidate_range_count() {
        let candidate = candidate_range(candidate_index)?;
        let start = align_up(candidate.start, PAGE_SIZE)?;
        let end = align_down(candidate.end()?, PAGE_SIZE);
        if end <= start {
            continue;
        }

        let mut cursor = start;
        for reserved in reserved.iter().take(reserved_count).copied() {
            let reserved_start = reserved.start.max(start);
            let reserved_end = reserved.end()?.min(end);
            if reserved_end <= cursor || reserved_start >= end {
                continue;
            }
            if reserved_start > cursor {
                publish_usable_range(&mut usable_count, cursor, reserved_start)?;
            }
            cursor = cursor.max(reserved_end);
        }
        if cursor < end {
            publish_usable_range(&mut usable_count, cursor, end)?;
        }
    }

    // SAFETY: MemBlock.Setup is the only writer of usable range facts.
    unsafe {
        core::ptr::write_volatile(
            &raw mut __arceos_ex_memblock_usable_range_count,
            usable_count,
        );
    }
    Some(usable_count)
}

fn publish_usable_range(count: &mut usize, start: usize, end: usize) -> Option<()> {
    if end <= start || *count >= MAX_MEMBLOCK_RANGES * 2 {
        return None;
    }

    // SAFETY: MemBlock.Setup is the only writer of usable range facts.
    unsafe {
        core::ptr::write_volatile(
            (&raw mut __arceos_ex_memblock_usable_ranges)
                .cast::<MemBlockRange>()
                .add(*count),
            MemBlockRange {
                start,
                size: end - start,
            },
        );
    }
    *count += 1;
    Some(())
}

fn range_is_inside_candidate(range: MemBlockRange) -> bool {
    let Some(range_end) = range.end() else {
        return false;
    };
    for index in 0..candidate_range_count() {
        let Some(candidate) = candidate_range(index) else {
            return false;
        };
        let Some(candidate_end) = candidate.end() else {
            return false;
        };
        if range.start >= candidate.start && range_end <= candidate_end {
            return true;
        }
    }
    false
}

fn sort_ranges(ranges: &mut [MemBlockRange; MAX_MEMBLOCK_RANGES], count: usize) {
    let mut i = 0;
    while i < count {
        let mut j = i + 1;
        while j < count {
            if ranges[j].start < ranges[i].start {
                ranges.swap(i, j);
            }
            j += 1;
        }
        i += 1;
    }
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
