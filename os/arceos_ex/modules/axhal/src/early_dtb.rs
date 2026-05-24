use core::slice;

use crate::{
    boot, cmdline,
    fdt::{Fdt, Node},
    fixmap, memblock, raw_dtb,
};

const MAX_PHYSICAL_MEMORY_RANGES: usize = 4;
const MAX_PLATFORM_HARTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalMemoryRange {
    pub start: usize,
    pub size: usize,
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.early_dtb")]
pub static mut __arceos_ex_platform_hart_count: usize = 0;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.early_dtb")]
pub static mut __arceos_ex_platform_harts: [usize; MAX_PLATFORM_HARTS] = [0; MAX_PLATFORM_HARTS];

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.early_dtb")]
pub static mut __arceos_ex_physical_memory_range_count: usize = 0;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.early_dtb")]
pub static mut __arceos_ex_physical_memory_ranges: [PhysicalMemoryRange;
    MAX_PHYSICAL_MEMORY_RANGES] =
    [PhysicalMemoryRange { start: 0, size: 0 }; MAX_PHYSICAL_MEMORY_RANGES];

// SAFETY: scalar lifecycle fact is written once when EntrySuccessorPhase
// completes EarlyDtb.Cleanup.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.early_dtb")]
pub static mut __arceos_ex_early_dtb_destroyed: usize = 0;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_early_dtb_preset() -> usize {
    let Some(dtb) = mapped_dtb() else {
        return 0;
    };
    let Some(fdt) = Fdt::from_bytes(dtb) else {
        return 0;
    };

    if !publish_platform_cpu_info(&fdt, boot::boot_args().boot_hartid) {
        return 0;
    }
    if !publish_physical_memory(&fdt) {
        return 0;
    }

    1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_early_dtb_setup() -> usize {
    let Some(dtb) = mapped_dtb() else {
        return 0;
    };
    let Some(fdt) = Fdt::from_bytes(dtb) else {
        return 0;
    };

    let bootargs = fdt
        .find_node("/chosen")
        .and_then(|node| node.property("bootargs"));
    if !cmdline::publish_kernel_cmdline(bootargs) {
        return 0;
    }
    if !memblock::preset_from_physical_memory() {
        return 0;
    }

    1
}

// SAFETY: exported C ABI entry is required so naked startup assembly can drive
// EarlyDtb.Cleanup at the model boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_early_dtb_cleanup() -> usize {
    if !memblock::resize_allowed() {
        return 0;
    }

    // SAFETY: EarlyDtb.Cleanup runs once after all required early DTB facts have
    // been consumed by MemBlock, KernelCmdline and platform facts.
    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_early_dtb_destroyed, 1);
    }

    1
}

fn mapped_dtb() -> Option<&'static [u8]> {
    let raw_dtb = raw_dtb::raw_dtb()?;
    let fdt_slot = fixmap::fdt_slot()?;
    let raw_offset = raw_dtb.start.checked_sub(fdt_slot.phys_start)?;
    let dtb_vaddr = fdt_slot.virt_start.checked_add(raw_offset)?;
    let dtb_vaddr_end = dtb_vaddr.checked_add(raw_dtb.total_size)?;
    if dtb_vaddr < fdt_slot.virt_start || dtb_vaddr_end > fdt_slot.virt_end {
        return None;
    }

    // SAFETY: RawDtb.Ready and FixMap.Ready proved that this DTB physical range
    // is fully covered by the FDT fixmap slot for EarlyDtb parsing.
    Some(unsafe { slice::from_raw_parts(dtb_vaddr as *const u8, raw_dtb.total_size) })
}

fn publish_platform_cpu_info(fdt: &Fdt<'_>, boot_hartid: usize) -> bool {
    let Some(address_cells) = cpu_address_cells(fdt) else {
        return false;
    };
    let mut hart_count = 0;
    let mut boot_hart_found = false;

    for node in fdt.nodes() {
        if !is_cpu_node(&node) {
            continue;
        }
        let Some(hartid) = cpu_reg_hartid(&node, address_cells) else {
            return false;
        };
        if hart_count >= MAX_PLATFORM_HARTS {
            return false;
        }
        if hartid == boot_hartid {
            boot_hart_found = true;
        }

        unsafe {
            core::ptr::write_volatile(
                (&raw mut __arceos_ex_platform_harts)
                    .cast::<usize>()
                    .add(hart_count),
                hartid,
            );
        }
        hart_count += 1;
    }

    if hart_count == 0 || !boot_hart_found {
        return false;
    }

    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_platform_hart_count, hart_count);
    }

    true
}

fn publish_physical_memory(fdt: &Fdt<'_>) -> bool {
    let Some((address_cells, size_cells)) = root_address_size_cells(fdt) else {
        return false;
    };
    let mut range_count = 0;
    for node in fdt.nodes() {
        if !is_memory_node(&node) {
            continue;
        }
        let Some(reg) = node.property("reg") else {
            return false;
        };
        let mut raw = reg;
        let Some(tuple_cells) = address_cells.checked_add(size_cells) else {
            return false;
        };
        let Some(tuple_bytes) = tuple_cells.checked_mul(4) else {
            return false;
        };
        if raw.is_empty() || raw.len() % tuple_bytes != 0 {
            return false;
        }

        while !raw.is_empty() {
            let Some(start) = take_cell(&mut raw, address_cells) else {
                return false;
            };
            let Some(size) = take_cell(&mut raw, size_cells) else {
                return false;
            };
            if size == 0 {
                continue;
            }
            if range_count >= MAX_PHYSICAL_MEMORY_RANGES {
                return false;
            }
            let Some(end) = start.checked_add(size) else {
                return false;
            };
            if end <= start {
                return false;
            }

            unsafe {
                core::ptr::write_volatile(
                    (&raw mut __arceos_ex_physical_memory_ranges)
                        .cast::<PhysicalMemoryRange>()
                        .add(range_count),
                    PhysicalMemoryRange { start, size },
                );
            }
            range_count += 1;
        }
    }

    if range_count == 0 {
        return false;
    }

    unsafe {
        core::ptr::write_volatile(
            &raw mut __arceos_ex_physical_memory_range_count,
            range_count,
        );
    }

    true
}

fn is_cpu_node(node: &Node<'_>) -> bool {
    if node.name == "cpus" || !node.name.starts_with("cpu") {
        return false;
    }

    node.prop_str_eq("device_type", b"cpu")
}

fn cpu_address_cells(fdt: &Fdt<'_>) -> Option<usize> {
    let cpus = fdt.find_node("/cpus")?;
    let value = read_property_u32(&cpus, "#address-cells")?;
    usize::try_from(value)
        .ok()
        .filter(|cells| *cells == 1 || *cells == 2)
}

fn cpu_reg_hartid(node: &Node<'_>, address_cells: usize) -> Option<usize> {
    let mut raw = node.property("reg")?;
    let byte_len = address_cells.checked_mul(4)?;
    if raw.len() < byte_len {
        return None;
    }

    take_cell(&mut raw, address_cells)
}

fn root_address_size_cells(fdt: &Fdt<'_>) -> Option<(usize, usize)> {
    let root = fdt.find_node("/")?;
    let address_cells = usize::try_from(read_property_u32(&root, "#address-cells")?).ok()?;
    let size_cells = usize::try_from(read_property_u32(&root, "#size-cells")?).ok()?;

    if !(address_cells == 1 || address_cells == 2) || !(size_cells == 1 || size_cells == 2) {
        return None;
    }

    Some((address_cells, size_cells))
}

fn is_memory_node(node: &Node<'_>) -> bool {
    node.name.starts_with("memory") && node.prop_str_eq("device_type", b"memory")
}

fn read_property_u32(node: &Node<'_>, name: &str) -> Option<u32> {
    let raw = node.property(name)?;
    if raw.len() != 4 {
        return None;
    }

    Some(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn take_cell(raw: &mut &[u8], cells: usize) -> Option<usize> {
    let bytes = cells.checked_mul(4)?;
    if raw.len() < bytes {
        return None;
    }

    let mut value = 0usize;
    for cell in raw[..bytes].chunks_exact(4) {
        let cell = u32::from_be_bytes([cell[0], cell[1], cell[2], cell[3]]) as usize;
        value = value.checked_shl(32)?.checked_add(cell)?;
    }

    *raw = &raw[bytes..];
    Some(value)
}

pub fn platform_hart_count() -> usize {
    unsafe { core::ptr::read_volatile(&raw const __arceos_ex_platform_hart_count) }
}

pub fn physical_memory_range_count() -> usize {
    unsafe { core::ptr::read_volatile(&raw const __arceos_ex_physical_memory_range_count) }
}

pub fn platform_hart_exists(hartid: usize) -> bool {
    let count = platform_hart_count();
    for index in 0..count {
        // SAFETY: PlatformCpuInfo.Online published exactly `count` valid hartid
        // entries during EarlyDtb.Preset.
        let current = unsafe {
            core::ptr::read_volatile(
                (&raw const __arceos_ex_platform_harts)
                    .cast::<usize>()
                    .add(index),
            )
        };
        if current == hartid {
            return true;
        }
    }

    false
}

pub fn physical_memory_range(index: usize) -> Option<PhysicalMemoryRange> {
    if index >= physical_memory_range_count() {
        return None;
    }

    // SAFETY: PhysicalMemory.Online published this entry before MemBlock.Preset
    // can copy it as a candidate range.
    Some(unsafe {
        core::ptr::read_volatile(
            (&raw const __arceos_ex_physical_memory_ranges)
                .cast::<PhysicalMemoryRange>()
                .add(index),
        )
    })
}
