use crate::boot;

const BOOT_ARG_UNSET: usize = usize::MAX;
const DTB_HEADER_MAGIC: u32 = 0xd00d_feed;
const DTB_HEADER_SIZE: usize = 40;
const DTB_MAGIC_OFFSET: usize = 0;
const DTB_TOTAL_SIZE_OFFSET: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawDtb {
    pub start: usize,
    pub end: usize,
    pub magic: u32,
    pub total_size: usize,
}

impl RawDtb {
    pub const fn new(start: usize, total_size: usize, magic: u32) -> Self {
        Self {
            start,
            end: start + total_size,
            magic,
            total_size,
        }
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.raw_dtb")]
pub static mut __arceos_ex_raw_dtb_start: usize = 0;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.raw_dtb")]
pub static mut __arceos_ex_raw_dtb_end: usize = 0;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.raw_dtb")]
pub static mut __arceos_ex_raw_dtb_magic: u32 = 0;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.raw_dtb")]
pub static mut __arceos_ex_raw_dtb_total_size: usize = 0;

pub fn raw_dtb() -> Option<RawDtb> {
    let start = unsafe { core::ptr::read_volatile(&raw const __arceos_ex_raw_dtb_start) };
    let end = unsafe { core::ptr::read_volatile(&raw const __arceos_ex_raw_dtb_end) };
    let magic = unsafe { core::ptr::read_volatile(&raw const __arceos_ex_raw_dtb_magic) };
    let total_size = unsafe { core::ptr::read_volatile(&raw const __arceos_ex_raw_dtb_total_size) };

    if start == 0 || end <= start || magic != DTB_HEADER_MAGIC || end - start != total_size {
        return None;
    }

    Some(RawDtb {
        start,
        end,
        magic,
        total_size,
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_raw_dtb_preset_setup() -> usize {
    let dtb_pa = boot::boot_args().dtb_pa;
    if dtb_pa == 0 || dtb_pa == BOOT_ARG_UNSET {
        return 0;
    }

    let Some(header_end) = dtb_pa.checked_add(DTB_HEADER_SIZE) else {
        return 0;
    };
    if header_end <= dtb_pa {
        return 0;
    }

    let magic = unsafe { read_dtb_header_field(dtb_pa, DTB_MAGIC_OFFSET) };
    if magic != DTB_HEADER_MAGIC {
        return 0;
    }

    let total_size = unsafe { read_dtb_header_field(dtb_pa, DTB_TOTAL_SIZE_OFFSET) } as usize;
    if total_size < DTB_HEADER_SIZE {
        return 0;
    }

    let Some(end) = dtb_pa.checked_add(total_size) else {
        return 0;
    };
    if end <= dtb_pa {
        return 0;
    }

    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_raw_dtb_start, dtb_pa);
        core::ptr::write_volatile(&raw mut __arceos_ex_raw_dtb_end, end);
        core::ptr::write_volatile(&raw mut __arceos_ex_raw_dtb_magic, magic);
        core::ptr::write_volatile(&raw mut __arceos_ex_raw_dtb_total_size, total_size);
    }

    1
}

unsafe fn read_dtb_header_field(dtb_pa: usize, offset: usize) -> u32 {
    let field = unsafe { core::ptr::read_unaligned((dtb_pa + offset) as *const u32) };
    u32::from_be(field)
}
