//! Early kernel command line storage.

const MAX_KERNEL_CMDLINE_LEN: usize = 1024;

// SAFETY: these symbols are fixed boot-storage ABI names/sections used to make
// KernelCmdline.Ready observable before allocator-backed storage exists.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.kernel_cmdline")]
pub static mut __arceos_ex_kernel_cmdline_len: usize = 0;

// SAFETY: see `__arceos_ex_kernel_cmdline_len`.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.kernel_cmdline")]
pub static mut __arceos_ex_kernel_cmdline: [u8; MAX_KERNEL_CMDLINE_LEN] =
    [0; MAX_KERNEL_CMDLINE_LEN];

pub fn publish_kernel_cmdline(raw: Option<&[u8]>) -> bool {
    let bytes = raw
        .and_then(|raw| raw.split(|byte| *byte == 0).next())
        .unwrap_or(&[]);
    if bytes.len() > MAX_KERNEL_CMDLINE_LEN {
        return false;
    }

    // SAFETY: entry successor still runs in the single-root boot flow, so this
    // static command line storage has no concurrent reader or writer yet.
    unsafe {
        let dst = (&raw mut __arceos_ex_kernel_cmdline).cast::<u8>();
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
        if bytes.len() < MAX_KERNEL_CMDLINE_LEN {
            core::ptr::write(dst.add(bytes.len()), 0);
        }
        core::ptr::write_volatile(&raw mut __arceos_ex_kernel_cmdline_len, bytes.len());
    }

    true
}

pub fn kernel_cmdline_len() -> usize {
    // SAFETY: the length is published with volatile writes in the boot path and
    // is a plain scalar checkpoint fact for later readers.
    unsafe { core::ptr::read_volatile(&raw const __arceos_ex_kernel_cmdline_len) }
}

pub fn kernel_cmdline_has_arg(expected: &[u8]) -> bool {
    let len = kernel_cmdline_len();
    if expected.is_empty() || len < expected.len() || len > MAX_KERNEL_CMDLINE_LEN {
        return false;
    }

    let mut arg_start = 0;
    while arg_start < len {
        while arg_start < len
            && read_cmdline_byte(arg_start).is_some_and(|byte| byte.is_ascii_whitespace())
        {
            arg_start += 1;
        }
        let mut arg_end = arg_start;
        while arg_end < len
            && read_cmdline_byte(arg_end).is_some_and(|byte| !byte.is_ascii_whitespace())
        {
            arg_end += 1;
        }
        if arg_end > arg_start && cmdline_arg_eq(arg_start, arg_end, expected) {
            return true;
        }
        arg_start = arg_end.saturating_add(1);
    }

    false
}

fn cmdline_arg_eq(start: usize, end: usize, expected: &[u8]) -> bool {
    if end - start != expected.len() {
        return false;
    }

    for (offset, expected) in expected.iter().copied().enumerate() {
        if read_cmdline_byte(start + offset) != Some(expected) {
            return false;
        }
    }

    true
}

fn read_cmdline_byte(index: usize) -> Option<u8> {
    if index >= MAX_KERNEL_CMDLINE_LEN {
        return None;
    }

    // SAFETY: `index` is bounded by the fixed command line storage size above.
    Some(unsafe {
        core::ptr::read_volatile(
            (&raw const __arceos_ex_kernel_cmdline)
                .cast::<u8>()
                .add(index),
        )
    })
}
