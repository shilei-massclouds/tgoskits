const BOOT_ARG_UNSET: usize = usize::MAX;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.boot_args")]
pub static mut __arceos_ex_boot_hartid: usize = BOOT_ARG_UNSET;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".data.boot_args")]
pub static mut __arceos_ex_dtb_pa: usize = BOOT_ARG_UNSET;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot_cpu")]
pub static mut __arceos_ex_boot_cpu_hartid: usize = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootArgs {
    pub boot_hartid: usize,
    pub dtb_pa: usize,
}

impl BootArgs {
    pub const fn new(boot_hartid: usize, dtb_pa: usize) -> Self {
        Self {
            boot_hartid,
            dtb_pa,
        }
    }
}

pub fn init_boot_args(boot_hartid: usize, dtb_pa: usize) {
    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_boot_hartid, boot_hartid);
        core::ptr::write_volatile(&raw mut __arceos_ex_dtb_pa, dtb_pa);
    }
}

pub fn boot_args() -> BootArgs {
    unsafe {
        BootArgs::new(
            core::ptr::read_volatile(&raw const __arceos_ex_boot_hartid),
            core::ptr::read_volatile(&raw const __arceos_ex_dtb_pa),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootCpu {
    pub hartid: usize,
}

impl BootCpu {
    pub const fn new(hartid: usize) -> Self {
        Self { hartid }
    }
}

pub fn boot_cpu() -> BootCpu {
    unsafe {
        BootCpu::new(core::ptr::read_volatile(
            &raw const __arceos_ex_boot_cpu_hartid,
        ))
    }
}
