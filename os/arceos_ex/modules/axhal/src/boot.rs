use core::sync::atomic::{AtomicUsize, Ordering};

static BOOT_HARTID: AtomicUsize = AtomicUsize::new(0);
static DTB_PA: AtomicUsize = AtomicUsize::new(0);

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
    BOOT_HARTID.store(boot_hartid, Ordering::Relaxed);
    DTB_PA.store(dtb_pa, Ordering::Relaxed);
}

pub fn boot_args() -> BootArgs {
    BootArgs::new(
        BOOT_HARTID.load(Ordering::Relaxed),
        DTB_PA.load(Ordering::Relaxed),
    )
}
