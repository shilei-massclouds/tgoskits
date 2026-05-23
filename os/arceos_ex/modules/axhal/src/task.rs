#[repr(C, align(64))]
pub struct InitTaskStorage {
    marker: usize,
}

impl InitTaskStorage {
    pub const fn new() -> Self {
        Self { marker: 0 }
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.init_task")]
pub static mut __arceos_ex_init_task: InitTaskStorage = InitTaskStorage::new();

pub fn init_task_addr() -> usize {
    &raw const __arceos_ex_init_task as usize
}
