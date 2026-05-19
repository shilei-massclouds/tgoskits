//! Runtime library for arceos_ex.
//!
//! This crate keeps the public runtime entry shape expected by the existing
//! ArceOS `ax-std` / `arceos-rust` path while the internals are incrementally
//! replaced by specification-defined startup phases.

#![feature(extern_item_impls)]
#![cfg_attr(not(test), no_std)]
#![allow(missing_abi)]

use core::{panic::PanicInfo, time::Duration};

#[macro_use]
extern crate ax_log;

#[eii]
fn ax_app_entry() {
    #[cfg(not(test))]
    unsafe extern "C" {
        safe fn main();
    }

    #[cfg(not(test))]
    main();
}

struct LogIfImpl;

#[ax_crate_interface::impl_interface]
impl ax_log::LogIf for LogIfImpl {
    fn console_write_str(s: &str) {
        ax_hal::console::write_text_bytes(s.as_bytes());
    }

    fn current_time() -> Duration {
        Duration::from_nanos(0)
    }

    fn current_cpu_id() -> Option<usize> {
        Some(0)
    }

    fn current_task_id() -> Option<u64> {
        None
    }
}

/// Primary runtime entry called by the platform after entry-prelude handoff.
#[cfg_attr(not(test), ax_plat::main)]
pub fn rust_main(_cpu_id: usize, _arg: usize) -> ! {
    ax_log::init();
    ax_log::set_max_level(option_env!("AX_LOG").unwrap_or("info"));

    info!("arceos_ex runtime entered");
    ax_app_entry();
    ax_hal::power::system_off()
}

#[cfg(all(target_os = "none", not(test)))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    ax_println!("{}", info);
    ax_hal::power::system_off()
}
