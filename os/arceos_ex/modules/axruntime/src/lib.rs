//! Runtime library for arceos_ex.
//!
//! This crate keeps the public runtime entry shape expected by the existing
//! ArceOS `ax-std` / `arceos-rust` path while the internals are incrementally
//! replaced by specification-defined startup phases.

#![feature(extern_item_impls)]
#![cfg_attr(not(test), no_std)]
#![allow(missing_abi)]

use core::panic::PanicInfo;

mod boot;

#[eii]
fn ax_app_entry() {
    #[cfg(not(test))]
    unsafe extern "C" {
        safe fn main();
    }

    #[cfg(not(test))]
    main();
}

/// Primary runtime entry called by the platform after entry-prelude handoff.
#[cfg_attr(not(test), ax_plat::main)]
pub fn rust_main(cpu_id: usize, arg: usize) -> ! {
    if !boot::entry_successor_phase_setup(cpu_id, arg) {
        ax_hal::power::system_off()
    }

    ax_app_entry();
    ax_hal::power::system_off()
}

#[cfg(all(target_os = "none", not(test)))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    ax_hal::console::write_text_bytes(b"arceos_ex panic\n");
    ax_hal::power::system_off()
}
