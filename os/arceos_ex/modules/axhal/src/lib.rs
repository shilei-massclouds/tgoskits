//! arceos_ex hardware abstraction layer skeleton.
//!
//! This crate is intentionally minimal while the arceos-ex overlay workspace is
//! being wired into xtask. Startup implementation must be filled according to
//! the componentized kernel specification before it is used as a real HAL.

#![no_std]

pub mod console {
    pub use ax_plat::console::{read_bytes, write_bytes, write_text_bytes};
}

pub mod power {
    pub use ax_plat::power::system_off;
}
