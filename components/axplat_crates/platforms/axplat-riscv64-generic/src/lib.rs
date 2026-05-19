//! arceos_ex generic RISC-V64 SBI/FDT platform skeleton.
//!
//! The implementation must derive platform facts from the boot ABI and FDT.
//! Fixed QEMU values in `axconfig.toml` are temporary build-tool defaults and
//! must not be used as runtime truth for arceos_ex startup.

#![no_std]

pub mod console {
    pub fn write_bytes(_bytes: &[u8]) {}

    pub fn write_text_bytes(bytes: &[u8]) {
        write_bytes(bytes);
    }

    pub fn read_bytes(_bytes: &mut [u8]) -> usize {
        0
    }
}

pub mod power {
    pub fn system_off() -> ! {
        sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::NoReason);
        loop {
            core::hint::spin_loop();
        }
    }
}
