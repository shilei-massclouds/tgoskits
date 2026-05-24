//! Minimal SBI ecall wrappers owned by arceos_ex.

const EID_BASE: usize = 0x10;
const FID_GET_SPEC_VERSION: usize = 0;
const FID_GET_IMPL_ID: usize = 1;
const FID_GET_IMPL_VERSION: usize = 2;
const FID_PROBE_EXTENSION: usize = 3;
const EID_LEGACY_CONSOLE_PUTCHAR: usize = 1;
const EID_SRST: usize = 0x5352_5354;
const FID_SYSTEM_RESET: usize = 0;
const RESET_TYPE_SHUTDOWN: usize = 0;
const RESET_REASON_NONE: usize = 0;

pub const EXTENSION_TIME: usize = 0x5449_4d45;
pub const EXTENSION_IPI: usize = 0x7350_49;
pub const EXTENSION_RFENCE: usize = 0x5246_4e43;
pub const EXTENSION_SRST: usize = EID_SRST;
pub const EXTENSION_DBCN: usize = 0x4442_434e;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct SbiRet {
    pub error: usize,
    pub value: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct SbiCapabilityView {
    pub spec_version: usize,
    pub impl_id: usize,
    pub impl_version: usize,
    pub time_available: usize,
    pub ipi_available: usize,
    pub rfence_available: usize,
    pub srst_available: usize,
    pub dbcn_available: usize,
    pub legacy_console_available: usize,
}

// SAFETY: fixed boot-storage symbol used to publish SBI.Ready facts before the
// regular runtime can allocate a richer platform service object.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.sbi")]
pub static mut __arceos_ex_sbi_capability_view: SbiCapabilityView = SbiCapabilityView {
    spec_version: 0,
    impl_id: 0,
    impl_version: 0,
    time_available: 0,
    ipi_available: 0,
    rfence_available: 0,
    srst_available: 0,
    dbcn_available: 0,
    legacy_console_available: 0,
};

// SAFETY: exported C ABI entry is required so naked startup assembly can drive
// SBI.Setup at the model boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __arceos_ex_sbi_setup() -> usize {
    let view = SbiCapabilityView {
        spec_version: sbi_call_0(EID_BASE, FID_GET_SPEC_VERSION).value,
        impl_id: sbi_call_0(EID_BASE, FID_GET_IMPL_ID).value,
        impl_version: sbi_call_0(EID_BASE, FID_GET_IMPL_VERSION).value,
        time_available: probe_extension(EXTENSION_TIME),
        ipi_available: probe_extension(EXTENSION_IPI),
        rfence_available: probe_extension(EXTENSION_RFENCE),
        srst_available: probe_extension(EXTENSION_SRST),
        dbcn_available: probe_extension(EXTENSION_DBCN),
        legacy_console_available: 1,
    };

    // SAFETY: SBI.Setup runs once in the single-root boot flow; this publishes
    // a plain capability fact with no concurrent writer.
    unsafe {
        core::ptr::write_volatile(&raw mut __arceos_ex_sbi_capability_view, view);
    }

    1
}

#[inline]
pub fn legacy_console_putchar(byte: u8) {
    let _ = sbi_call_1(EID_LEGACY_CONSOLE_PUTCHAR, 0, byte as usize);
}

#[inline]
pub fn system_shutdown() -> ! {
    let _ = sbi_call_2(
        EID_SRST,
        FID_SYSTEM_RESET,
        RESET_TYPE_SHUTDOWN,
        RESET_REASON_NONE,
    );
    loop {
        core::hint::spin_loop();
    }
}

#[inline]
pub fn dbcn_available() -> bool {
    // SAFETY: this reads the boot-time fact published by SBI.Setup.
    unsafe {
        core::ptr::read_volatile(&raw const __arceos_ex_sbi_capability_view).dbcn_available != 0
    }
}

#[inline]
pub fn legacy_console_available() -> bool {
    // SAFETY: this reads the boot-time fact published by SBI.Setup.
    unsafe {
        core::ptr::read_volatile(&raw const __arceos_ex_sbi_capability_view)
            .legacy_console_available
            != 0
    }
}

#[inline]
fn probe_extension(extension_id: usize) -> usize {
    usize::from(sbi_call_1(EID_BASE, FID_PROBE_EXTENSION, extension_id).value != 0)
}

#[inline(always)]
fn sbi_call_0(eid: usize, fid: usize) -> SbiRet {
    let error: usize;
    let value: usize;

    // SAFETY: this is the RISC-V SBI ecall ABI boundary. Inputs are register
    // values only, and outputs are captured from a0/a1 as specified by SBI.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") 0usize => error,
            lateout("a1") value,
            in("a6") fid,
            in("a7") eid,
            options(nostack)
        );
    }

    SbiRet { error, value }
}

#[inline(always)]
fn sbi_call_1(eid: usize, fid: usize, arg0: usize) -> SbiRet {
    let error: usize;
    let value: usize;

    // SAFETY: see `sbi_call_0`; a0 additionally carries the first SBI argument.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") arg0 => error,
            lateout("a1") value,
            in("a6") fid,
            in("a7") eid,
            options(nostack)
        );
    }

    SbiRet { error, value }
}

#[inline(always)]
fn sbi_call_2(eid: usize, fid: usize, arg0: usize, arg1: usize) -> SbiRet {
    let error: usize;
    let value: usize;

    // SAFETY: see `sbi_call_0`; a0/a1 carry the first two SBI arguments.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") arg0 => error,
            inlateout("a1") arg1 => value,
            in("a6") fid,
            in("a7") eid,
            options(nostack)
        );
    }

    SbiRet { error, value }
}
