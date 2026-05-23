//! Specification checkpoint trace hooks.
//!
//! Checkpoints are independent from early console and the regular console. The
//! default hook is empty; optional backends can be selected for early debugging.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Checkpoint {
    BootArgsReady       = b'A',
    InterruptStreamPrepared = b'1',
    KernelImagePrepared = b'2',
    RootStreamPrepared  = b'3',
    KernelImageReady    = b'4',
    BootCpuPrepared     = b'B',
    InitTaskPrepared    = b'T',
    InitStackPrepared   = b'S',
    EventStreamPrepared = b'5',
    TrampolineVmReady   = b'6',
    RawDtbReady         = b'C',
    EarlyVmReady        = b'D',
    VmOnline            = b'E',
    EntryPreludeReady   = b'F',
    SwapperVmOnline     = b'G',
    EntrySuccessorReady = b'H',
}

impl Checkpoint {
    pub const fn trace_byte(self) -> u8 {
        self as u8
    }
}

#[inline(always)]
pub fn hit(checkpoint: Checkpoint) {
    emit(checkpoint.trace_byte());
}

#[inline(always)]
pub fn emit(_byte: u8) {
    #[cfg(all(target_arch = "riscv64", feature = "checkpoint-sbi-char"))]
    {
        emit_sbi_char(_byte);
    }
}

#[cfg(all(target_arch = "riscv64", feature = "checkpoint-sbi-char"))]
#[inline(always)]
fn emit_sbi_char(byte: u8) {
    #[allow(deprecated)]
    sbi_rt::legacy::console_putchar(byte as usize);
}

#[macro_export]
macro_rules! checkpoint {
    ($checkpoint:expr $(,)?) => {
        $crate::checkpoint::hit($checkpoint)
    };
}
