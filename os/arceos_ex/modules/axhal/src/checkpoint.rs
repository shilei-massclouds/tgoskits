//! Specification checkpoint trace hooks.
//!
//! Checkpoints are independent from early console and the regular console. The
//! default hook is empty; optional backends can be selected for early debugging.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Checkpoint {
    BootArgsReady        = b'A',
    InterruptStreamPrepared = b'1',
    KernelImagePrepared  = b'2',
    RootStreamPrepared   = b'3',
    KernelImageReady     = b'4',
    BootCpuPrepared      = b'B',
    InitTaskPrepared     = b'T',
    InitStackPrepared    = b'S',
    EventStreamPrepared  = b'5',
    TrampolineVmReady    = b'6',
    RawDtbReady          = b'C',
    FixMapReady          = b'7',
    EarlyVmReady         = b'D',
    VmReady              = b'E',
    EventStreamOnline    = b'e',
    InitTaskOnline       = b't',
    InitStackReady       = b's',
    SocPrepared          = b'P',
    EntryPreludeReady    = b'F',
    EntryPreludeDestroyed = b'f',
    InitStackOnline      = b'k',
    PlatformCpuInfoOnline = b'c',
    PhysicalMemoryOnline = b'm',
    EarlyDtbPrepared     = b'd',
    CpuIdMapReady        = b'i',
    InterruptStreamReady = b'I',
    BootCpuReady         = b'b',
    BootCpuOnline        = b'o',
    PrintkBufferPrepared = b'p',
    KernelCmdlineReady   = b'a',
    MemBlockPrepared     = b'M',
    EarlyDtbReady        = b'R',
    InitMmReady          = b'n',
    EarlyIoremapReady    = b'r',
    SbiReady             = b'y',
    EarlyConOnline       = b'l',
    KernelParamReady     = b'K',
    SwapperVmOnline      = b'G',
    EntrySuccessorReady  = b'H',
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
    crate::sbi::legacy_console_putchar(byte);
}

#[macro_export]
macro_rules! checkpoint {
    ($checkpoint:expr $(,)?) => {
        $crate::checkpoint::hit($checkpoint)
    };
}
