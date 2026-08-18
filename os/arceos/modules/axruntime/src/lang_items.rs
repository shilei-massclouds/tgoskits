// Copyright 2025 The Axvisor Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    match axpanic::enter_panic(current_cpu_id()) {
        axpanic::PanicDisposition::Primary => panic_primary(info),
        // Once panic ownership is established, recursive and cross-CPU panic
        // entries must avoid the full print/backtrace path and terminate the
        // system instead of halting one CPU and risking test timeouts.
        axpanic::PanicDisposition::Recursive | axpanic::PanicDisposition::Concurrent => {
            panic_shutdown()
        }
    }
}

fn panic_primary(info: &PanicInfo) -> ! {
    let _oops_guard = axpanic::enter_oops();
    #[cfg(feature = "kerndiff-fault-observer")]
    kerndiff_panic_notify(info);
    panic_message(info);
    panic_backtrace();
    panic_shutdown()
}

#[cfg(feature = "kerndiff-fault-observer")]
fn kerndiff_panic_notify(info: &PanicInfo) {
    // Establish the allocation-free, lock-free QMP authority before touching
    // the console path.  The marker below is supporting identity evidence and
    // must not be able to prevent PVPANIC_PANICKED from reaching the host.
    ax_driver::kerndiff_fault::notify_panic();
    if let Some(location) = info.location() {
        ax_println!(
            "STARRY_KERNEL_PANIC version=1 panic_type=panic callsite={}:{} cpu={}",
            location.file(),
            location.line(),
            current_cpu_id(),
        );
    } else {
        ax_println!(
            "STARRY_KERNEL_PANIC version=1 panic_type=panic callsite=unknown cpu={}",
            current_cpu_id(),
        );
    }
}

fn panic_message(info: &PanicInfo) {
    ax_println!("{}", info);
}

fn panic_backtrace() {
    if should_print_panic_backtrace() {
        ax_println!("{}", axbacktrace::Backtrace::capture().kind("panic"));
    }
}

fn should_print_panic_backtrace() -> bool {
    axpanic::should_emit_panic_backtrace()
}

fn panic_shutdown() -> ! {
    ax_hal::power::system_off()
}

fn current_cpu_id() -> usize {
    #[cfg(feature = "smp")]
    {
        ax_hal::percpu::this_cpu_id()
    }

    #[cfg(not(feature = "smp"))]
    {
        0
    }
}
