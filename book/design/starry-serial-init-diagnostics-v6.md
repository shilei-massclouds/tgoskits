# Starry serial-init diagnostics v6

Status: implemented; static gates and the non-QEMU release build passed,
2026-08-22. Normal QEMU acceptance and natural-recurrence decoding remain
pending.

This compatibly extends
[Starry init-task diagnostics v5](starry-init-task-diagnostics-v5.md). The
KernDiff consumer continues to retain the raw axbuild QMP fault event, so no
KernDiff CLI or persistence schema changes.

## Problem, evidence, and success criteria

Three independent natural Variant A recurrences produced the same complete v5
state. Bootstrap feeder creation and runqueue insertion returned, the main boot
path entered serial initialization, and neither serial initialization return nor
the feeder's first scheduler selection was published. CPU 0 stayed at scheduler
epoch zero and recorded only one or two timer IRQs. The latest occurrence was on
the accepted lazy-observer revision and a different target ELF, so the removed
unconditional scheduler clock reads are not the sole cause.

Version 5 cannot distinguish a main-thread stall while taking serial devices,
masking the UART, allocating runtime state, registering the UART IRQ, inserting
the worker task, or publishing the runtime array. It also cannot show whether a
timer interrupt that overlaps serial initialization returns through scheduler
clock publication, task-timer dispatch, and one-shot timer reprogramming. The
direct users are the opt-in KernDiff observer and maintainers diagnosing the
next natural recurrence.

Version 6 succeeds when it preserves the complete v1--v5 byte prefix, records
the selected serial and timer boundaries without locks, allocation, or logging,
and axbuild strictly decodes versions 1 through 6. It must not change serial,
IRQ, timer, task, or boot ordering; expose a new axtask API; change the
60-second watchdog; or change ordinary coverage, the QMP event schema, KernDiff
CLI/schema, or Starry syscall and Linux ABI behavior.

Adding generic allocator, lock, IRQ, or scheduler tracing was rejected because
the evidence selects one early boot window. Serial output markers were rejected
because the suspected path owns serial initialization and a stall can suppress
them. Repeated per-device and per-tick histories were rejected because they add
hot-path writes and require a new ring-buffer coherence contract. The selected
one-shot boundaries are sufficient for the single-UART x86_64 QEMU profile and
remain truthful on multi-device systems: the inner chain describes only the
first enumerated runtime, while the final publication bit covers completion of
the complete device loop.

## Persistent page layout

The aligned 4 KiB page retains the v1 prefix through byte 1576, v2 through byte
1696, v3 through byte 1752, v4 through byte 1808, and v5 through byte 1928.
Version 6 appends:

```text
offset 1928  serial_init_checkpoint_bitmap: u64
offset 1936  serial_init_checkpoint_elapsed_ns[18]: u64
```

The v6 payload ends at byte 2080; the declared aligned structure size remains
4096. Watchdog arming clears the new bitmap and elapsed values with all older
diagnostic state.

Checkpoint IDs and boundaries are fixed:

| id | name | publication boundary |
| ---: | --- | --- |
| 0 | `serial-device-drain-entered` | immediately before `take_serial_devices` |
| 1 | `serial-device-drain-returned` | device collection returned |
| 2 | `serial-first-runtime-build-entered` | before building the first enumerated runtime |
| 3 | `serial-first-port-mask-entered` | immediately before the first UART `mask_all` |
| 4 | `serial-first-port-mask-returned` | the first UART `mask_all` returned |
| 5 | `serial-first-runtime-allocation-entered` | before allocating the first runtime's shared state, queues, poll sets, and worker task |
| 6 | `serial-first-runtime-allocation-returned` | that runtime and worker task construction returned |
| 7 | `serial-first-irq-setup-entered` | before resolving/registering the first runtime IRQ, or deciding to skip it |
| 8 | `serial-first-irq-setup-returned` | IRQ setup or the no-IRQ branch returned |
| 9 | `serial-first-worker-spawn-entered` | immediately before inserting the first maintenance task |
| 10 | `serial-first-worker-spawn-returned` | first maintenance-task insertion returned |
| 11 | `serial-first-runtime-build-returned` | the first `build_runtime` call returned `Ok` or `Err` to the device loop |
| 12 | `serial-runtimes-published` | the complete device loop returned and `SERIAL_RUNTIMES` was published |
| 13 | `serial-window-timer-irq-entered` | the first timer IRQ observed after serial-init entry and before its return |
| 14 | `serial-window-scheduler-clock-returned` | scheduler-clock publication in that IRQ returned |
| 15 | `serial-window-task-timer-entered` | periodic advancement returned and task-timer dispatch is about to begin |
| 16 | `serial-window-task-timer-returned` | task-timer dispatch returned |
| 17 | `serial-window-next-timer-programmed` | one-shot timer reprogramming returned |

IDs 0--12 form the main serial chain, with two deliberate branches.
`serial-first-runtime-build-returned` depends on build entry rather than every
successful inner boundary because `build_runtime` can return an error. Likewise,
`serial-runtimes-published` depends only on device-drain return because the
device list may be empty or a runtime may fail without hanging boot. All other
inner first-runtime boundaries are sequential. IDs 13--17 are an independent
timer-IRQ chain because an interrupt may preempt the main producer at any serial
boundary.

Every v6 writer first Acquire-observes the v4 `serial-init-entered` bit and
rejects publication after `serial-init-returned`. It then validates the v6
dependency bitmap. Only an eligible unpublished checkpoint evaluates its clock
callback. Elapsed time is stored before the bit is published with Release
ordering. Thus unrelated timer IRQs, later timer IRQs, repeated boundaries, a
disarmed watchdog, or a call outside the serial window do not read the clock.

## Host decode contract

Axbuild accepts diagnostic versions 1 through 6. Version 6 retains every v5 JSON
member and adds:

```json
{
  "serial_init_checkpoint_bitmap": "0x3ffff",
  "serial_init_checkpoint_elapsed_ns": {
    "serial-device-drain-entered": 1,
    "serial-device-drain-returned": 2,
    "serial-first-runtime-build-entered": 3,
    "serial-first-port-mask-entered": 4,
    "serial-first-port-mask-returned": 5,
    "serial-first-runtime-allocation-entered": 6,
    "serial-first-runtime-allocation-returned": 7,
    "serial-first-irq-setup-entered": 8,
    "serial-first-irq-setup-returned": 9,
    "serial-first-worker-spawn-entered": 10,
    "serial-first-worker-spawn-returned": 11,
    "serial-first-runtime-build-returned": 12,
    "serial-runtimes-published": 13,
    "serial-window-timer-irq-entered": 14,
    "serial-window-scheduler-clock-returned": 15,
    "serial-window-task-timer-entered": 16,
    "serial-window-task-timer-returned": 17,
    "serial-window-next-timer-programmed": 18
  }
}
```

Map order and numeric ID order are not temporal ordering between the main and
IRQ producers. Only reached checkpoints appear. The decoder rejects unknown
bits, broken within-chain dependencies, v6 bits without v4 serial-init entry,
and serial-init return without `serial-runtimes-published`. Decode or `pmemsave`
failure remains in `raw_error` and never removes the authoritative WATCHDOG
event.

## Interpreting the next natural recurrence

- The last reached serial-main boundary selects device collection, UART masking,
  runtime/task allocation, IRQ setup, worker insertion, the post-spawn log/return
  boundary, a later-device build, or runtime-array publication.
- No timer-chain bit means no timer IRQ was observed in the serial window. A
  timer IRQ entry without scheduler-clock return selects scheduler-clock
  publication. Scheduler-clock return without task-timer entry selects periodic
  advancement. Task-timer entry without return selects timer/preemption dispatch;
  a concurrent feeder-selection bit shows whether that dispatch selected the
  feeder. Task-timer return without timer-programmed selects deadline selection
  or hardware one-shot programming.
- A complete timer chain with an incomplete serial-main chain favors a local
  serial-path stall over the specific observed timer-dispatch boundaries, but it
  does not prove a lock or instruction. A partial timer chain can instead select
  a broader IRQ/scheduler liveness failure.

Only the interval selected by the next natural recurrence receives finer
instrumentation. Version 6 remains diagnostic and does not claim a root cause.

## Verification and rollback

Lowest-layer tests cover v6 offsets and page size, both dependency chains, lazy
clock evaluation, reset, v1--v5 compatibility, valid v6 JSON, and damaged v6
rejection. Targeted ax-driver and axbuild tests, ax-driver and Starry clippy,
rustfmt, a non-QEMU x86_64 release Starry build, and `git diff --check` form the
implementation gate. Operator QEMU acceptance must be a normal pipe-smoke run
that reaches all twelve phases, guest start, coverage, and normal QMP SHUTDOWN;
it must not use a deliberate `kernel-watchdog` injection.

Rollback restores the v5 writer and call sites while current axbuild continues
to decode versions 1 through 5. Older axbuild rejects v6 diagnostics but
preserves the raw WATCHDOG event and decode error, so fault authority remains
intact.

Implementation verification passed with 20 targeted ax-driver tests and 10
axbuild QMP-decoder tests. Warnings-as-errors clippy passed all 53 ax-driver, 27
ax-runtime, one axbuild, and 27 Starry kernel checks. `cargo fmt --all --check`
and `git diff --check` passed. A non-QEMU x86_64 release build using the
`qemu/kerndiff` build configuration produced target ELF SHA-256
`d925a72eadcf34bfadd4a77ff0eaae0e1c639e625dd2dc5b5db6029c01d73fa2`.
This build result proves compilation and linkage only; it is not normal-boot or
fault-path acceptance.
