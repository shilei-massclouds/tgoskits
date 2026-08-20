# Starry post-spawn bootstrap diagnostics v4

Status: implemented; operator QEMU acceptance pending, 2026-08-20.

This compatibly extends
[Starry bootstrap feeder diagnostics v3](starry-bootstrap-feeder-diagnostics-v3.md).
The KernDiff consumer continues to retain the raw axbuild QMP fault event, so no
KernDiff persistence schema changes.

## Problem, evidence, and success criteria

A natural v3-instrumented recurrence stopped at `watchdog-armed` with CPU 0
`scheduler_epoch=0`, `irq_epoch=1`, and bootstrap bitmap `0x7`. The feeder task
had a stable reference and its registry/runqueue insertion returned, but the
entry closure never began. Source-order review showed that the main boot task
runs serial initialization and RTC output between feeder spawn return and
`filesystem-init-start`. Version 3 cannot distinguish a scheduler that never
selects the feeder from a main-thread stall in that interval.

The direct users are the opt-in KernDiff observer and maintainers diagnosing the
next natural recurrence. Version 4 succeeds when it preserves the complete
v1/v2/v3 byte prefix, independently records the feeder's first scheduler
selection and the main task's post-spawn progress, and axbuild strictly decodes
versions 1 through 4. It must not allocate, lock, or log from a checkpoint; add
an `axtask` public API; change boot order, scheduling behavior, the 60-second
watchdog, ordinary coverage, CLI, QMP fault-event schema, boot-cohort schema, or
Starry syscall/Linux ABI.

Keeping v3 would leave two materially different paths indistinguishable.
Adding callbacks inside generic task registration and runqueue insertion was
rejected because A4 proves those calls returned and would expand `axtask` for one
feature-gated observer. Serial markers were rejected because the observed stall
can prevent serial output. The selected design reuses the existing Starry
`SchedTracepoint` implementation for the scheduler boundary and the diagnostic
page's atomic publication contract for both paths. No external specification or
hardware protocol defines these project-local boot boundaries; project source,
the retained A4 QMP event, and existing v3 ordering are the applicable prior art.

## Persistent page layout

The aligned 4 KiB page retains the v1 prefix through byte 1576, v2 through byte
1696, and v3 through byte 1752. Version 4 appends:

```text
offset 1752  bootstrap_followup_checkpoint_bitmap: u64
offset 1760  bootstrap_followup_checkpoint_elapsed_ns[6]: u64
```

The v4 payload ends at byte 1808; the declared aligned structure size remains
4096. Watchdog arming resets the new bitmap and elapsed values together with all
older diagnostic fields and clears the internal feeder task identity.

Checkpoint IDs and boundaries are fixed:

| id | name | publication boundary |
| ---: | --- | --- |
| 0 | `feeder-scheduler-selected` | scheduler chose the registered feeder after the `prev == next` short-circuit and before the architectural context switch |
| 1 | `main-bootstrap-returned` | `start_bootstrap` returned to the main runtime boot sequence |
| 2 | `serial-init-entered` | immediately before `serial::init` |
| 3 | `serial-init-returned` | immediately after `serial::init` returned |
| 4 | `rtc-output-entered` | immediately before the RTC `Boot at` output call |
| 5 | `rtc-output-returned` | immediately after the RTC output call returned |

The feeder task ID is published before `spawn_task_with` makes the task runnable.
The Starry scheduler tracepoint compares `next_tid` with that ID and performs no
work for unrelated switches. Each reached checkpoint stores elapsed nanoseconds
before publishing its bit with release ordering. The scheduler bit is independent
because the feeder may run before the spawning task returns. The main chain is
`main-bootstrap-returned -> serial-init-entered -> serial-init-returned ->
rtc-output-entered -> rtc-output-returned`.

The writer additionally requires v3 `feeder-task-initialized` before scheduler
selection and v3 `feeder-spawn-returned` before any main-chain checkpoint. The
decoder enforces the same cross-version and within-v4 dependencies and rejects
unknown bits.

## Host decode contract

Axbuild accepts diagnostic versions 1, 2, 3, and 4. Version 4 retains every v3
JSON member and adds:

```json
{
  "bootstrap_followup_checkpoint_bitmap": "0x3f",
  "bootstrap_followup_checkpoint_elapsed_ns": {
    "feeder-scheduler-selected": 7,
    "main-bootstrap-returned": 4,
    "serial-init-entered": 5,
    "serial-init-returned": 8,
    "rtc-output-entered": 9,
    "rtc-output-returned": 10
  }
}
```

Elapsed map order is not a temporal contract; the scheduler and main task are
concurrent. Only reached checkpoints appear. Decode or `pmemsave` failure stays
in `raw_error` and never removes the authoritative QMP WATCHDOG event.

## Interpreting the next natural recurrence

- No `main-bootstrap-returned`: inspect the return boundary after v3
  `feeder-spawn-returned`.
- Through `serial-init-entered` but not `serial-init-returned`: add checkpoints
  only inside serial device drain, runtime allocation, IRQ registration, worker
  task insertion, and their lock boundaries.
- Through `serial-init-returned` but not `rtc-output-returned`: inspect RTC
  formatting and console output ownership/locking.
- Main chain complete without `feeder-scheduler-selected`: inspect timer IRQ and
  scheduler task-selection progress.
- `feeder-scheduler-selected` without v3 `feeder-entered`: inspect context-switch
  preparation, commit, previous-task cleanup, and the task-entry trampoline.
- Both scheduler selection and feeder entry reached: continue with the existing
  v3 affinity/first-poll interpretation.

Only the interval selected by the next natural recurrence receives still finer
instrumentation. Version 4 is diagnostic and does not claim a root cause or
change scheduling behavior.

## Verification and rollback

Lowest-layer tests cover the v4 offsets and page size, independent concurrent
chains, dependency rejection, reset, v1/v2/v3 compatibility, valid v4 JSON, and
damaged v4 rejection. Targeted ax-driver, axruntime, axbuild, and Starry kernel
build checks, rustfmt, warnings-as-errors clippy, and a non-QEMU release Starry
build form the implementation gate. Operator QEMU acceptance should observe both
bitmaps as `0x3f`, all twelve boot phases, and `KERNDIFF_GUEST_START`.

Rollback may restore the v3 writer while current axbuild continues to decode
versions 1 through 3. Older axbuild rejects v4 diagnostics but preserves the raw
WATCHDOG event and reports the decode failure, so fault authority remains intact.
