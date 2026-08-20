# Starry bootstrap feeder diagnostics v3

Status: implemented; operator QEMU acceptance pending, 2026-08-20.

This extends
[Starry early boot progress and watchdog diagnostics v1](starry-early-boot-progress-v1.md).
The KernDiff consumer records the raw axbuild QMP fault event without adding a
new persistence schema.

## Problem, evidence, and success criteria

Three intermittent boots have stopped after `watchdog-armed` with CPU 0
`scheduler_epoch=0` and approximately 67-second QMP WATCHDOG pauses. The v2 page
places them before `filesystem-init-start`, but cannot distinguish task
construction, stable-reference initialization, registry/runqueue insertion, or
the feeder's first execution. The direct users of this extension are the
KernDiff fault observer and maintainers locating the next recurrence.

The extension is complete when the existing page preserves its v1 and v2 byte
prefixes, records six allocation-free and lock-free checkpoint publications,
axbuild strictly decodes v1/v2/v3, and a normal boot exposes every checkpoint in
the raw QMP diagnostic. It does not change the 60-second watchdog, boot order,
ordinary coverage protocol, CLI, QMP fault-event schema, KernDiff boot-cohort
schema, or any Starry syscall/Linux ABI.

Keeping v2 would leave the observed spawn-to-first-poll interval unresolved.
Serial-only markers were rejected because the guest can stop between the state
transition and console output. Adding checkpoints to axtask was rejected because
only this opt-in observer consumes them and the existing `TaskInner::new` plus
`spawn_task_with` callback already exposes the necessary stable-reference
boundary. Adding registry/runqueue or lock-level checkpoints now was deferred
until a captured failure selects one smaller interval.

No external protocol or hardware prior art defines these project-local task
boundaries. The design reuses the existing v2 page publication ordering,
axtask's stable-reference initialization callback, and axbuild's strict
versioned decoder.

## Persistent page layout

The aligned 4 KiB page retains the v1 prefix through byte 1576 and the v2
extension through byte 1696. Version 3 appends:

```text
offset 1696  bootstrap_checkpoint_bitmap: u64
offset 1704  bootstrap_checkpoint_elapsed_ns[6]: u64
```

The complete v3 payload ends at byte 1752; the declared aligned structure size
remains 4096. Arming the watchdog resets phase, liveness, checkpoint bitmap, and
checkpoint elapsed fields before enabling publication for the new boot.

Checkpoint IDs and boundaries are fixed:

| id | name | publication boundary |
| ---: | --- | --- |
| 0 | `feeder-spawn-requested` | armed marker emitted, immediately before `TaskInner::new` |
| 1 | `feeder-task-initialized` | stable task reference exists, before registry and runqueue insertion |
| 2 | `feeder-spawn-returned` | registry and runqueue insertion returned to the spawning task |
| 3 | `feeder-entered` | first instruction in the feeder closure |
| 4 | `feeder-affinity-ready` | the CPU0 affinity operation returned |
| 5 | `feeder-first-poll-complete` | the first bootstrap watchdog poll returned |

Each checkpoint has one producer. It stores elapsed nanoseconds from
`boot_epoch` before publishing its bitmap bit with release ordering. Publication
does not allocate, lock, or emit serial output. The creation chain is
`requested -> initialized -> spawn-returned`; the execution chain is
`initialized -> entered -> affinity-ready -> first-poll-complete`.
`feeder-entered` and later execution checkpoints may precede
`feeder-spawn-returned` because the new task can run while the spawning task is
still returning from runqueue insertion.

## Host decode contract

Axbuild accepts page versions 1, 2, and 3. Version 1 has only liveness fields;
version 2 adds boot-phase fields; version 3 adds these JSON members to the
diagnostic object:

```json
{
  "bootstrap_checkpoint_bitmap": "0x3f",
  "bootstrap_checkpoint_elapsed_ns": {
    "feeder-spawn-requested": 1,
    "feeder-task-initialized": 2,
    "feeder-spawn-returned": 3,
    "feeder-entered": 4,
    "feeder-affinity-ready": 5,
    "feeder-first-poll-complete": 6
  }
}
```

Only reached checkpoints appear in the elapsed map. Bits outside the six
defined checkpoints or a bitmap that violates either dependency chain make the
diagnostic corrupt. As before, decode or `pmemsave` failure is retained in the
fault event's `raw_error`; it never removes the authoritative QMP WATCHDOG
event.

## Interpreting the next recurrence

- Only `feeder-spawn-requested`: inspect stack allocation, `TaskInner::new`, and
  conversion to the stable reference.
- Through `feeder-task-initialized`: inspect task registration, runqueue
  selection, and insertion.
- Through `feeder-spawn-returned`: inspect the small window after the spawning
  thread returns.
- Through `feeder-entered` or `feeder-affinity-ready`: inspect feeder entry,
  affinity handling, or the first poll.
- Through `feeder-first-poll-complete` while scheduler epoch remains abnormal:
  inspect inconsistency between checkpoint and liveness publication.

Only after a recurrence selects an interval should that interval gain finer
registry, runqueue, or lock-boundary checkpoints.

## Verification and rollback

Lowest-layer tests cover the v3 offsets and 4 KiB size, watchdog reset,
elapsed-before-bit publication, the two dependency chains and their allowed
concurrency, v1/v2 compatibility, valid v3 JSON, and damaged v3 rejection.
Targeted ax-driver, axruntime, and axbuild tests, formatting, clippy with warnings
denied, and a non-QEMU Starry build are the implementation gate. Operator-run
QEMU acceptance must observe all six checkpoints, all twelve boot phases, and
`KERNDIFF_GUEST_START`.

Rollback can restore the v2 writer while current axbuild continues to decode v1
and v2. Old axbuild versions reject v3 diagnostics but preserve the raw WATCHDOG
event and report the decode failure, so fault authority is not lost.
