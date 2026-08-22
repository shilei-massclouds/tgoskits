# Starry filesystem-init diagnostics v7

Status: implemented; static gates and the non-QEMU release build passed; normal
QEMU acceptance pending.

This compatibly extends
[Starry serial-init diagnostics v6](starry-serial-init-diagnostics-v6.md).
The KernDiff consumer continues to retain the raw axbuild QMP fault event, so
no KernDiff CLI or persistence schema changes.

## Problem, evidence, and success criteria

The eleventh recorded `defect-0001` occurrence is the third Variant B
occurrence. The v6 page recorded both bootstrap chains, all 13 serial-main
checkpoints, and all five timer checkpoints through next-timer programming.
The guest published `filesystem-init-start` but not `filesystem-init-ready`;
QMP reported `WATCHDOG action=pause` at 67,327 ms. CPU 0 recorded
`scheduler_epoch=1` and `irq_epoch=4`. This matches the prior Variant B phase
and scheduling state while selecting only filesystem initialization for the
next diagnostic round. It does not identify a root cause.

Version 7 succeeds when it preserves the complete v1--v6 byte prefix, records
the selected block-runtime and root-mount boundaries without changing their
behavior, and strictly decodes versions 1 through 7. It must not change the
60-second watchdog, scheduling, IRQ, filesystem, mount, serial, QMP, KernDiff
CLI/schema, Starry syscall, or Linux ABI behavior. Writers must add no
allocation, logging, new lock, reverse dependency, or non-page global state.

Generic block I/O, allocator, lock, filesystem-operation, IRQ, or scheduler
histories were rejected because the evidence selects one bounded, one-shot
initialization interval. Serial markers were rejected because a stopped boot
cannot guarantee output and because v6 already completed that path. Reusing
the existing runtime capability boundary keeps `ax-fs-ng` independent of
`ax-driver`: a default-empty observation callback is enabled only by an empty
opt-in feature, and axruntime maps the semantic callbacks to the v7 writer.

## Persistent page layout

The aligned 4 KiB page retains the v1 prefix through byte 1576, v2 through byte
1696, v3 through byte 1752, v4 through byte 1808, v5 through byte 1928, and v6
through byte 2080. Version 7 appends:

```text
offset 2080  filesystem_init_checkpoint_bitmap: u64
offset 2088  filesystem_init_checkpoint_elapsed_ns[32]: u64
```

Only the low 32 bitmap bits are defined. The v7 payload ends at byte 2344; the
declared aligned structure size remains 4096. Watchdog arming clears the new
bitmap and elapsed values with all older diagnostic state.

Checkpoint IDs and boundaries are fixed:

| id | name | publication boundary |
| ---: | --- | --- |
| 0 | `filesystem-runtime-adapter-installed` | all `ax-fs-ng` OS capabilities were installed |
| 1 | `filesystem-block-devices-drained` | direct RDIF block-device collection returned |
| 2 | `filesystem-block-groups-drained` | RDIF block-group collection returned |
| 3 | `filesystem-runtime-install-entered` | immediately before building/installing the block runtime |
| 4 | `filesystem-direct-device-loop-entered` | immediately before the direct-device loop |
| 5 | `filesystem-direct-device-loop-returned` | the complete direct-device loop returned, including empty/error branches |
| 6 | `filesystem-first-group-controller-entered` | before starting the first observed block group controller |
| 7 | `filesystem-first-group-controller-returned` | that controller start returned success or error |
| 8 | `filesystem-first-group-member-bootstrap-entered` | before the first observed group-member bootstrap |
| 9 | `filesystem-first-group-member-bootstrap-returned` | that member bootstrap returned success or error |
| 10 | `filesystem-first-group-irq-setup-entered` | before the first observed group IRQ setup branch |
| 11 | `filesystem-first-group-irq-setup-returned` | that IRQ setup branch returned success or error |
| 12 | `filesystem-first-group-member-ready-entered` | before the first observed bootstrapped member is made ready |
| 13 | `filesystem-first-group-member-ready-returned` | that member-ready operation returned success or error |
| 14 | `filesystem-runtime-published` | the runtime singleton was published after all direct/group attempts |
| 15 | `filesystem-root-init-entered` | immediately before root discovery and mounting |
| 16 | `filesystem-disk-collection-entered` | immediately before collecting discovered disks |
| 17 | `filesystem-first-volume-scan-entered` | before the first observed disk volume scan |
| 18 | `filesystem-first-volume-scan-returned` | that scan returned success or error |
| 19 | `filesystem-root-candidate-selected` | root selection returned a concrete disk/partition |
| 20 | `filesystem-root-mounted` | root filesystem construction and root mount publication returned |
| 21 | `filesystem-additional-mounts-returned` | all selected-disk and remaining-disk additional mount attempts returned |
| 22 | `filesystem-root-init-returned` | the complete root initialization entry point returned |
| 23 | `filesystem-first-block-worker-spawn-entered` | before the first block maintenance task insertion |
| 24 | `filesystem-first-block-worker-spawn-returned` | that task insertion returned |
| 25 | `filesystem-first-block-worker-entered` | the first observed block worker began its entry closure |
| 26 | `filesystem-first-block-worker-affinity-returned` | that worker's CPU-affinity operation returned |
| 27 | `filesystem-window-timer-irq-entered` | the first timer IRQ while phase sequence is exactly two began |
| 28 | `filesystem-window-scheduler-clock-returned` | scheduler-clock publication in that IRQ returned |
| 29 | `filesystem-window-task-timer-entered` | periodic advancement returned and task-timer dispatch is about to begin |
| 30 | `filesystem-window-task-timer-returned` | task-timer dispatch returned |
| 31 | `filesystem-window-next-timer-programmed` | one-shot timer reprogramming returned |

IDs 0--5 are the required runtime prefix. IDs 6--13 describe the first
eligible group branch but are not required for runtime publication: the group
list may be empty, controller/member/IRQ/ready setup may return an error, and
boot continues with direct devices. IDs 14--22 form the required successful
root chain. IDs 23--26 are a concurrent worker chain; worker entry depends on
spawn entry rather than spawn return because the new task may execute before
its spawner returns. IDs 27--31 are an independent timer chain because an IRQ
may preempt either main or worker producer at any boundary.

Every v7 writer first verifies that the watchdog is armed and Acquire-observes
`phase_sequence == 2`. It then validates the checkpoint dependency bitmap and
rejects a published bit. Only an eligible unpublished checkpoint evaluates its
clock callback. Elapsed time is stored before the bit is published with Release
ordering. Thus disarmed, pre-filesystem, post-filesystem, duplicate, damaged-
dependency, later-worker, and later-timer calls do not read the clock.

The timer IRQ uses one permanent early-boot router. Phase sequence one routes
the five timer boundaries to the retained v6 serial writer, phase sequence two
routes them to v7, and every other phase performs no diagnostic write. The old
v6 public writer remains available for compatibility; no second timer hot-path
observer is added.

## Host decode contract

Axbuild accepts diagnostic versions 1 through 7. Version 7 retains every v6
JSON member and adds:

```json
{
  "filesystem_init_checkpoint_bitmap": "0xffffffff",
  "filesystem_init_checkpoint_elapsed_ns": {
    "filesystem-runtime-adapter-installed": 1,
    "filesystem-root-init-returned": 23,
    "filesystem-first-block-worker-entered": 26,
    "filesystem-window-next-timer-programmed": 32
  }
}
```

Only reached checkpoints appear. Map and numeric ID order do not imply temporal
ordering across main, worker, and IRQ producers. The decoder rejects upper
bitmap bits, broken main/group/worker/timer dependencies, any v7 bit before
`filesystem-init-start`, and `filesystem-init-ready` without
`filesystem-root-init-returned`. Decode or `pmemsave` failure remains in
`raw_error` and never removes the authoritative WATCHDOG event.

## Interpreting the next natural recurrence

- The last reached runtime/root boundary selects capability installation,
  driver collection, direct/group runtime construction, root disk/volume
  discovery, selection, root construction/mount, or additional mounts.
- Worker spawn without entry selects initial worker scheduling. Worker entry
  without affinity return selects affinity handling; affinity return does not
  prove that the portable controller entry later progressed.
- The timer chain has the same interpretation as v6 but is limited to the
  filesystem phase. A complete timer chain with an incomplete main chain rules
  out only those observed timer return boundaries for that occurrence.

Only the interval selected by a retained natural recurrence receives finer
instrumentation. Version 7 remains diagnostic and does not claim a root cause.

## Verification and rollback

Lowest-layer tests cover v7 offsets, the v1--v6 prefix, page size, reset, lazy
clock evaluation, direct-device and group success/error branches, worker entry
before spawn return, both timer routes, valid v7 JSON, v1--v6 compatibility,
and damaged v7 rejection. Targeted ax-driver, ax-fs-ng, and axbuild tests;
warnings-as-errors clippy for ax-driver, ax-fs-ng, ax-runtime, axbuild, and the
Starry kernel; rustfmt; a non-QEMU x86_64 release Starry build; and
`git diff --check` form the implementation gate.

Operator acceptance is one normal, no-fault pipe-smoke run that reaches all 12
phases, guest start, fresh coverage, and normal QMP `SHUTDOWN`. Only after that
acceptance may an ordinary natural-reproduction family command run. A new hang
must be retained immediately; indeterminate or fault-injected samples are never
replaced or cleaned.

Implementation verification passed with 24 targeted ax-driver tests, all 68
ax-fs-ng library tests with the observer enabled, and all 11 axbuild QMP decoder
tests. Warnings-as-errors clippy passed all 53 ax-driver, seven ax-fs-ng, 27
ax-runtime, one axbuild, and 27 Starry kernel checks. `cargo fmt --all --check`
and `git diff --check` passed. A non-QEMU x86_64 release build using the
`qemu/kerndiff` build configuration produced target ELF SHA-256
`bf75d63401631c5c79e554aef6b980d12e5757bfeb937228bb06146117045f00`.
This proves compilation and linkage only; it is not normal-boot or fault-path
acceptance.

Rollback removes v7 writers and call sites while current axbuild continues to
decode versions 1 through 6. Older axbuild rejects v7 diagnostics but preserves
the raw WATCHDOG event and decode error, so fault authority remains intact.
