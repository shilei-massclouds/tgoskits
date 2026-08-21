# Starry init-task diagnostics v5

Status: accepted for implementation, 2026-08-21.

This compatibly extends
[Starry post-spawn bootstrap diagnostics v4](starry-post-spawn-bootstrap-diagnostics-v4.md).
The KernDiff consumer continues to retain the raw axbuild QMP fault event, so no
KernDiff persistence schema changes.

## Problem, evidence, and success criteria

A natural v4-instrumented recurrence reached `userspace-init`, stopped before
`shell-ready` and guest start, and produced a complete diagnostic. Both v3/v4
bootstrap bitmaps were `0x3f`, all four per-CPU liveness tasks recorded their
first epoch, and QMP reported `WATCHDOG action=pause` at 67,172 ms. Source order
places the unobserved interval after init image loading and before the init shell
publishes `shell-ready`. Version 4 cannot distinguish init task/process setup,
runqueue insertion, task-extension switching, the task entry trampoline, or the
first user-context run.

The direct users are the opt-in KernDiff observer and maintainers diagnosing the
next natural recurrence. Version 5 succeeds when it preserves the complete
v1--v4 byte prefix, records both sides of the concurrent init main-task and
scheduled-task chains, and axbuild strictly decodes versions 1 through 5. A
checkpoint must not allocate, lock, or log. This change must not alter task or
boot ordering, add an `axtask` public API, change the 60-second watchdog, ordinary
coverage, CLI, QMP fault-event schema, boot-cohort schema, or Starry syscall and
Linux ABI behavior.

Keeping v4 would leave the newly observed interval opaque. Adding serial markers
was rejected because the failure may disable serial progress. Moving or expanding
the generic `axtask` scheduler interface was rejected because existing
`spawn_task_with` and Starry's scheduler tracepoint already expose the required
stable-reference and post-task-extension boundaries. Adding detailed checkpoints
inside every process, file, scope, and runqueue helper was rejected until a
natural recurrence selects one sub-interval. No external specification defines
these project-local diagnostic boundaries; the retained v4 event, Starry init
source order, `spawn_task_with`, `TaskExt::on_enter`, and the v4 atomic page
contract are the applicable prior art.

## Persistent page layout

The aligned 4 KiB page retains the v1 prefix through byte 1576, v2 through byte
1696, v3 through byte 1752, and v4 through byte 1808. Version 5 appends:

```text
offset 1808  init_task_checkpoint_bitmap: u64
offset 1816  init_task_checkpoint_elapsed_ns[14]: u64
```

The v5 payload ends at byte 1928; the declared aligned structure size remains
4096. Watchdog arming clears the new bitmap, elapsed values, and internal init
task identity with all older diagnostic state.

Checkpoint IDs and boundaries are fixed:

| id | name | publication boundary |
| ---: | --- | --- |
| 0 | `init-task-create-requested` | immediately after `userspace-init`, before `UserContext` and task construction |
| 1 | `init-task-constructed` | task construction and page-table-root assignment returned |
| 2 | `init-process-ready` | process, cgroup, stdio, thread, and task extension setup completed |
| 3 | `init-spawn-requested` | immediately before entering the IRQ/preemption guard and calling `spawn_task_with` |
| 4 | `init-task-initialized` | stable task reference exists, before registry and runqueue insertion |
| 5 | `init-spawn-returned` | registry and runqueue insertion returned |
| 6 | `init-console-irq-armed` | `tty::arm_console_irq` returned |
| 7 | `init-join-entered` | the spawning task is about to wait in `join` |
| 8 | `init-task-ext-entered` | the scheduler called PID 1's `TaskExt::on_enter`, before scope acquisition |
| 9 | `init-task-ext-returned` | PID 1's scope was installed and `TaskExt::on_enter` is returning |
| 10 | `init-scheduler-selected` | the existing scheduler tracepoint observed the registered init task after task-extension hooks |
| 11 | `init-task-entered` | the init task began its user-task closure |
| 12 | `init-first-user-run-entered` | immediately before the first `UserContext::run()` |
| 13 | `init-first-user-run-returned` | the first `UserContext::run()` returned a syscall, exception, or interrupt reason |

The main chain is IDs 0 through 7. The scheduled-task chain may begin as soon as
ID 4 publishes the stable task identity and therefore does not depend on spawn
return. Its order is IDs 8 through 13. The scheduler tracepoint is intentionally
after `TaskExt::on_enter`; IDs 8 and 9 separately expose the scope hook that runs
with IRQs disabled before that tracepoint. The init closure records its first run
only once. Every reached checkpoint stores elapsed nanoseconds before publishing
its bit with release ordering. The decoder rejects unknown bits and enforces the
same within-chain and cross-chain dependencies, including the prerequisite that
`userspace-init` is already the eleventh published phase.

## Host decode contract

Axbuild accepts diagnostic versions 1 through 5. Version 5 retains every v4 JSON
member and adds:

```json
{
  "init_task_checkpoint_bitmap": "0x3fff",
  "init_task_checkpoint_elapsed_ns": {
    "init-task-create-requested": 1,
    "init-task-constructed": 2,
    "init-process-ready": 3,
    "init-spawn-requested": 4,
    "init-task-initialized": 5,
    "init-spawn-returned": 10,
    "init-console-irq-armed": 11,
    "init-join-entered": 12,
    "init-task-ext-entered": 6,
    "init-task-ext-returned": 7,
    "init-scheduler-selected": 8,
    "init-task-entered": 9,
    "init-first-user-run-entered": 13,
    "init-first-user-run-returned": 14
  }
}
```

Map order and numeric ID order are not a temporal ordering between the two
producers. Only reached checkpoints appear. Decode or `pmemsave` failure stays in
`raw_error` and never removes the authoritative QMP WATCHDOG event.

## Interpreting the next natural recurrence

- The last reached main-chain checkpoint selects construction, process/stdio,
  stable-reference, registry/runqueue, console IRQ, guard-return, or join work.
- `init-task-initialized` without `init-task-ext-entered` means the task was not
  observed entering its task-extension switch hook; inspect runqueue selection
  before adding generic scheduler instrumentation.
- `init-task-ext-entered` without `init-task-ext-returned` selects the scope
  acquisition/install path inside `TaskExt::on_enter`.
- `init-task-ext-returned` without `init-scheduler-selected` selects the small
  post-hook/pre-tracepoint scheduler window.
- `init-scheduler-selected` without `init-task-entered` selects architectural
  context switching and the task-entry trampoline.
- `init-task-entered` without `init-first-user-run-entered` selects the closure's
  pre-run setup.
- `init-first-user-run-entered` without its return selects the first user-mode
  interval; a return without `shell-ready` selects subsequent syscall/signal or
  userspace initialization progress.

Only the interval selected by the next natural recurrence receives finer
instrumentation. Version 5 is diagnostic and does not claim a root cause or
change scheduling behavior.

## Verification and rollback

Lowest-layer tests cover v5 offsets and page size, concurrent dependency chains,
stable task identity, reset, v1--v4 compatibility, valid v5 JSON, and damaged v5
rejection. Targeted ax-driver, axruntime, axbuild, and Starry kernel checks,
rustfmt, warnings-as-errors clippy, and a non-QEMU release Starry build form the
implementation gate. Operator QEMU regression acceptance must show a normal boot
reaching all twelve phases and guest start. The existing deliberate
`kernel-watchdog` injection occurs before kernel main and PID 1, so it cannot
produce a complete v5 bitmap and is intentionally not moved by this diagnostic
change. The first natural late recurrence supplies the end-to-end v5 page
acceptance evidence; until then, the complete bitmap and damaged-page contracts
are covered at the writer and decoder layers.

Rollback may restore the v4 writer while current axbuild continues to decode
versions 1 through 4. Older axbuild rejects v5 diagnostics but preserves the raw
WATCHDOG event and reports the decode failure, so fault authority remains intact.
