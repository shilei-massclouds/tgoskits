# Starry early boot progress and watchdog diagnostics v1

Status: complete, 2026-08-19. Boot-probe host contract clarified 2026-08-20.

The bootstrap task creation and first-run extension is defined by
[Starry bootstrap feeder diagnostics v3](starry-bootstrap-feeder-diagnostics-v3.md).

The consumer contract is
[KernDiff phase 2.14 early boot historical statistical diff v1](https://github.com/shilei-massclouds/KernDiff/blob/dev/docs/design/early-boot-historical-diff-v1.md).
TGOSKits publishes target facts only. It does not own cohorts, baselines,
statistics, revision comparisons, campaign budgets, retry, or minimization.

## Problem and success criteria

The current opt-in KernDiff profile exposes an armed i6300ESB marker, a QMP
fault event, a watchdog diagnostic page v1, and three `STARRY_BOOT_STAGE` v1
lines. Those facts locate only the tail of initialization and the page cannot
say which stable early phase was last committed. In addition, the current
`kernel-watchdog` validation injection fires before the external guest runner,
so a consumer needs enough evidence to classify it in the boot domain.

The producer is complete when one helper records a stable phase in the
host-readable diagnostic page before emitting its serial marker, QMP exports
the added fields while retaining v1 decode compatibility, a corrupt page never
cancels the authoritative WATCHDOG event, and the opt-in Starry QEMU path proves
the ordered protocol through `KERNDIFF_GUEST_START`.

This does not change general Starry boot order, watchdog timing, normal QEMU
defaults, or any syscall/Linux ABI. It adds no production `/dev/watchdog` API.

## Stable phase protocol

The feature-gated helper publishes these exact phases in order:

| id | name | boundary |
| ---: | --- | --- |
| 0 | `watchdog-armed` | i6300ESB programming and enable verified |
| 1 | `filesystem-init-start` | immediately before `axruntime::fs::init` |
| 2 | `filesystem-init-ready` | `axruntime::fs::init` returned |
| 3 | `secondary-startup-start` | immediately before secondary release |
| 4 | `secondary-startup-ready` | secondary startup call returned |
| 5 | `all-cpus-initialized` | the runtime CPU initialization barrier completed |
| 6 | `ipi-ready` | all intended CPUs passed the IPI readiness barrier |
| 7 | `smp-filesystem-online` | the SMP block/filesystem runtime is online |
| 8 | `watchdog-handoff` | per-CPU liveness tasks replaced the bootstrap feeder |
| 9 | `kernel-main` | Starry application entry began |
| 10 | `userspace-init` | PID 1 image loaded, before scheduling |
| 11 | `shell-ready` | PID 1 shell reached its pre-autorun control point |

The emitted line is:

```text
STARRY_BOOT_STAGE version=2 sequence=<1..12> stage=<name> elapsed_ns=<n>
```

Sequence is monotonically increasing and `elapsed_ns` is measured from the
watchdog arm epoch. A missing, duplicate, or reordered mandatory phase is a
protocol error for the KernDiff QEMU profile. The existing v1
`kernel-main`/`userspace-init`/`shell-ready` lines remain as compatibility
aliases and are emitted by the same helper after the v2 page update. Existing
guest start/result/coverage markers are unchanged.

The shell reaches the helper by writing the exact token `shell-ready` to a
test-only procfs control file. The kernel validates the token, records the page,
then prints both markers; the shell does not independently claim that the page
was updated.

## Diagnostic page v2

The page keeps the v1 prefix byte-for-byte:

```text
magic, version, size, max_cpus,
boot_epoch, online_mask, stale_mask,
scheduler_epoch[64], irq_epoch[64], last_progress_ns[64]
```

Version 2 appends:

```text
reached_phase_bitmap: u64
last_phase: u32
reserved: u32
phase_sequence: u64
phase_elapsed_ns[12]: u64
```

The writer stores the phase elapsed time and reached bit before publishing the
last phase/sequence and before serial output. The page remains within the
existing aligned 4 KiB `pmemsave` transfer. Axbuild accepts and strictly decodes
both versions. v1 JSON has no phase fields; v2 JSON adds the bitmap, last phase,
sequence, and the reached phase elapsed-time map.

The QMP `WATCHDOG` event with `action=pause`, associated case identity, and a
previous armed marker remains authoritative. Diagnostic decode or `pmemsave`
failure is copied to `raw_error` and leaves the event intact. RESET, SHUTDOWN,
timeouts, validation markers, and serial phase markers are supporting facts,
not substitutes for WATCHDOG authority.

## Boot-only probe and frozen inputs

For bounded historical investigation the existing KernDiff case accepts two
opt-in environment inputs supplied by the Target Driver:

- a validated absolute frozen rootfs base used instead of the managed shared
  rootfs before the per-run overlay copy;
- boot-probe mode, which asks the QMP capture to quit cleanly after the matching
  `KERNDIFF_GUEST_START` line.

Boot-probe mode restores the validated frozen ELF byte-for-byte after Cargo's
build boundary and before kallsyms/bin generation. This is distinct from normal
pinned replay: ordinary replay continues to reject executable or coverage
section drift, while a boot cohort must execute the original frozen artifact
even when a repeated instrumented link is not byte-reproducible. The restore is
accepted only when QMP fault capture and boot-probe mode are both explicit and
the frozen path exactly matches the existing pinned-kallsyms source boundary.

The frozen ELF remains coverage-instrumented, but boot-probe execution has an
independent host success contract: the complete line must match
`KERNDIFF_GUEST_START version=1 run_id=[0-9a-f]+`. Axbuild installs that exact
marker as the QEMU runner's direct child-stream stop contract. The general
streaming QEMU-output capture independently verifies it, including when it
spans host output chunks, and notifies QMP to issue the clean `quit` during the
runner's output-drain window. The direct runner contract prevents a valid
guest-start from falling through to the case timeout if an indirect host tee
cannot drive termination. In this mode axbuild does not install the axtest
coverage monitor, export profraw, wait for
`AXTEST_COVERAGE_DONE`, or require a fresh profile at completion. A stop before
the exact guest-start marker remains a failure, and QEMU startup, timeout,
WATCHDOG, pvpanic, and other real errors retain their existing precedence.
`KERNDIFF_BOOT_PROBE=1` without `KERNDIFF_QMP_FAULTS=1` fails before QEMU starts.

This exception is limited to the boot-only probe. Ordinary syscall/test runs
with coverage enabled retain the existing strict contract: the guest result and
coverage trigger must lead to a newly exported profraw, and a missing profile is
still a coverage failure. No CLI, configuration, marker, QMP event, or persisted
JSON schema changes.

The existing per-run rootfs copy plus disk snapshot semantics remain in force.
The Target Driver supplies a frozen OVMF directory through the existing
`TGOS_OVMF_DIR` boundary and a pinned target ELF through the existing kallsyms
source boundary. These inputs are accepted only with the opt-in QMP fault
profile and fail closed when absent, non-absolute, symlinked, or not regular.
Normal Starry QEMU cases do not inspect them.

## Alternatives and risks

Adding another watchdog or parsing ordinary log text was rejected because QMP
already supplies the authoritative event. Printing phases without updating the
page was rejected because a hang can stop serial output after the state
transition. Replacing v1 in place was rejected because existing consumers need
an unambiguous compatibility path. A userspace-only shell marker was rejected
because it cannot prove the diagnostic page reached the same phase.

The extra atomics and serial lines exist only in the KernDiff fault-observer
build. Phase publication does not allocate or lock in the driver page update.
The procfs control is test-only and accepts one closed token. Rollback removes
the observer feature or ignores v2; watchdog v1/QMP behavior remains readable.

## Verification

Lowest-layer tests cover stable phase ids/order, record-before-marker state,
v1/v2 page decode, malformed v2 rejection, frozen-rootfs validation, boot-probe
contract priority over coverage, exact streaming guest-start matching,
guest-start-driven QMP quit, missing-marker and real-QEMU-error precedence,
ordinary missing-profraw failure, and corrupt-diagnostic WATCHDOG retention.
Targeted ax-driver,
axruntime, Starry kernel, and axbuild tests plus fmt/clippy are required. The
`qemu/kerndiff` integration run must observe all v2 phases in order, then
`KERNDIFF_GUEST_START`; the existing `kernel-watchdog` validation fault must
stop before guest start and still produce armed + QMP WATCHDOG evidence.

The non-QEMU implementation gate passed on 2026-08-19: workspace formatting,
7 ax-driver observer tests, 6 axbuild QMP diagnostic tests, the ax-runtime
observer check, a release Starry x86_64 KernDiff-profile build, and focused
clippy with warnings denied for axbuild, ax-driver, and ax-runtime. Ax-runtime
clippy used `--no-deps` because dependency-inclusive clippy reaches an unrelated
pre-existing needless-return warning in `ax-task/src/run_queue.rs`. A full
axbuild library run completed 876 tests before the remaining QEMU
asset-preparation case was deliberately stopped for operator handoff.

No QEMU process was started for the non-QEMU validation. Operator-controlled
KernDiff Phase 2.14 acceptance then passed against this exact Starry QEMU
profile. The injected `kernel-watchdog` trigger and both frozen-ELF follow-up
boots stopped after `watchdog-handoff` with an armed marker, matching QMP
WATCHDOG pause, and no guest-start marker. The resulting strict cohort contained
three hangs and exactly two additional executions. A fault-free run published
all twelve v2 phases in order and then `KERNDIFF_GUEST_START`. Finally, the same
fault with early-boot history disabled started exactly one execution and
published no cohort. Exact commands, cohort identity, statistics, and storage
checks are recorded in the matching KernDiff validation record.
