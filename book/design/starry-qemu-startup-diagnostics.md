# Starry QEMU startup diagnostics

Status: implemented, 2026-08-17.

## Problem and compatibility boundary

A coverage-enabled QEMU run previously finalized its coverage capture with `?`
before returning the QEMU result. If QEMU reached its deadline and no profile was
captured, the coverage error replaced the timeout. External automation then saw
only an apparent coverage failure and could not tell which boot phase had
stalled. Existing guest result markers and the `qemu/kerndiff` 300-second timeout
are compatibility boundaries and remain unchanged.

## Error priority

`run_qemu_with_axtest_coverage` now collects the QEMU result and coverage-finalizer
result independently. A real QEMU error remains the first error; if coverage also
fails, the latter is appended as `additional coverage failure`. A lone coverage
failure is still returned directly. The existing compact summary for the benign
“stopped without matching success regex” condition remains in force, including
the historical behavior where a simultaneous coverage failure is the actionable
result. This prevents guest protocol lines from being replayed in a host error.

## Host event protocol

Every prepared QEMU case emits compact JSON after the literal prefix
`[axbuild] qemu-case-event `. The event object has
`schema_name="axbuild-qemu-case"` and `schema_version=1`.

The `start` object contains `event`, `case`, and `timeout_seconds`. The timeout is
the effective value after `AXBUILD_QEMU_TIMEOUT_SCALE`; disabled deadlines are
JSON null. The `end` object repeats that identity and adds `elapsed_ms`, `result`
(`passed` or `failed`), and `error_summary` (null on success). The error summary
uses the complete anyhow display before any external classifier rewrites it.
The end event is emitted before per-case temporary asset cleanup and for both
success and returned QEMU errors.

Consumers must ignore unknown schema versions. Adding optional fields is
backward-compatible; changing field meaning or the line prefix requires a new
schema version. Rolling back this protocol only removes diagnostics and does not
change case selection, timeout, success regex, or guest execution.

## Guest boot stages

Starry emits three ordered raw-console lines:

1. `kernel-main` at the Starry binary entry before calling the kernel init path;
2. `userspace-init` after PID 1's executable image is loaded and before it is
   scheduled;
3. `shell-ready` from the PID 1 shell script before grouped autorun can emit any
   guest test marker.

The syntax is `STARRY_BOOT_STAGE version=1 stage=<stage>`. The existing
KernDiff guest start, result, infrastructure, and coverage-triggered lines remain
unchanged. A consumer can therefore distinguish failure before Starry main,
during kernel initialization, while loading PID 1, or after the shell begins.
A future reordering or additional mandatory stage requires a protocol version
change so strict consumers do not silently misclassify a boot.

## Verification

Axbuild unit tests cover QEMU timeout plus missing coverage, event serialization,
and placement of each boot marker before its next runtime handoff. The Starry
KernDiff QEMU case is the integration gate: it proves the three runtime markers
arrive in order before the unchanged guest protocol and records the effective
300-second inner deadline.
