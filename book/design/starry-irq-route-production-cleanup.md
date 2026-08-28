# Starry IRQ-route production cleanup

Status: implemented; non-QEMU acceptance passed and operator QEMU acceptance
pending, 2026-08-28.

## Decision

The forced-overlap experiment demonstrated that an ordinary IRQ-route read
guard permits same-CPU hard-IRQ re-entry and that an IRQ-saving guard excludes
that deadlock.  A subsequent frozen natural sample completed 405 target boots
without a hang while the candidate was installed.  That result supports taking
the candidate to its production form, but it does not prove that every
historical `defect-0001` occurrence had this cause.

The production candidate therefore retains only the two IRQ-saving
`IRQ_ROUTES` guards and their guard-state regression test.  The temporary
forced-overlap probe was already removed.  This cleanup additionally retires
the defect-directed v3--v7 checkpoint implementation after the frozen sample:

- bootstrap-feeder and post-spawn bootstrap checkpoints;
- init-task and first-user-run checkpoints;
- serial-init and overlapping timer checkpoints;
- filesystem-init, block-worker, and overlapping timer checkpoints;
- their ax-fs-ng observation feature and callbacks; and
- their axbuild v3--v7 page decoding and tests.

The v1/v2 watchdog and early-boot progress contract remains.  In particular,
the i6300 watchdog, QMP fault authority, per-CPU liveness epochs, diagnostic
page v1/v2 compatibility, and the ordered 12-phase protocol are unchanged.
Historical v3--v7 design and acceptance documents remain as evidence records;
they no longer describe code enabled at this revision.

## Mechanical boundary

Of the 19 checkpoint-touched implementation, configuration, guide, and v1
design files, 18 are restored byte-for-byte to the fixed post-v2 boundary
`9493f7f6c68ecd09665ad8e056a79ab474e3e01e`.  `proc.rs` differs only by the
behavior-equivalent `SimpleFileOperation::Write([])` pattern required by the
current warnings-as-errors Clippy.  The IRQ-route implementation is outside
that restore set and retains the accepted candidate from
`05564f51ecb42758a205bd31e4d787d6594bae5b`.  This makes the cleanup auditable
without hand-editing filesystem, task, serial, or timer behavior.

## Acceptance

Before operator-controlled QEMU execution, the cleanup must pass:

1. absence checks for every retired type, writer, bitmap, feature, callback,
   timer router, and forced-overlap probe in production code/configuration;
2. byte comparison of 18 restored files against the fixed v2 boundary plus the
   isolated behavior-equivalent `proc.rs` syntax update;
3. the IRQ-route IRQ-state regression test and targeted ax-driver, ax-fs-ng,
   axruntime, axbuild, and Starry kernel checks;
4. warnings-as-errors clippy, workspace formatting, release build, and diff
   hygiene; and
5. a clean, non-reused pipe-smoke with 12 phases, guest/application completion,
   fresh coverage, and QMP `SHUTDOWN`.

After that smoke, a bounded natural regression runs against this production-only
candidate.  A natural hang remains authoritative evidence and does not justify
restoring checkpoints in the same run.  Until the cleanup smoke and regression
complete, `defect-0001` remains open and unresolved.

Non-QEMU acceptance passed with 35 ax-driver observer tests, 53 somehal library
tests including the IRQ-route guard-state regression, 78 ax-fs-ng tests, and six
axbuild QMP decoder tests.  Warnings-as-errors Clippy passed all 122 selected
checks across somehal, ax-driver, ax-fs-ng, ax-runtime, axbuild, and the Starry
kernel.  `cargo fmt --all --check` and `git diff --check` passed.  A non-QEMU
x86_64 release build using the `qemu/kerndiff` build configuration produced a
17,551,016-byte target ELF with SHA-256
`479b49bcbdb5219457c9feab92bfb009b2e514f3989696082efe2083f1ce09c2`.
This proves compilation and linkage only; it is not normal-boot acceptance.
