# Stage 6.1: controlled eventfd blocking and wakeup

## Status

Implementation in progress; runtime acceptance is pending. This document is
the independently reviewable high-risk design for Stage 6.1 of the Starry
Linux differential-testing roadmap. It introduces a bounded pthread
concurrency model and a new persistent canonical format, so implementation
must remain a separate commit from this design.

Stage 5's synchronous adapter remains `eventfd-v1`. The CLI calls that scenario
model `simple-single` because it is single-threaded and statically nonblocking.
Stage 6.1 adds the independent `eventfd-blocking-v1` adapter selected by
`fuzz.py --model blocking`; omitting `--model` selects `simple-single`. The two
identities are not aliases: replay selects one from the saved `adapter_id` and
rejects unknown or contradictory metadata.

Model names and format versions are separate axes. `simple-single` retains the
historical `eventfd-v1` identity because changing it would invalidate existing
metadata. `blocking` starts at adapter version 1 while using `eventfd.ops`
format version 2. A later blocking-format change increments that model's own
versions; it does not imply that blocking replaces the simple model.

## Problem, users, and success criteria

The synchronous eventfd adapter deliberately rejects every call that could
sleep. It therefore cannot test the compatibility boundary where an empty
counter blocks a reader, a full counter blocks a writer, and a change made
through the same event object wakes that waiter. Those paths exercise the
eventfd wait queue, Starry task `poll_io`, and `axpoll::PollSet`, and a missed
wakeup can hang an application even when every nonblocking result is correct.

Direct users are Starry eventfd, filesystem, syscall, scheduler, and polling
maintainers. A concrete Stage 6.1 story is: start one blocking raw syscall in a
worker, prove that it remains incomplete during a fixed pending guard, change
the same eventfd from the controller, and require the worker to finish with
the result recorded by the host Linux run.

The stage succeeds when:

- a strict `eventfd.ops` v2 can express one controller and one worker with at
  most one unfinished call;
- validation proves that every `start-*` initially blocks, every controller
  trigger addresses the same event object, and the worker is eventually able
  to complete before `join`;
- the host and Starry harnesses observe the same pending checkpoints, trigger
  syscall results, and joined worker result without comparing natural
  scheduling order or elapsed time;
- fixed normal, semaphore, alias, zero-write, and phased-release stories have
  byte-stable host traces over three consecutive recordings;
- blocking campaigns have their own adapter identity, campaign root, coverage target,
  corpus, metadata, replay dispatch, attribution, and minimization state; and
- every v1 canonical byte, digest, artifact, task, command default, and
  persistent directory remains unchanged and replayable.

Keeping Stage 6.1 out would leave the eventfd wait/wakeup implementation
untested by the Linux oracle. Replacing v1 would make old synchronous evidence
ambiguous and would force concurrency machinery into users that do not need it.

## Risk classification and evidence sources

This is high risk under `book/guideline/feature-development.md`: it adds a
canonical persistent format, a new concurrency model, atomic synchronization,
thread ownership, and timeout classifications. The design therefore fixes the
state machine, validation proof, compatibility boundary, failure ownership,
and validation evidence before implementation.

Host Linux execution is the semantic authority. The harness records what the
running host returns for the exact canonical scenario; neither Python nor the
C comparator contains an expected errno, scheduling, or wakeup model.

Linux source is used only to understand the mechanism. The fixed explanatory
reference remains
[`a2cf4ef33184df0ae9e1a2b05b550133dde1698c`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c),
whose eventfd read/write paths wait on `ctx->wqh` and wake the complementary
side after changing `ctx->count`. Host traces, not this revision, decide the
expected result.

There is a version-dependent write-length detail. Before Linux commit
[`d31563b5f9bb601a805c4a1b491edf69ada79688`](https://github.com/torvalds/linux/commit/d31563b5f9bb601a805c4a1b491edf69ada79688),
`eventfd_write` rejected only lengths below eight and accepted longer writes
while consuming eight bytes. That commit changed the guard from
`count < sizeof(ucnt)` to `count != sizeof(ucnt)`, so kernels containing it
reject longer writes with `EINVAL`. Stage 6.1 blocking calls always use an
exact eight-byte transfer. Other synchronous v2 operations retain explicit
lengths and are judged by the running host trace, allowing both kernel
behaviors without hard-coded version detection.

Internal prior art is the Stage 5 eventfd resource model, strict adapter
metadata, pipe/eventfd campaign framework, and the existing QEMU artifact
injection path. They provide canonical-byte handling, exact attribution,
minimization, and failure persistence, but none owns actor or pending semantics.
The controlled worker stays eventfd-local until pipe supplies a second real
blocking adapter.

## Alternatives

| Alternative | Advantage | Blocking cost |
|---|---|---|
| Keep v1 only | No concurrency complexity | Cannot reach wait queues or prove wakeups |
| Add sleeps around ordinary operations | Small patch | Compares accidental scheduling and cannot prove the syscall entered |
| Add arbitrary actors/barriers now | General syntax | Guesses a public concurrency abstraction from one adapter and admits unstable interleavings |
| Replace v1 with a superset v2 | One apparent entry point | Breaks old adapter identity, digests, recovery, and the simple synchronous default |
| Add one controlled worker as a separate model | Minimal state machine, exact lifecycle, independent rollback | Maintains two explicit adapter identities |

The selected design is the last alternative. It pays a small dispatcher and
duplicate adapter-spec cost to keep compatibility and make the new risk
visible. Shared actor abstractions are deferred until a pipe blocking adapter
demonstrates the same semantics.

## Canonical v2 model

`eventfd.ops` v2 is strict UTF-8, newline terminated, and canonically rendered
under the same entry limits as v1. Every scenario has controller actor `0` and
worker actor `1`. Existing synchronous operation spellings are unchanged and
implicitly execute as actor 0. Four new spellings carry the only legal worker
identity explicitly:

```text
start-read 1 SLOT
start-write 1 SLOT VALUE
assert-pending 1
join 1
```

The worker read and write use an exact eight-byte valid harness-owned buffer.
No pointer, length, actor count, pending duration, completion timeout, thread
identifier, or scheduling choice is configurable in canonical input. This
keeps mutation from converting infrastructure timing into semantic input.

The lifecycle is:

```text
idle
  -> start-read/start-write
started
  -> assert-pending
pending-confirmed
  -> one or more same-event read/write triggers
  -> assert-pending after a statically insufficient trigger (optional)
triggered-completable
  -> join
idle
```

Only one worker call may be active. A scenario must end in `idle`. `join`
before a completing trigger, repeated `start`, wrong actor IDs, missing pending
confirmation, operations after a completing trigger other than `join`, and a
scenario ending with a worker are codec errors.

## Static blocking and completion proof

The v2 validator extends the existing event-object/open-file-description/fd
model; it does not predict observed syscall return values. It proves only the
conditions needed to admit a bounded blocking schedule.

For `start-read`, the slot must be a live eventfd whose shared description does
not have `O_NONBLOCK`, and its counter must be zero. For `start-write`, the slot
must be live and blocking, the value must be in `0..UINT64_MAX-1`, and adding
the value must exceed `UINT64_MAX-1`. A zero worker write is therefore never a
valid blocking start.

While the worker is active, the controller may execute only exact-eight-byte,
valid-pointer `read` or `write` operations on a live fd that resolves to the
same event object, plus `assert-pending` and `join`. In particular it may not:

- close, duplicate, replace, or create a descriptor;
- set `O_NONBLOCK` or `FD_CLOEXEC`;
- poll, query flags, use invalid pointers or invalid lengths; or
- touch a different eventfd, even if that operation would be synchronous.

This removes close/flag/lifetime races from Stage 6.1. Aliases remain valid
triggers because the resource model proves that they resolve to the same event
object and share the counter and `O_NONBLOCK` state.

After each controller trigger, the validator updates the conservative counter
state and asks whether the worker condition is now satisfiable. An empty-reader
worker becomes completable only when the counter is nonzero. A writer becomes
completable only when its value fits in the newly available counter space.
`assert-pending` after a trigger is accepted only when completion is still
impossible; `join` is accepted only after completion is possible. The validator
also applies the joined read/write transition so later synchronous operations
have a sound state.

These checks are input admissibility proofs, not the comparison oracle. The
host still supplies the joined result and resulting observable values.

## Harness ownership, synchronization, and timeouts

Each scenario owns one `pthread_t` and one worker record. Actor 0 creates and
joins it; actor 1 never outlives the scenario. The worker stores its immutable
operation before creation, publishes `entered` immediately before the raw
syscall with release ordering, stores the complete normalized result, then
publishes `completed` with release ordering. The controller observes those
states with acquire ordering. There is no shared mutable fd table access by the
worker after start; active-lifecycle validation prevents descriptor mutation.

`assert-pending` first requires the worker's `entered` publication, then uses a
monotonic-clock guard of exactly 50 ms. Completion observed before the guard
expires is a semantic mismatch. Remaining incomplete for the full guard emits
the canonical pending observation. A host candidate is accepted only after
three complete recordings produce byte-identical traces, which rejects inputs
whose apparent pending state depends on an unstable schedule.

Once a controller trigger makes completion possible, `join` waits for the
`completed` publication up to a hard monotonic deadline of 5 s, then calls
`pthread_join` only after completion is visible. Failure to complete is
`schedule-timeout`. `pthread_create`, `pthread_join`, atomic-clock support,
clock reads/sleeps, or other harness prerequisites failing is `harness-error`.
Neither class is rewritten as a syscall result. The QEMU outer timeout remains
an infrastructure safety net and must be longer than the harness deadline.

The 50 ms and 5 s constants do not enter canonical input or normalized trace.
They are fixed harness policy. Increasing them is not an accepted fix for a
semantic mismatch, missed wakeup, or unstable candidate.

## Trace v2 and comparison

Trace v2 records operations in canonical script order, not thread completion
order. It retains normalized logical slots and never records real fd numbers,
`pthread_t`, kernel task IDs, clock values, durations, or scheduler order.

- `start-*` records the accepted actor/operation identity without fabricating a
  syscall result;
- `assert-pending` records one exact pending observation after the guard;
- controller triggers record their ordinary syscall result, errno, value, and
  buffer effects using the existing normalization; and
- `join` records the worker syscall result and read value/buffer effects, or the
  distinct timeout/infrastructure class.

Host record must not write a successful trace when a statically blocking call
finishes before its pending checkpoint, when a required wakeup times out, or
when harness infrastructure fails. Compare reports an early completion or a
different joined syscall record with the existing semantic-mismatch marker.
It reports `schedule-timeout` and `harness-error` with dedicated markers so the
Python classifier and persisted failure category do not conflate them with an
errno difference or outer QEMU timeout.

Malformed input, wrong trace version, missing/extra trace entries, operation or
actor identity mismatch, truncated data, unknown outcome classes, and trailing
bytes fail closed.

## Fixed corpus

The checked-in v2 corpus contains separate deterministic scenarios for:

- blocking read on empty normal eventfd, woken by a write through the original
  fd and through a `dup` alias;
- blocking read on empty semaphore eventfd, woken through the original or an
  alias and returning one;
- blocking write on a full normal eventfd, released by a normal read;
- blocking write on a full semaphore eventfd, released by a semaphore read;
- a write value requiring two units of space: one semaphore read followed by
  `assert-pending`, then a second read and `join`;
- zero controller write preserving the pending empty read, followed by a
  positive write that wakes it; and
- alias-shared counter and `O_NONBLOCK`, where setup changes the shared status
  flag before the worker starts and the opposite alias triggers completion.

All starts and triggers use exact eight-byte valid buffers. Error precedence,
oversized write compatibility, invalid pointers, fd close, and zero-timeout poll
remain v1 synchronous responsibilities unless they are part of v2 setup before
the worker starts.

## Generator, mutation, and reduction

The v2 generator emits only complete lifecycles. It chooses from bounded story
templates and may vary normal/semaphore mode, original/alias start and trigger
slots, worker write values, and the number of statically insufficient semaphore
releases. It does not generate arbitrary actor schedules.

Structured mutation operates on lifecycle units as well as ordinary setup
operations. Repair may re-establish a required start/pending/trigger/join
sequence, but it may not add sleeps, switch to nonblocking behavior, or redirect
a trigger to a different event object. Every executable mutation changes the
canonical digest; malformed lifecycles receive a stable codec category before
host execution.

Reduction deletes whole scenarios, optional setup, aliases not used by the
lifecycle, insufficient trigger/checkpoint pairs, and simplifies values while
preserving the required mismatch operation or attributed regions. It never
synthesizes synchronization. Candidate documents must remain statically
blocking and completable and have a strictly smaller complexity key.

## Adapter, persistence, and replay isolation

`eventfd-blocking-v1` uses:

- adapter version 1, corpus format version 2, and its own generator version;
- campaign root `coverage/eventfd-blocking-oracle-fuzz`;
- target set `eventfd-blocking-v1`;
- the existing artifact filenames and QEMU case only as opaque values supplied
  by its independent `AdapterSpec`; and
- the common canonical-byte execution, strict persistence, attribution, and
  minimization machinery without actor/eventfd branches.

All common metadata already binds `adapter_id`, target-set ID, scenario digest,
trace digest, host ELF, and Starry ELF. v2 stores those fields with its new
identity. Loading a blocking directory through the simple adapter, a simple
directory through the blocking adapter, or an unknown model fails before
recovery or QEMU execution.

`fuzz.py` accepts only `--model simple-single` and `--model blocking`, with
`simple-single` as the default.
`replay.py` reads strict metadata first, dispatches by the exact adapter ID,
then validates the complete artifact with that spec. A user-provided model
cannot override artifact identity. Historical v1 roots are never scanned,
rewritten, or migrated by a blocking run.

The v2 host-record hook records into three temporary trace files and accepts
the candidate only if every run passes and all bytes match. This policy remains
adapter-owned. The common framework continues to see opaque canonical bytes and
one final trace path.

## Coverage boundary

The `eventfd-blocking-v1` target set contains all v1 eventfd syscall/file paths
plus the scheduler and poll-wait paths that own blocking and wakeup:

- `kernel/src/file/event.rs`;
- `kernel/src/syscall/fs/event.rs`;
- `kernel/src/syscall/fs/fd_ops.rs` and `kernel/src/syscall/fs/io.rs`;
- `kernel/src/syscall/io_mpx/mod.rs` and `poll.rs`;
- the `axtask` source that implements `poll_io`; and
- the `axpoll` source that implements `PollSet`.

The implementation must resolve the exact workspace-relative source paths and
tests must reject a missing target source. Region IDs remain source/line/column
and coverage state remains scoped by target set and exact Starry ELF digest.

## Difference policy

Any Linux/Starry difference first receives a deterministic raw-syscall
regression in the existing eventfd2 system case. The test must fail on the
observed implementation without sleeps that merely widen a race. Only then is
the production wait, wake, atomic, or syscall implementation fixed. Acceptance
reruns the same raw regression and original saved v2 scenario.

Changing expected traces, classifying an early completion as pending, widening
timeouts, lowering generator weight, redirecting coverage, or removing the
scenario is not a fix. Changes to waiting or atomic implementations additionally
require the affected crate's targeted clippy and `cargo xtask sync-lint`.

## Validation and acceptance gates

Unit and integration tests cover:

- v2 codec round trip and strict rejection of v1/wrong versions;
- wrong actor IDs, repeated starts, missing/early pending/join, unfinished
  scenarios, operations on another eventfd, close/dup/flag changes while active,
  nonblocking starts, starts that cannot block, and triggers that cannot finish;
- normal/semaphore read wakeups, full-counter writes, alias sharing, zero writes,
  phased releases, and the joined worker state transition;
- deterministic generation, every mutation kind, resource-valid reduction,
  origin preservation, and stable mismatch fingerprints;
- three-record host stability and rejection of one differing trace;
- wrong adapter, target set, digest, trace, host ELF, Starry ELF, unknown fields,
  recovery order, and complete simple/blocking persistence isolation; and
- dedicated early-completion, `schedule-timeout`, and `harness-error`
  classification without accepting an outer timeout as semantic evidence.

Runtime acceptance is serial:

1. common framework, eventfd v1, eventfd v2, and retained pipe Python tests;
2. `py_compile` for every affected Python module;
3. three byte-identical host recordings and host compare of fixed v2 corpus;
4. `cargo fmt` and `cargo xtask clippy --package starry-kernel`;
5. `qemu/system/syscall-test-eventfd2`;
6. explicit pipe, eventfd v1, and eventfd v2 x86_64 QEMU compares with no
   mismatch, panic, timeout, or missing coverage;
7. v2 `seed=42`, three batches, 16 candidates per batch, `max-qemu=32`, with at
   least one exactly attributed corpus entry;
8. one completed coverage minimization, including `already-minimal`;
9. affected wait/atomic crate clippy and `cargo xtask sync-lint` when production
   synchronization changes; and
10. `git diff --check`.

Physical-board, self-hosted, SMP-stress, performance, and default-CI validation
are not applicable to this bounded x86_64 QEMU stage.

## Rollback and Stage 6.2

Rollback removes the blocking model and stops creating new blocking state. The
simple model's commands, artifacts, and persistence remain untouched. Existing
blocking directories are archived or replayed with the matching implementation;
they are never reinterpreted as `eventfd-v1`.

Stage 6.2 will consider multiple waiters, fairness, pipe blocking and
`PIPE_BUF` atomicity, allowed-result sets, close/lifetime races, signal/EINTR,
and poll/epoll wakeup interleavings. Only after the pipe adapter establishes a
second controlled blocking implementation may actor/barrier/join machinery be
extracted into `scripts/linux_oracle/`.

## Explicit non-goals

Stage 6.1 does not include multiple workers, fairness, close races, fork,
signal delivery, `EINTR`, `SA_RESTART`, nonzero-timeout poll, epoll, vector I/O,
SMP stress, a syzkaller importer, or a unified short command frontend. It does
not compare natural scheduling order or absolute timing and does not make the
blocking model the default.
