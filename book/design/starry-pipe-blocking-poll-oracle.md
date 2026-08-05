# Starry pipe controlled blocking poll oracle

## Status and scope

This document is the independently reviewable high-risk design for Stage 6.3b
of the Starry Linux differential-testing roadmap. It extends the pipe Linux
oracle with one controlled worker that blocks in `poll(2)` and is woken by one
pipe readiness transition. The implementation is test infrastructure only: it
does not change StarryOS production pipe, wait-queue, synchronization, or
syscall code.

The stage adds a new `pipe-blocking-v2` adapter selected by
`fuzz.py --model blocking`. The default `simple-single` model remains
`pipe-v4`. Historical `pipe-blocking-v1` artifacts remain replayable by their
exact adapter ID but are no longer selected for new blocking campaigns.

This is a high-risk feature under `feature-development.md` because it adds a
persisted corpus version, trace version, adapter identity, and controlled
concurrent syscall behavior. Design review therefore precedes implementation
and acceptance evidence.

## Problem, users, and success criteria

The synchronous pipe adapter samples readiness only with timeout-zero
`poll(2)`. The first blocking pipe adapter proves read/write sleep and wakeup,
but it does not prove that a pipe state change wakes a task already registered
and sleeping in `poll(2)`. A lost registration/wakeup race, byte-count rather
than pipe-buffer-slot readiness check, missed hangup, or incorrect interaction
with `O_NONBLOCK` can therefore escape both accepted adapters.

The direct users are StarryOS pipe, syscall, scheduler, and wait-queue
maintainers. Stage 6.3b succeeds when the same canonical scenarios prove on
Linux and StarryOS that:

1. an empty read end blocks for `POLLIN`, remains pending through the guard,
   and wakes after a positive write;
2. a full write end blocks for `POLLOUT`, remains pending after a partial read
   that keeps the pipe-buffer slot occupied, and wakes only when the complete
   slot is released;
3. an empty read end blocks for `POLLIN` and returns `POLLHUP` after the last
   writer is closed;
4. direct descriptors, aliases, and targets carrying `O_NONBLOCK` retain the
   same controlled semantics; and
5. all historical v4/v5 bytes, digests, traces, fingerprints, persistence,
   and exact-ID replay behavior remain unchanged.

Each successful join compares the raw `poll` return value, exact `errno`, and
two-byte `revents`. The checked v6 corpus and fixed generator seeds must produce
byte-stable host traces, compare successfully in StarryOS x86_64 QEMU, and
leave no pending attribution or minimization work after bounded recovery.

Without this stage, the oracle can show pipe readiness when sampled but cannot
distinguish a correct sleeping poll waiter from one that returns prematurely
or never wakes.

## Semantic references and correspondence

Linux behavior is fixed to commit
[`a2cf4ef33184df0ae9e1a2b05b550133dde1698c`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/pipe.c#L755-L805).
Its `pipe_poll` registers the applicable read or write wait queue before
sampling pipe state, reports readable only when a buffer is present, reports
writable only when a complete pipe-buffer slot is free, reports read-end
hangup when writers have disappeared, and reports write-end error when readers
have disappeared. Stage 6.3b covers the first three results and deliberately
excludes the write-end error case.

The same pinned implementation publishes the controller transitions used by
the model:

- [`anon_pipe_read`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/pipe.c#L360-L495)
  wakes writers only after a full buffer is removed and a formerly full pipe
  becomes non-full;
- [`anon_pipe_write`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/pipe.c#L522-L697)
  treats a zero-length write as success without adding data and wakes poll
  readers after committed data; and
- [`pipe_release`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/pipe.c#L823-L843)
  updates endpoint counts and wakes both wait queues when the last endpoint of
  one direction disappears.

[`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html) defines readiness
as an operation that will not block, negative timeout as infinite, `POLLIN` as
data available, `POLLOUT` as writing being possible, and `POLLHUP` as peer
closure. It also states that `poll` and `ppoll` behavior is not affected by
`O_NONBLOCK`. [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html)
defines empty/full blocking, endpoint lifetime, EOF, and pipe capacity. POSIX
[`poll()`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/poll.html)
is the portable interface contract; the pinned Linux implementation is
authoritative for pipe-buffer-slot and Linux hangup wake behavior.

The Starry correspondence under test is:

- `sys_poll` and `do_poll` in
  `os/StarryOS/kernel/src/syscall/io_mpx/poll.rs`;
- `Pipe::poll`, `Pipe::register`, read/write transitions, and endpoint `Drop`
  in `os/StarryOS/kernel/src/file/pipe.rs`;
- `PollSet` registration and wakeup in `components/axpoll/src/lib.rs`; and
- the `axtask` poll/wait path reached by the poll syscall.

The stage only observes these production paths. If the new oracle finds a
Linux/Starry difference, Stage 6.3b acceptance stops. The difference receives
a separate fail-first raw-syscall regression and production fix rather than an
expected trace change, wider timing guard, or relaxed resource model.

Repository history through Stage 6.3a, current pipe/eventfd adapter code, and a
targeted public issue/PR search were checked on 2026-08-05. The accepted
eventfd blocking-poll v2 adapter is the direct concurrency prior art, and the
accepted pipe blocking v1 adapter is the direct resource-model prior art. No
competing pipe blocking-poll oracle was found.

## Alternatives

| Option | Result |
|---|---|
| Keep timeout-zero readiness sampling | Supplies no concurrency or wakeup evidence; does not solve the problem. |
| Add `start-poll` to corpus v5 | Changes frozen bytes, parser surface, trace identity, generator, campaign, and replay meaning. Rejected. |
| Infer blocking with sleeps | Cannot distinguish scheduling delay from completed wait registration. Rejected. |
| Add a standalone raw QEMU test | Appropriate after a discovered production defect, but lacks Linux trace identity, mutation, reduction, attribution, and saved replay. |
| Generalize now to arbitrary poll arrays, workers, timeouts, signals, or epoll | Introduces allowed results and uncontrolled interleavings without a current requirement. Deferred. |
| Add a distinct v6 adapter using the shared lifecycle and harness | Preserves historical identities and adds the smallest complete wakeup slice. Selected. |

## Versioned interface and compatibility boundary

Canonical corpus version 6 adds one operation:

```text
start-poll 1 <slot> <events>
```

`actor` is exactly `1`, `slot` is one live logical pipe descriptor, and
`events` is numeric `POLLIN` (`1`) or `POLLOUT` (`4`). The C harness always
calls raw `SYS_poll` with one stable `struct pollfd`, `nfds = 1`, and timeout
`-1`. Descriptor count and timeout are not corpus parameters.

The adapter contract is frozen as:

| Field | Value |
|---|---|
| adapter ID | `pipe-blocking-v2` |
| adapter version | `2` |
| corpus version | `6` |
| trace magic | `PIPEORC1` |
| trace version | `6` |
| coverage target | `pipe-blocking-v2` |
| campaign root | `coverage/pipe-blocking-v2-oracle-fuzz` |
| artifact names | `pipe.ops`, `linux.trace`, `pipe-linux-oracle` |
| QEMU case | existing `qemu/pipe-linux-oracle` |

The independent checked corpus is `pipe-blocking-poll.ops`.
`--model blocking` selects v2 for new work; omitting `--model` still selects
`pipe-v4`. Replay reads strict metadata and routes `pipe-v4`,
`pipe-blocking-v1`, and `pipe-blocking-v2` by exact adapter ID before loading
any artifact.

The C parser accepts only corpus versions 1 through 6 and validates each
version against its disjoint operation set. All pipe trace versions retain the
existing `PIPEORC1` magic and are isolated by the exact header version and
corpus digest. Existing operation and fingerprint numbers remain fixed:
`join` remains ID 24 and `start-poll` appends ID 25.

`start-poll` records its actor and immutable parameters without fabricating a
syscall result. `assert-pending` retains the existing scalar pending record. A
v6 `join` record retains kind `join`, stores the raw `poll` return value and
`errno`, and stores exactly two native bytes of returned `revents` in the
existing data field. No historical record layout changes.

Before implementation, the checked v4 corpus and v5 read/write corpora, old
host executable, canonical digests, three host traces per corpus, and the
existing failure fingerprint are retained outside the worktree. Upgrade begins
only after the old blocking campaign has no pending or running attribution or
minimization task. Historical campaign roots and metadata are never migrated
or rewritten.

## Controlled resource model

The v6 model reuses `SingleWorkerLifecycle[StartPoll, pipe_object]`. One
scenario-local resource state remains the sole owner of logical slots,
endpoint direction, pipe-object and open-file-description identity, aliases,
shared status flags, pipe-buffer records, capacity slots, and endpoint counts.

The worker lifecycle remains:

```text
absent -> started -> pending-confirmed -> completable -> joined -> absent
```

`start-poll` is accepted only when no worker is active and the target is:

- a live read endpoint with an empty pipe and at least one writer for
  `POLLIN`; or
- a live write endpoint with no complete free pipe-buffer slot and at least
  one reader for `POLLOUT`.

The target open file description may carry `O_NONBLOCK`, because that flag
does not change `poll`. The initial-state proof rejects wrong endpoint
direction, a ready pipe, an invalid slot or mask, a missing peer, and multiple
workers.

After `assert-pending`, the controller may act only through a valid descriptor
or alias of the same pipe:

- a valid positive or zero-length write while a `POLLIN` waiter is pending;
- closing the final live writer while an empty `POLLIN` waiter is pending; or
- a valid positive read while a `POLLOUT` waiter is pending.

Duplication, flag or capacity changes, vector I/O, timeout-zero poll, another
pipe, wrong-direction I/O, invalid pointers, and general close competition are
rejected while the worker is active. The last-reader close path is excluded so
v6 never creates write-end `POLLERR`, `SIGPIPE`, or `EPIPE`.

The controller transition is applied before readiness is recomputed:

- positive data makes `POLLIN` completable;
- a zero-length write leaves `POLLIN` pending;
- final-writer close on an empty pipe makes the read end completable with
  `POLLHUP`; and
- a read makes `POLLOUT` completable only when it removes the complete front
  pipe-buffer record and frees a slot.

Consequently a partial read that leaves bytes in the record must be followed
by another `assert-pending`; freeing the remainder permits join. Once the
worker is completable, `join` must immediately follow. Poll join observes
readiness but consumes no bytes and creates no pipe record. A scenario ending
with an active worker, triggering before the pending guard, joining before a
proof of readiness, or starting initially ready retains the shared
`actor-lifecycle` and `blocking-proof` error categories.

The model is an admission proof for a bounded schedule, not an expected-result
implementation. Linux still supplies the return value, errno, and `revents`
used for comparison.

## Generator, mutation, and reduction

The v6 generator emits complete bounded stories covering:

- direct worker/controller descriptors and aliases;
- target open file descriptions with and without `O_NONBLOCK`;
- `POLLIN` wakeup by a positive write;
- a zero-length write, a second pending proof, and a positive wakeup;
- empty-pipe final-writer close and `POLLHUP`;
- `POLLOUT` wakeup after a full slot is released; and
- a partial read, a second pending proof, and final slot release.

Every story begins non-ready, proves pending at least once, targets only the
same pipe, reaches a statically completable state, and joins. Random generation
never emits arbitrary actor schedules.

Mutation remains structured over complete lifecycle stories. Every mutation
kind must either produce different canonical executable bytes or a typed
malformed result. Reduction may delete whole scenarios and optional setup,
simplify safe values, remove unused aliases, or remove a redundant pending-
preserving trigger. Every yielded candidate is revalidated, strictly smaller,
and origin-preserving when required; it cannot lose the pending guard, become
initially ready, target another pipe, or become uncompletable.

## Host and guest execution

The existing pipe C harness gains `WORKER_POLL` and one `struct pollfd` in
`worker_state`. Actor 0 initializes the complete structure before
`controlled_worker_start`; the descriptor and pollfd remain stable until
join. The worker publishes `entered`, invokes raw `SYS_poll`, records result,
`errno`, and the two-byte `revents`, then publishes `completed`.

The shared `controlled_worker` remains the only owner of pthread creation,
entered/completed atomics, the pending guard, monotonic deadline, wait, and
join. Its classifications remain unchanged:

- early completion is a semantic mismatch in compare mode and rejects a host
  recording;
- completion timeout emits the schedule-timeout marker; and
- pthread, clock, sleep, or join failure emits the harness-error marker.

Record and compare execute identical canonical v6 bytes. The v2 adapter uses
the stable recorder policy requiring three independent successful and byte-
identical host traces. The existing QEMU case receives only the host ELF, v6
corpus, and trace through `STARRY_PIPE_ORACLE_ARTIFACT_DIR`; discovery,
configuration, regexes, and rootfs injection remain unchanged.

## Coverage, persistence, and recovery

`pipe-blocking-v2` owns an independent coverage target containing pipe
read/write/poll state, the poll syscall, `axpoll`, and task wait/wakeup paths.
Coverage is scoped by target ID and exact Starry ELF digest. Its campaign root
is never shared with v1.

The common framework treats scenario bytes and traces as opaque. Metadata
binds adapter ID/version, corpus version, coverage target, canonical digest,
trace digest, host ELF, and Starry ELF. Unknown fields, wrong IDs or versions,
digest changes, and cross-adapter loads fail before host or QEMU execution.

Acceptance runs a bounded v2 campaign, then recovery-only
`--batches 0 --max-qemu 64`. Completion requires no pending attribution or
minimization task. The historical v1 root is inspected and replayed but is not
used to start a new batch.

## Validation plan

Fail-first Python tests precede implementation and cover:

- v6 round trip, fixed canonical digest, and strict v1 through v6 rejection
  boundaries;
- invalid actor, slot, endpoint, and event mask;
- initial-ready rejection and `O_NONBLOCK` acceptance;
- ordinary `POLLIN`, `POLLOUT`, and `POLLHUP` completion, aliases, zero-write
  pending, phased slot release, unfinished scenarios, and lifecycle errors;
- deterministic fixed seeds, every mutation kind, resource-aware reduction,
  and origin preservation;
- checked corpus coverage and canonical bytes;
- exact adapter routing, v1/v2 persistence isolation, campaign roots, target
  identities, failure fingerprints, and CLI selection; and
- stable host recording plus typed early-completion, completion-timeout, and
  helper-error classification.

Host C tests cover pending `POLLIN`/write/join, zero-write non-completion,
final-writer `POLLHUP`, pending `POLLOUT` with partial then complete slot
release, initial immediate completion rejection, completion timeout, and
typed helper error. Each valid checked path records identically three times
and passes host self-compare.

Serial acceptance is:

1. common, all pipe, and all eventfd Python tests;
2. `py_compile` for every affected Python module;
3. common controlled-worker tests and a warnings-as-errors static pipe harness
   build;
4. byte comparison of the retained v4/v5 corpora, digests, three traces, and
   old failure fingerprint;
5. fixed v6 checked corpus and generator seed bytes/digests, three stable host
   traces, and host self-compare;
6. `cargo fmt` and `cargo xtask clippy --package starry-kernel`;
7. raw `qemu/system/syscall-test-pipe`;
8. pipe simple QEMU compare, v1 blocking artifact replay, and v6 artifact
   injection through the existing pipe case;
9. bounded `pipe-blocking-v2` campaign and recovery-only run; and
10. `git diff --check`.

All QEMU runs are serial in one checkout. Because the implementation does not
change production synchronization, `cargo xtask sync-lint` is not applicable.
If any production wait, atomic, pipe, or syscall path changes, Stage 6.3b stops
and the expanded scope is redesigned separately.

## Syscall compatibility map

| Syscall | Conclusion | Standard | Basis |
|---|---|---|---|
| `poll` | Differential behavior added; no production semantics changed | [`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html), [POSIX `poll()`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/poll.html), [pinned Linux `pipe_poll`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/pipe.c#L755-L805) | One pipe fd, `POLLIN` or `POLLOUT`, timeout `-1`; compares return value, errno, and `revents`, including unsolicited `POLLHUP`. |
| `pipe2` | Existing setup behavior reused; no production semantics changed | [`pipe2(2)`](https://man7.org/linux/man-pages/man2/pipe.2.html), [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html) | Creates the two endpoints and optional `O_NONBLOCK` state used by controlled scenarios. |
| `read` | Existing controller operation reused; no production semantics changed | [`read(2)`](https://man7.org/linux/man-pages/man2/read.2.html), [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html), [pinned Linux read path](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/pipe.c#L360-L495) | A complete record release makes a full pipe writable; a partial read preserves the occupied slot. |
| `write` | Existing controller operation reused; no production semantics changed | [`write(2)`](https://man7.org/linux/man-pages/man2/write.2.html), [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html), [pinned Linux write path](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/pipe.c#L522-L697) | Positive data wakes `POLLIN`; zero length succeeds without changing readiness. |
| `close` | Restricted final-writer controller operation reused; no production semantics changed | [`close(2)`](https://man7.org/linux/man-pages/man2/close.2.html), [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html), [pinned Linux release path](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/pipe.c#L823-L843) | Closing the final writer wakes an empty read-end poll waiter with `POLLHUP`; final-reader close is excluded. |
| `dup` | Existing alias setup reused; no production semantics changed | [`dup(2)`](https://man7.org/linux/man-pages/man2/dup.2.html) | Proves worker and controller descriptors can refer to the same pipe through aliases. |
| `fcntl` | Existing setup/query behavior reused; no production semantics changed | [`fcntl(2)`](https://man7.org/linux/man-pages/man2/fcntl.2.html), [`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html) | Sets pipe capacity and shared `O_NONBLOCK`; neither becomes an active-lifecycle race. |

Signals, restart, credentials, namespaces, compat layout, write-end error, and
general close races are unchanged and excluded. The raw `struct pollfd` layout
is the existing x86_64 C ABI already used by the harness.

## Rollback and non-goals

Rollback stops selecting `pipe-blocking-v2`, archives its independent campaign
root, and removes its v6-only modules/parser branch. The default and historical
adapters need no migration. Saved v6 failures remain self-identifying and fail
closed if the matching adapter is unavailable.

Stage 6.3b excludes write-end `POLLERR`, `SIGPIPE`/`EPIPE`, final-reader close,
general close/lifetime races, more than one `pollfd`, more than one worker,
multiple waiters, fairness, allowed-result sets, nonnegative timeout, signals
and `EINTR`, `ppoll`, `epoll`, cross-architecture behavior, and default CI. It
does not claim performance or scheduling fairness. Those concerns remain
independent later Stage 6 work; Stage 7 continues evidence- and priority-driven
oracle expansion after the bounded concurrency slices.
