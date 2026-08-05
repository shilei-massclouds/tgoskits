# Starry eventfd controlled blocking poll oracle

## Status and scope

This document is the independently reviewable high-risk design for Stage 6.3a.
It extends the eventfd Linux differential oracle with a controlled worker that
blocks in `poll(2)` and is woken by a readiness transition on one eventfd. The
implementation is test infrastructure only: it does not change StarryOS
production synchronization, wait queues, or syscall code.

The stage adds a new `eventfd-blocking-v2` adapter selected by
`fuzz.py --model blocking`. The default `simple-single` model remains
`eventfd-v1`. Historical `eventfd-blocking-v1` artifacts remain replayable by
their exact adapter ID but are no longer selected for new campaigns.

This is a high-risk feature under `feature-development.md` because it adds a
persisted corpus version, trace version, adapter identity, and controlled
concurrent syscall behavior. Design review therefore precedes implementation
and acceptance evidence.

## Problem, users, and success criteria

The synchronous eventfd adapter validates readiness only with zero-timeout
`poll(2)`. The first blocking adapter validates blocking `read(2)` and
`write(2)`, but it does not prove that an eventfd readiness change wakes a task
already sleeping in `poll(2)`. A missed registration/wakeup race, wrong
readiness threshold, or incorrect interaction with `O_NONBLOCK` can therefore
escape both adapters.

The direct users are StarryOS syscall and wait-queue maintainers. A concrete
scenario is:

1. create an eventfd with count zero;
2. start one worker executing raw `poll([{fd, POLLIN, 0}], 1, -1)`;
3. prove the worker remains pending through the controlled-worker guard;
4. write a positive value through the eventfd or an alias;
5. join the worker and compare its return value, `errno`, and `revents` with a
   trace recorded from the same canonical bytes on Linux.

The `POLLOUT` dual starts at count `UINT64_MAX - 1` and uses an exact valid
read to release counter space. Success requires both paths to block before the
trigger, wake after readiness becomes true, produce byte-stable host traces,
and compare successfully under StarryOS x86_64 QEMU. Existing v1/v2 bytes,
digests, traces, fingerprints, campaign state, and replay routing must remain
unchanged.

Without this stage, the oracle can show an eventfd is ready when sampled but
cannot distinguish correct blocking wakeup from a task that sleeps forever or
returns before readiness.

## Semantic references

The Linux behavior is fixed to commit
[`a2cf4ef33184df0ae9e1a2b05b550133dde1698c`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L111-L163).
Its `eventfd_poll` registers the wait queue before reading the count, reports
readable when count is positive, and reports writable only when count is less
than `UINT64_MAX - 1`. Its read and write paths wake the opposite readiness
class after publishing the counter transition
([read](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L202-L235),
[write](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L237-L273)).

[`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html) defines readiness
as an operation that will not block, a negative timeout as infinite, `POLLIN`
as data available to read, and `POLLOUT` as writing being possible. It also
states that `poll`/`ppoll` behavior is not affected by `O_NONBLOCK`.
[`eventfd(2)`](https://man7.org/linux/man-pages/man2/eventfd.2.html) defines the
64-bit counter, the maximum user-written count of `UINT64_MAX - 1`, ordinary
and semaphore reads, blocking overflow writes, and `poll` readiness. POSIX
[`poll()`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/poll.html)
is the portable contract; the pinned Linux implementation is authoritative for
Linux-specific eventfd thresholds and wakeups.

The Starry correspondence under test is:

- `sys_poll` -> `do_poll` in
  `os/StarryOS/kernel/src/syscall/io_mpx/poll.rs`;
- `FdPollSet` and `axpoll::PollSet` registration;
- `EventFd::poll`, `EventFd::register`, `EventFd::read`, and `EventFd::write` in
  `os/StarryOS/kernel/src/file/event.rs`; and
- `axtask::future::poll_io` for eventfd I/O used as controller triggers.

The stage observes these paths and does not modify them. If the new oracle
finds a difference, acceptance stops. The difference receives a separate
fail-first raw syscall regression and production fix rather than an expected
trace, timing, or model relaxation in this stage.

## Alternatives

| Option | Result |
|---|---|
| Keep zero-timeout sampling only | No concurrency or wakeup evidence; does not meet the problem. |
| Add `poll` to `eventfd-blocking-v1` corpus v2 | Changes frozen canonical bytes, parser surface, trace identity, generator, campaign, and replay meaning. Rejected. |
| Use sleeps to assume the worker blocked | Timing-dependent and cannot distinguish scheduling delay from registered sleep. Rejected. |
| Add a raw standalone QEMU case | Useful for a discovered regression, but does not provide Linux trace identity, mutation, reduction, attribution, or saved replay. |
| Add a distinct v3 adapter using the shared lifecycle and harness | Preserves old identities, reuses proven control machinery, and adds only the required behavior. Selected. |
| Generalize immediately to multiple fds, timeouts, signals, or epoll | Expands allowed outcomes and scheduling state without a current requirement. Deferred. |

## Versioned interface and compatibility boundary

Canonical corpus version 3 adds one operation:

```text
start-poll 1 <slot> <events>
```

`actor` is exactly `1`, `slot` is one live logical eventfd descriptor, and
`events` is numeric `POLLIN` (`1`) or `POLLOUT` (`4`). The harness always calls
raw `SYS_poll` with one stable `struct pollfd`, `nfds = 1`, and timeout `-1`.
The timeout and fd count are not corpus parameters.

The adapter contract is frozen as:

| Field | Value |
|---|---|
| adapter ID | `eventfd-blocking-v2` |
| adapter version | `2` |
| corpus version | `3` |
| trace magic | `EVFDORC3` |
| coverage target | `eventfd-blocking-v2` |
| campaign root | `coverage/eventfd-blocking-v2-oracle-fuzz` |
| artifact names | `eventfd.ops`, `linux.trace`, `eventfd-linux-oracle` |
| QEMU case | existing `qemu/eventfd-linux-oracle` |

The generator has an independent version and the new checked corpus is
`eventfd-blocking-poll.ops`. `--model blocking` selects v2 for new work;
omitting `--model` still selects `eventfd-v1`. Replay reads strict metadata and
routes `eventfd-v1`, `eventfd-blocking-v1`, and `eventfd-blocking-v2` by exact
adapter ID before loading the artifact.

The C parser reads only corpus versions 1 through 3, then validates each
version against a disjoint operation set. `EVFDORC1`, `EVFDORC2`, and
`EVFDORC3` are selected only by the matching corpus version and cannot be
cross-read. Existing operation and fingerprint numbers remain fixed;
`start-poll` appends ID 18. A v3 join trace record has kind `join`, the raw
`poll` return value and `errno`, and exactly two bytes containing the returned
`revents`. No existing record layout changes.

Before implementation, the checked v1 and v2 corpora, old host executable, and
three traces for each are retained outside the worktree. Upgrade begins only
after the old blocking campaign has no pending or running attribution or
minimization task. Old campaign roots, failure artifacts, digests, and metadata
are never migrated or rewritten.

## Controlled resource model

The v3 model reuses `SingleWorkerLifecycle[StartPoll, event_id]`. Its state is
owned by one `ResourceState` per scenario; the existing simple eventfd model
continues to own descriptor, open-file-description, alias, flag, semaphore,
and counter state.

The worker state machine is:

```text
absent -> started -> pending-confirmed -> completable -> joined -> absent
```

`start-poll` is accepted only when:

- the target slot is live and resolves to an eventfd;
- `POLLIN` targets count zero;
- `POLLOUT` targets count exactly `UINT64_MAX - 1`; and
- no worker is active.

Unlike blocking read/write, `O_NONBLOCK` is allowed because it does not affect
`poll`. `EFD_SEMAPHORE` changes read consumption but not the two start
readiness predicates.

After `assert-pending`, the controller may run only an exact eight-byte valid
read or write through the same eventfd or an alias. Invalid pointers, short or
long buffers, `UINT64_MAX` writes, other operations, other eventfds, fd/flag
changes, and close/lifetime races are rejected by the codec. The simple model
executes the trigger, then readiness is recomputed:

- `POLLIN` becomes completable when count is greater than zero;
- `POLLOUT` becomes completable when count is less than
  `UINT64_MAX - 1`.

A zero-value write is a valid non-completing `POLLIN` trigger, so another
`assert-pending` may follow. Once readiness is true, `join` must immediately
follow; further triggers or pending assertions are rejected. Join never
consumes or changes eventfd count because `poll` only observes readiness. A
scenario ending with an active worker, joining before readiness, triggering
before the pending guard, or starting initially ready keeps the existing
`actor-lifecycle`/`blocking-proof` categories and shared lifecycle text.

The codec therefore accepts only schedules that are statically proven to block
first and to complete before join. Natural scheduling order and elapsed time
are not semantic inputs.

## Generator, mutation, and reduction

The v3 generator emits bounded complete stories for:

- ordinary and `EFD_SEMAPHORE` eventfds;
- direct worker/trigger descriptors and aliases;
- targets with and without `O_NONBLOCK`;
- `POLLIN` wakeup by a positive write;
- `POLLIN` remaining pending after a zero write and then waking;
- `POLLOUT` wakeup after an ordinary or semaphore read releases space.

All stories begin in a statically non-ready state, include at least one
`assert-pending`, reach a ready state through a same-event exact trigger, and
join. Random generation never emits arbitrary schedules.

Mutation remains structured over complete lifecycle stories. Each mutation
kind must either produce different canonical executable bytes or a typed
malformed result; it cannot repair a case with sleeps, a ready start, or a
different resource. Reduction may delete whole scenarios and optional setup,
simplify safe parameters, or remove unused aliases. Every yielded candidate is
revalidated by the v3 resource model, remains strictly smaller, preserves the
required origin when requested, and therefore cannot lose the pending guard,
become initially ready, or become uncompletable.

## Host and guest execution

The existing eventfd C harness gains `WORKER_POLL` and one `struct pollfd` in
`worker_state`. The structure is initialized completely before
`controlled_worker_start` and remains stable until join. The worker publishes
`entered`, invokes raw `SYS_poll`, records the syscall result, `errno`, and the
two-byte native `revents`, then publishes `completed`.

The shared `controlled_worker` remains the only owner of pthread creation,
entered/completed atomics, the pending guard, monotonic deadline, wait, and
join. Its status mapping is unchanged:

- early completion is a semantic mismatch at `assert-pending` in compare mode
  and rejects a host recording;
- completion timeout emits the existing schedule-timeout marker; and
- pthread, clock, or sleep failures emit the existing harness-error marker.

Record and compare execute identical canonical v3 bytes. The v2 adapter-owned
stable recorder policy is reused: three independently written host traces must
all pass and be byte-identical before a candidate is admitted. The existing
QEMU case receives the host executable, v3 corpus, and trace only through the
existing absolute artifact-directory environment variable; discovery,
runtime configuration, regexes, and image injection are unchanged.

## Coverage, persistence, and recovery

`eventfd-blocking-v2` uses an independent coverage target containing eventfd
read/write/poll readiness, syscall `poll`, `axpoll`, and `axtask` wait paths.
Coverage state is scoped by target ID and exact Starry ELF digest. Its campaign
root is never shared with v1.

The common framework continues to treat scenario bytes and traces as opaque.
It binds adapter ID/version, corpus version, target ID, canonical digest, trace
digest, host ELF, and Starry ELF in strict metadata. Wrong IDs, versions,
digests, unknown fields, or cross-adapter loads fail before host or QEMU
execution.

Acceptance runs a bounded new v2 campaign, then a recovery-only run with
`--batches 0 --max-qemu 64`. Completion requires no pending attribution or
minimization task. The v1 root is checked only for replay compatibility and is
not used to start a new batch.

## Validation plan

Fail-first unit tests are added before implementation. Python coverage includes:

- v3 round trip, canonical digest, strict v1/v2/v3 rejection boundaries, and
  invalid actor, slot, or event masks;
- initial-ready rejection and acceptance of `O_NONBLOCK`;
- `POLLIN`, `POLLOUT`, alias, semaphore, zero-write pending, readiness after a
  trigger, successful join, unfinished scenarios, and exact lifecycle errors;
- deterministic fixed seeds, every mutation kind, resource-aware reduction,
  and origin preservation;
- checked corpus coverage and canonical bytes;
- old/new adapter routing, strict replay isolation, campaign roots, target
  identities, failure fingerprints, and CLI selection; and
- three-record stability plus typed early-completion, completion-timeout, and
  helper-error classification.

Host C tests record and compare controlled pending `POLLIN`/write/join and
pending `POLLOUT`/read/join paths, reject immediate completion during host
recording, and preserve timeout/error markers. The checked v3 corpus must
produce three identical traces and pass host self-compare.

Serial runtime acceptance is:

1. common, all eventfd, and retained pipe Python tests;
2. `py_compile` for affected Python modules;
3. common controlled-worker tests and static eventfd host build with warnings
   as errors;
4. byte comparison of preserved v1/v2 corpora, digests, three traces, and old
   failure fingerprint;
5. fixed v3 checked corpus and generator seed bytes/digests, three stable host
   traces, and host self-compare;
6. `cargo fmt` and `cargo xtask clippy --package starry-kernel`;
7. raw `qemu/system/syscall-test-eventfd2`;
8. eventfd simple QEMU compare, v1 blocking artifact injection, and v3 poll
   artifact injection through the existing case;
9. bounded `eventfd-blocking-v2` campaign and recovery-only run; and
10. `git diff --check`.

All QEMU runs are serial in one checkout. Because the design does not change
production synchronization, `cargo xtask sync-lint` is not applicable. If a
production wait/atomic/syscall path changes, Stage 6.3a stops and the expanded
scope is redesigned separately.

## Syscall compatibility map

| Syscall | Conclusion | Standard | Basis |
|---|---|---|---|
| `poll` | Differential behavior added; no production semantics changed | [`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html), [POSIX `poll()`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/poll.html), [pinned Linux `eventfd_poll`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L111-L163) | One fd, `POLLIN` or `POLLOUT`, timeout `-1`; compares return value, `errno`, and `revents`. |
| `eventfd` | Setup behavior retained; no production semantics changed | [`eventfd(2)`](https://man7.org/linux/man-pages/man2/eventfd.2.html), [pinned Linux eventfd implementation](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L111-L273) | Creates the counter used to prove initial non-readiness and controller readiness transitions. |
| `eventfd2` | Setup/flag behavior retained; no production semantics changed | [`eventfd(2)`](https://man7.org/linux/man-pages/man2/eventfd.2.html), [pinned Linux eventfd implementation](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L111-L273) | Adds `EFD_SEMAPHORE` and `EFD_NONBLOCK` setup while preserving poll semantics. |
| `read` | Existing controller operation reused; no production semantics changed | [`eventfd(2)`](https://man7.org/linux/man-pages/man2/eventfd.2.html), [pinned Linux `eventfd_read`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L202-L235) | Exact valid eight-byte read makes a full counter writable and wakes `POLLOUT`. |
| `write` | Existing controller operation reused; no production semantics changed | [`eventfd(2)`](https://man7.org/linux/man-pages/man2/eventfd.2.html), [pinned Linux `eventfd_write`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L237-L273) | Exact valid eight-byte positive write makes an empty counter readable and wakes `POLLIN`; zero preserves pending. |

Signals, restart, credential, namespace, compat layout, and close races are
unchanged and excluded from generated inputs. The raw `struct pollfd` layout is
the existing x86_64 C ABI used by the harness and target case.

## Rollback and non-goals

Rollback stops selecting `eventfd-blocking-v2`, archives its independent
campaign root, and removes its v3-only modules/parser branch. The default model
and historical v1/v2 artifacts need no migration. Saved v3 failures remain
replayable only with the matching implementation and are never reinterpreted.

Stage 6.3a excludes pipe blocking poll (Stage 6.3b), epoll and `EPOLLET`, more
than one `pollfd`, more than one waiter, allowed-result sets, fairness,
nonnegative timeout, `ppoll`, signal/`EINTR`, close/lifetime races,
cross-architecture behavior, and default CI. It also does not claim performance
or scheduling fairness.

## Acceptance evidence

Acceptance evidence is added only after implementation and all applicable
gates complete. A Linux/Starry difference blocks this section and is handled as
a separate regression and production fix.
