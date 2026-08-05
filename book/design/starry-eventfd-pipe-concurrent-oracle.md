# Stage 6.4 eventfd and pipe concurrent oracle

## Status, scope, and non-goals

This is the independently reviewable resource and syscall design for the two
final Stage 6 adapters:

| Resource | Adapter | Corpus/trace | Trace identity | Coverage target | Campaign root |
|---|---|---:|---|---|---|
| eventfd | `eventfd-concurrent-v1` | 4 | `EVFDORC4`, version 4 | `eventfd-concurrent-v1` | `coverage/eventfd-concurrent-v1-oracle-fuzz` |
| pipe | `pipe-concurrent-v1` | 7 | `PIPEORC1`, version 7 | `pipe-concurrent-v1` | `coverage/pipe-concurrent-v1-oracle-fuzz` |

`--model concurrent` is explicit. `simple-single`, `blocking`, all historical
adapter IDs, artifact names, and QEMU case names retain their current meaning.
Network EPOLLET, nested epoll, fork/exec stories, arbitrary signals, and
arbitrary event masks are not goals. Closing in one thread the same numeric fd
currently monitored by another thread's `poll` is a 100-run Linux-specific
diagnostic, not a semantic gate.

The feature is high risk because it introduces a second worker, signals,
timeouts, epoll state, OFD lifetime, and persisted formats. The common
allowed-outcome protocol is specified separately in
`starry-linux-oracle-concurrent-outcomes.md`.

## Problem and success criteria

The accepted adapters show one waiter wakes, but cannot detect wake-one versus
wake-all mistakes, lost second wakeups, signal restart errors, timeout early
return, epoll ready-list bugs, or alias/OFD lifetime errors. Direct users are
Starry file, signal, task, and I/O-multiplexing maintainers.

Success requires bounded checked stories proving:

- two eventfd or pipe waiters both make progress after sufficient triggers;
- all observed scheduler orders belong to a converged Linux scenario set;
- `SIGUSR1`, `EINTR`, `SA_RESTART`, and temporary signal masks match Linux;
- immediate, finite, readiness-before-expiry, and infinite waits are distinct;
- epoll LT, ET, ONESHOT, EXCLUSIVE, multi-fd, truncation, and rotation behave
  like Linux; and
- alias close, final peer close, blocked-I/O OFD references, `POLLERR`, EOF,
  `SIGPIPE`, and `EPIPE` preserve Linux lifetime semantics.

Fairness means no lost wakeup and bounded progress. It never requires actor 1
or actor 2 to win first.

## Semantic baseline

The execution authority is host Linux `5.15.0-186-generic` on x86_64, with
the exact kernel release stored in every trace. Public contracts are:

- [`eventfd(2)`](https://man7.org/linux/man-pages/man2/eventfd.2.html) for the
  counter, semaphore reads, blocking overflow writes, and readiness;
- [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html) for EOF,
  `PIPE_BUF` atomicity, `SIGPIPE`/`EPIPE`, and capacity;
- [`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html) for timeout,
  `POLLHUP`, `POLLERR`, `EINTR`, and atomic `ppoll` masks;
- [`signal(7)`](https://man7.org/linux/man-pages/man7/signal.7.html) and
  [`sigaction(2)`](https://man7.org/linux/man-pages/man2/sigaction.2.html) for
  restart classes;
- [`epoll(7)`](https://man7.org/linux/man-pages/man7/epoll.7.html),
  [`epoll_ctl(2)`](https://man7.org/linux/man-pages/man2/epoll_ctl.2.html), and
  [`epoll_wait(2)`](https://man7.org/linux/man-pages/man2/epoll_wait.2.html)
  for interest/ready lists, OFD identity, LT/ET/ONESHOT/EXCLUSIVE, timeout,
  atomic masks, and successive round-robin; and
- [`close(2)`](https://man7.org/linux/man-pages/man2/close.2.html) for the OFD
  reference held by an already blocked I/O call after another thread closes
  the descriptor.

The pinned Linux 5.15 source paths used during implementation are
`fs/eventfd.c`, `fs/pipe.c`, `fs/eventpoll.c`, `fs/select.c`, and
`kernel/signal.c`. Starry paths under test are the corresponding eventfd,
pipe, signal, `io_mpx`, `axpoll::PollSet`, and task wait/wakeup paths. A
production edit expands the change into a separate regression-and-fix commit.

## Canonical operations and bounds

Versions 4 and 7 reuse their resource's synchronous and blocking vocabulary
and append these operations:

```text
start-read <actor> <slot> <length>
start-write <actor> <slot> <value-or-length>
start-poll <actor> <slot> <events> <timeout-ms>
start-ppoll <actor> <slot> <events> <timeout-ns|null> <empty|usr1>
signal-config SIGUSR1 <0|SA_RESTART>
send-signal <actor> SIGUSR1
assert-signal-handled <actor> <count>
epoll-create <slot> <0|CLOEXEC>
epoll-ctl <epoll-slot> <add|mod|del> <target-slot> <events> <data>
start-epoll-wait <actor> <epoll-slot> <maxevents> <timeout-ms>
start-epoll-pwait <actor> <epoll-slot> <maxevents> <timeout-ms> <empty|usr1>
start-epoll-pwait2 <actor> <epoll-slot> <maxevents> <timeout-ns|null> <empty|usr1>
assert-pending <actor>
assert-all-pending
join <actor>
join-set <actor> <actor>
```

There are at most two workers, four returned epoll events, 16 logical slots,
and 64 operations per scenario. Millisecond timeouts are `-1` or `0..1000`;
nanosecond timeouts are `null` or normalized `0..1_000_000_000`. The only
signal is `SIGUSR1`; flags are zero or `SA_RESTART`; masks are empty or contain
`SIGUSR1`.

Epoll event bits are `IN`, `OUT`, `ERR`, `HUP`, `ET`, `ONESHOT`, and
`EXCLUSIVE`. The validator enforces Linux combinations: EXCLUSIVE only on
ADD, only with allowed readiness bits and optional ET, never MOD; DEL ignores
event/data semantically but uses their canonical zero spelling. Invalid
timespecs, sigset sizes, maxevents, flags, and raw pointers remain synchronous
raw-system regressions, not blocking resource stories.

Operation and mismatch IDs are append-only after historical IDs. A versioned
parser rejects a concurrent operation in every earlier corpus version and
rejects a historical parser cross-load before execution.

## Signal ownership and timing

The harness installs a `sigaction` for `SIGUSR1`, saves the previous action,
and restores it after every scenario. The handler performs only a lock-free
atomic increment indexed by worker actor. Each worker publishes its Linux TID
before syscall entry; the controller uses a thread-directed signal.

The checked matrix is:

| Wait | no `SA_RESTART` | `SA_RESTART` |
|---|---|---|
| zero-progress pipe/eventfd read/write | `-1/EINTR` | remains pending, then completes after a resource trigger |
| poll/ppoll/epoll wait family | `-1/EINTR` | `-1/EINTR` |
| pipe write after positive partial progress | transferred byte count | transferred byte count |

`ppoll`, `epoll_pwait`, and `epoll_pwait2` scenarios verify that masking
`SIGUSR1` prevents handler execution during the wait, the original mask is
restored on return, and a later unmask delivers exactly the pending count.

Elapsed time is not compared across kernels. The harness uses
`CLOCK_MONOTONIC` only to reject a timeout that is clearly earlier than its
requested lower bound. A syscall timeout, five-second schedule deadline, and
outer QEMU timeout retain separate categories.

## Eventfd resource stories

The model retains event object, OFD, alias, `O_NONBLOCK`, counter, and
semaphore state. Checked multi-waiter stories include:

- two `POLLIN` waiters woken by one readiness transition;
- two ordinary readers, with two writes proving both eventually complete;
- two `EFD_SEMAPHORE` readers released by one count of two;
- two writers near the counter maximum, with staged reads creating enough
  space for each;
- direct descriptors and aliases sharing one OFD/status flags; and
- mirror stories that exchange actors without constraining the first winner.

Eventfd epoll covers IN/OUT LT repetition, consumption and re-readiness, ET
new edges and partial drains, ONESHOT disable/MOD rearm, multi-fd truncation
and rotation, blocking wake, timeouts, signals, pwait masks, two waiters on one
epoll instance, and two EXCLUSIVE epoll instances. An eventfd ET mismatch is
never admitted as a known failure: preserve the raw fail-first result, fix the
Starry ready-list/wakeup path, and promote the existing eventfd EPOLLET probe.

## Pipe resource stories

The model owns pipe object, read/write endpoint direction, OFD identity,
descriptor aliases, shared `O_NONBLOCK`, record boundaries, capacity slots,
endpoint counts, and signal disposition. Checked stories include:

- two readers with staged writes;
- two atomic writers on a full one-page pipe, with whole-record reads freeing
  one slot at a time;
- two waiters for `POLLIN`, `POLLOUT`, and `POLLHUP`;
- a partial read that does not free the front buffer slot;
- aliases of one OFD and separate endpoint OFDs;
- final writer close producing data-then-EOF and HUP;
- final reader close producing write-end ERR and waking a blocked writer with
  `EPIPE` plus exactly one `SIGPIPE` handler invocation; and
- handler, ignored, and child default-SIGPIPE dispositions.

Pipe epoll adds HUP/ERR to the same LT/ET/ONESHOT/multi-fd/waiter matrix.
Unrequested HUP and ERR are preserved in exact returned events, as Linux
reports them regardless of the interest mask.

## Epoll identity and lifetime

One epoll interest is keyed by the numeric fd used at ADD plus its OFD. A dup
alias can be independently added with different mask/data. Closing one alias
does not remove interests while another reference to the OFD remains. Closing
the last reference removes the interest. Reusing the old numeric fd for a new
OFD never inherits the old interest.

LT may report readiness repeatedly until the resource changes. ET reports
only a new transition; a partial drain does not synthesize a new edge.
ONESHOT disables after the first returned event and is rearmed only by MOD.
When more than `maxevents` entries are ready, successive waits must expose the
remaining ready entries without starvation. Returned arrays compare in their
Linux order as part of the complete alternative.

For EXCLUSIVE registrations the first transition may complete any Linux-
allowed nonempty subset. A subsequent edge must give every still-pending
worker bounded progress. No claim is made about a fixed winner or strict
fairness.

An already blocked pipe/eventfd read or write holds its OFD reference. If the
controller closes the same descriptor number, the worker can still complete
after the peer transition. The model tracks the held OFD separately so cleanup
never acts on a reused number.

## Generator, mutation, and reduction

Generators select complete story templates, then vary actors, direct/alias
slots, legal masks, timeout buckets, event data, counter/value/length buckets,
and optional setup. Random output is always statically cleanable and never
depends on an uncontrolled external service.

Mutations operate on whole lifecycle stories or typed safe parameters. A
mutation must produce distinct executable canonical bytes or a typed rejected
candidate. Reduction removes scenarios and optional setup, simplifies values,
aliases, masks, and timeouts, and preserves resource dependencies, signal
restore, pending proof, cleanup, and the fresh-host-set mismatch rule.

## Checked acceptance and diagnostic

Each checked corpus is recorded 32 times into an allowed set, then the
aggregate is recorded independently three times byte-identically and
self-compared. Historical corpus hashes and traces are verified before and
after C changes. Python suites cover codecs, actor/mask/timeout/epoll bounds,
all fixed seeds and mutations, resource-aware reduction, routing, failure,
cleanup, replay, and campaign isolation.

QEMU runs serially: existing raw eventfd/pipe/signal/poll/epoll cases, every
historical adapter artifact, then the two concurrent checked artifacts. Each
new campaign runs seed 42 with four batches of 16 and a 64-QEMU budget,
followed by recovery-only runs with a 128-QEMU budget until no background task
remains. No new RNG is consumed during recovery.

The non-gating same-fd cross-thread poll-close diagnostic executes 100 host and
100 Starry iterations and records kernel release, completion/timeout, and
result distribution. A semantic distribution difference does not block Stage
6; panic, UAF, harness error, or an unjoinable worker does.

## Syscall compatibility map

| Syscall | Conclusion and observed contract | Standard |
|---|---|---|
| `eventfd2` | Existing creation flags and shared counter/OFD state; no production change unless a fail-first mismatch is found. | [`eventfd(2)`](https://man7.org/linux/man-pages/man2/eventfd.2.html) |
| `pipe2` | Existing endpoint creation, `PIPE_BUF`, capacity, EOF, SIGPIPE/EPIPE state. | [`pipe(2)`](https://man7.org/linux/man-pages/man2/pipe.2.html), [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html) |
| `read` | Slow-device EINTR/restart, partial progress, EOF, eventfd 8-byte result, and blocked-I/O OFD reference. | [`read(2)`](https://man7.org/linux/man-pages/man2/read.2.html), [`signal(7)`](https://man7.org/linux/man-pages/man7/signal.7.html), [`close(2)`](https://man7.org/linux/man-pages/man2/close.2.html) |
| `write` | Slow-device EINTR/restart, partial progress, atomic pipe writes, eventfd overflow blocking, EPIPE/SIGPIPE. | [`write(2)`](https://man7.org/linux/man-pages/man2/write.2.html), [`signal(7)`](https://man7.org/linux/man-pages/man7/signal.7.html), [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html) |
| `poll` | Immediate/finite/infinite wait, EINTR regardless of SA_RESTART, HUP/ERR. | [`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html), [POSIX `poll`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/poll.html) |
| `ppoll` | `poll` results plus atomic temporary mask and raw timespec timeout. | [`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html) |
| `rt_sigaction` | SIGUSR1 handler/ignore/default and flags 0/SA_RESTART; prior action restored. | [`sigaction(2)`](https://man7.org/linux/man-pages/man2/sigaction.2.html), [POSIX `sigaction`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/sigaction.html) |
| `tgkill` | Thread-directed SIGUSR1 to a published worker TID. | [`tgkill(2)`](https://man7.org/linux/man-pages/man2/tgkill.2.html) |
| `rt_sigprocmask` | Worker mask setup and restoration around atomic-mask waits. | [`sigprocmask(2)`](https://man7.org/linux/man-pages/man2/sigprocmask.2.html) |
| `epoll_create1` | Flags 0/CLOEXEC and epoll instance lifetime. | [`epoll_create(2)`](https://man7.org/linux/man-pages/man2/epoll_create.2.html) |
| `epoll_ctl` | ADD/MOD/DEL, fd+OFD identity, data, ET/ONESHOT/EXCLUSIVE restrictions. | [`epoll_ctl(2)`](https://man7.org/linux/man-pages/man2/epoll_ctl.2.html), [`epoll(7)`](https://man7.org/linux/man-pages/man7/epoll.7.html) |
| `epoll_wait` | LT/ET ready-list delivery, timeout, EINTR, maxevents, rotation. | [`epoll_wait(2)`](https://man7.org/linux/man-pages/man2/epoll_wait.2.html), [`epoll(7)`](https://man7.org/linux/man-pages/man7/epoll.7.html) |
| `epoll_pwait` | `epoll_wait` plus atomic temporary signal mask; never SA_RESTART restarted. | [`epoll_wait(2)`](https://man7.org/linux/man-pages/man2/epoll_wait.2.html), [`signal(7)`](https://man7.org/linux/man-pages/man7/signal.7.html) |
| `epoll_pwait2` | `epoll_pwait` with normalized nanosecond timeout; Linux since 5.11. | [`epoll_wait(2)`](https://man7.org/linux/man-pages/man2/epoll_wait.2.html) |
| `dup`, `dup2`, `dup3` | Alias and OFD identity setup; old interests do not transfer to a new OFD. | [`dup(2)`](https://man7.org/linux/man-pages/man2/dup.2.html), [`epoll(7)`](https://man7.org/linux/man-pages/man7/epoll.7.html) |
| `close` | Alias/final-reference lifetime and blocked-I/O reference; same-fd poll close remains diagnostic. | [`close(2)`](https://man7.org/linux/man-pages/man2/close.2.html), [`epoll(7)`](https://man7.org/linux/man-pages/man7/epoll.7.html) |

Credentials and namespaces are not involved. Compatibility is x86_64 only in
v1 because raw `sigsetsize`, `timespec`, and `epoll_event` layouts are recorded
against the existing x86_64 harness; cross-architecture work belongs to Stage
7.

