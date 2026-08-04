# Stage 6.2a: controlled pipe blocking and wakeup

## Status

Proposed on 2026-08-04. This is the independently reviewable high-risk design
for Stage 6.2a of the Starry Linux differential-testing roadmap. It introduces
a bounded pthread concurrency model and a new persistent canonical format.
Design acceptance, implementation, and runtime acceptance remain separate
commits.

The historical synchronous adapter remains `pipe-v4`. The CLI calls that
scenario model `simple-single` because every positive-length I/O is statically
nonblocking. Stage 6.2a adds the independent `pipe-blocking-v1` adapter selected
by `fuzz.py --model blocking`; omitting `--model` selects `simple-single`. The
two identities are not aliases. Strict common failure replay selects a model
from the saved `adapter_id` and rejects unknown or contradictory metadata.
Historical pipe failure schemas 1 through 3 do not have an adapter ID and
remain routed only to the existing v4 replay validator.

Model names and format versions are separate axes. `simple-single` retains
adapter version 4 and `pipe.ops` version 4. `blocking` starts at adapter version
1 and uses `pipe.ops` version 5 plus trace version 5. A later blocking change
increments its own versions and does not imply replacement of v4.

## Problem, users, and success criteria

The synchronous pipe adapter rejects every positive-length operation that may
sleep. It therefore cannot test the compatibility boundary where an empty pipe
blocks a reader, a full pipe blocks an atomic writer, data or EOF wakes a
reader, and freeing the final occupied pipe-buffer slot wakes a writer. These
paths exercise the pipe wait queue, Starry task `poll_io`, and
`axpoll::PollSet`. A lost or premature wakeup can hang an application even when
all nonblocking return values are correct.

Direct users are Starry pipe, filesystem, syscall, scheduler, and polling
maintainers. A concrete Stage 6.2a story is: start one blocking raw syscall in a
worker, prove that it remains incomplete during a fixed pending guard, change
the same pipe from the controller, and require the worker to finish with the
result recorded by the host Linux run.

The stage succeeds when:

- strict `pipe.ops` v5 expresses one controller and one worker with at most one
  unfinished syscall;
- validation proves that every `start-*` initially blocks, each controller
  trigger targets the same pipe, each phased release remains insufficient, and
  the worker can complete before `join`;
- the host and Starry harnesses observe the same pending checkpoints, trigger
  results, and joined worker result without comparing natural scheduling order
  or elapsed time;
- fixed read wakeup, alias, zero-write, EOF, full-pipe write, and phased-release
  stories produce byte-identical host traces over three consecutive runs;
- blocking campaigns have their own adapter identity, campaign root, coverage
  target, corpus, metadata, replay dispatch, attribution, and minimization
  state; and
- every v4 canonical byte, digest, trace, failure artifact, default CLI
  behavior, legacy recovery path, and persistent directory remains unchanged.

Keeping Stage 6.2a out leaves pipe wait/wakeup behavior untested by the Linux
oracle. Replacing v4 would make historical evidence ambiguous and force
concurrency machinery into synchronous users.

## Risk classification and evidence sources

This is high risk under `book/guideline/feature-development.md`: it adds a
canonical persistent format, a new concurrency model, atomic synchronization,
thread ownership, and timeout classifications. This design fixes the state
machine, proof boundary, compatibility rules, and validation evidence before
implementation.

The semantic references are POSIX.1-2024 and Linux man-pages 6.18:

- POSIX [`read()`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/read.html)
  requires a positive read on an empty blocking pipe to wait while a writer
  remains open and to return EOF when no writer remains.
- POSIX [`pipe()`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/pipe.html)
  defines the two open file descriptions and their initial `O_NONBLOCK` state.
- Linux [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html), from
  man-pages 6.18, records Linux's 4096-byte `PIPE_BUF`, capacity controls, EOF
  rule, and the all-or-block behavior of blocking writes no larger than
  `PIPE_BUF`.

Host Linux execution remains the comparison authority. The Python state model
proves only admission invariants needed to make the schedule bounded; it does
not replace the host trace with predicted syscall results.

Internal prior art is the v4 pipe fd/open-description model, the Stage 6.1
eventfd controlled worker, the common multi-adapter campaign framework, and the
existing QEMU artifact injection path. Repository history through Stage 6.1
and the open pull-request list were checked on 2026-08-04; no competing pipe
blocking adapter was present. Eventfd demonstrates the timeout and persistence
boundaries, but its counter state cannot model pipe endpoints, byte queues,
buffer slots, or EOF. Pipe therefore keeps its actor state local until Stage
6.2b independently extracts a framework from two stable implementations.

## Alternatives

| Alternative | Advantage | Blocking cost |
|---|---|---|
| Keep v4 only | No concurrency complexity | Cannot reach wait queues or prove wakeups |
| Add sleeps around ordinary reads/writes | Small patch | Depends on accidental scheduling and cannot prove syscall entry |
| Add arbitrary actors and barriers now | General syntax | Guesses an abstraction and admits unstable interleavings |
| Replace v4 with a v5 superset | One apparent entry point | Breaks identity, digests, legacy recovery, and the synchronous default |
| Share eventfd actor code in the same change | Less immediate duplication | Couples feature semantics to an unproven common boundary |
| Add one controlled worker in an independent adapter | Small explicit state machine and independent rollback | Maintains two adapter specifications |

The selected design is the last alternative. It accepts limited adapter-local
duplication to preserve compatibility and make concurrency risk visible.
Stage 6.2b will be a behavior-preserving refactor after both blocking adapters
are accepted.

## Canonical v5 model

`pipe.ops` v5 is strict UTF-8, newline terminated, and canonically rendered
under the existing entry limits. Every scenario has controller actor `0` and
worker actor `1`. Existing v4 operation spellings remain unchanged and execute
as actor 0. Four new spellings carry the only legal worker identity:

```text
start-read 1 SLOT LENGTH
start-write 1 SLOT LENGTH BYTE
assert-pending 1
join 1
```

Lengths are positive and bounded by the existing 8192-byte harness buffer.
Worker writes are additionally limited to `PIPE_BUF` (4096 bytes). No actor
count, pending duration, completion timeout, thread identifier, fd number,
clock value, or scheduling choice is configurable in canonical input.

The lifecycle is:

```text
idle
  -> start-read/start-write
started
  -> assert-pending
pending-confirmed
  -> one or more same-pipe wake operations
  -> assert-pending after a proven insufficient operation (optional)
triggered-completable
  -> join
idle
```

Only one worker may be active. A scenario must end in `idle`. Repeated starts,
wrong actor IDs, missing pending confirmation, early join, unrelated pipe
operations, operations after a completing trigger other than `join`, and an
unfinished scenario are codec errors.

## Resource model and static proof

The v5 validator tracks logical fd slots, endpoint direction, pipe-object
identity, open-file-description identity, fd flags, shared `O_NONBLOCK`, pipe
capacity, queued byte records, readable and writable endpoint counts, and the
worker lifecycle. A pipe record contains a byte value and remaining length;
reads consume records in FIFO order. Capacity is measured in 4096-byte
pipe-buffer slots for controlled write-blocking stories. Stage 6.2a admits only
states produced by successful-form operations whose result is deterministic
under the restricted model.

For `start-read`, the slot must be a live read endpoint whose shared open file
description has `O_NONBLOCK` clear. The requested length is positive, the pipe
is empty, and at least one writer remains open. These conditions make an
immediate data return, EOF, `EAGAIN`, and wrong-direction failure impossible.

For `start-write`, the slot must be a live write endpoint with `O_NONBLOCK`
clear, at least one reader must remain, and the length must be in
`1..PIPE_BUF`. The pipe must have no free buffer slot and the tail record must
not be mergeable. Thus Linux cannot partially commit the atomic write before
blocking. Generation reaches this state by setting capacity to 4096 and
filling one 4096-byte record.

While the worker is active, the controller may execute only:

- a valid positive or zero-length write through a write endpoint of the same
  pipe while a read worker is pending;
- a positive read through a read endpoint of the same pipe while a write
  worker is pending;
- closing the final live writer of that same pipe after the read worker's
  pending state was confirmed, making EOF inevitable;
- `assert-pending` and `join`.

Duplication, flag or size changes, vector I/O, poll, another pipe, general
close competition, and wrong-direction operations are rejected while active.
Aliases are valid wake endpoints because the model proves their endpoint,
pipe-object, and shared open-description identity. The sole active close is
the final-writer EOF transition; reader closure and `EPIPE` remain later work.

After a controller operation, the validator updates queued records and endpoint
counts. A read worker becomes completable when data exists or the last writer
has closed. A write worker becomes completable only when its whole atomic
record can be installed. `assert-pending` is accepted only while completion is
still impossible. In the phased-release story, reading one byte changes the
front record's length but leaves its 4096-byte slot occupied; reading the
remaining 4095 bytes frees the slot. `join` is accepted only after completion
is inevitable, and applies the joined syscall transition so subsequent
synchronous operations see a sound state.

These checks are input-admission proofs, not expected-result generation. The
running host still supplies errno, byte data, counts, and EOF results.

## Harness ownership, synchronization, and timeouts

Each scenario owns one `pthread_t` and one worker record. Actor 0 creates and
joins it; actor 1 cannot outlive the scenario. The worker stores immutable fd
and buffer arguments before creation, publishes `entered` immediately before
the raw syscall with release ordering, stores the normalized result, then
publishes `completed` with release ordering. The controller observes those
states with acquire ordering. Active-lifecycle validation prevents fd-table or
flag mutation that could race with the worker, except the explicitly modeled
last-writer close on another fd.

`assert-pending` waits for `entered`, then observes a monotonic-clock guard of
exactly 50 ms. Completion before the guard expires is a semantic mismatch. A
host candidate is accepted only when three complete recordings produce
byte-identical traces.

Once the model proves completion possible, `join` waits for `completed` for at
most 5 seconds and calls `pthread_join` only after completion is visible.
Failure to complete is `schedule-timeout`. `pthread_create`, `pthread_join`,
atomic-clock support, clock reads/sleeps, or another harness prerequisite
failure is `harness-error`. The outer QEMU timeout remains a longer
infrastructure safety net. The fixed 50 ms and 5 s policies never enter
canonical bytes or normalized traces, and increasing them is not a fix for a
lost wakeup or unstable input.

## Trace v5 and comparison

Trace v5 records operations in canonical script order, not worker completion
order. It retains logical slots and never records real fds, `pthread_t`, task
IDs, clocks, durations, or scheduler order.

- `start-*` records actor and immutable operation parameters without
  fabricating a syscall result;
- `assert-pending` records one exact pending observation after the guard;
- controller wake operations record ordinary normalized syscall results and
  read data; and
- `join` records the worker result and read data, or produces the distinct
  timeout/infrastructure marker.

Record mode does not produce a successful trace for early completion,
schedule timeout, or harness failure. Compare reports an early completion or a
different joined syscall result as semantic mismatch. It reports
`schedule-timeout` and `harness-error` with dedicated markers so persistence
does not conflate them with an errno difference or outer timeout.

Malformed input, wrong trace version, missing or extra records, identity
mismatch, truncated data, and trailing bytes fail closed. Version 4 corpus is
still recorded as trace version 4 and requires trace version 4; version 5
requires trace version 5.

## Fixed corpus

The checked-in v5 corpus contains separate deterministic scenarios for:

- an empty blocking pipe read woken by a positive write;
- a read started and woken through aliases after clearing shared
  `O_NONBLOCK`, with setup queries confirming the shared state;
- a zero-length write that leaves the reader pending, followed by a positive
  write that wakes it;
- an empty read returning EOF after the final writer is closed;
- capacity set to 4096, one full record, and an atomic worker write completed
  after a 4096-byte controller read; and
- the same full pipe with a one-byte read and second pending checkpoint,
  followed by a 4095-byte read that frees the only buffer slot.

All wake operations use valid harness-owned buffers. Invalid pointers, vector
I/O, general fd races, `EPIPE`, and poll remain v4 synchronous or later-stage
responsibilities.

## Generator, mutation, and reduction

The v5 generator emits complete lifecycle story templates and may vary logical
slots, aliases, bytes, read sizes, and atomic write sizes. It never generates
arbitrary actor schedules. Mutation operates on lifecycle units and whole
scenarios; executable candidates must change the canonical digest and pass the
blocking/completion proof. Reduction deletes scenarios, unused setup aliases,
and optional pending-preserving steps, and simplifies values while preserving
origin mapping and a strictly smaller complexity key. No transform synthesizes
sleeps or synchronization.

## Adapter, persistence, and replay isolation

`pipe-blocking-v1` uses adapter version 1, corpus version 5, generator version
1, campaign root `coverage/pipe-blocking-oracle-fuzz`, and target set
`pipe-blocking-v1`. It reuses only the common opaque-byte campaign machinery
and the QEMU case/artifact filenames supplied by its own `AdapterSpec`.

The blocking model uses only strict common failure schema 1 and never opens the
legacy pipe corpus, attribution, minimization, or failure stores. Common
metadata binds adapter ID, target set, scenario digest, trace, host ELF, and
Starry ELF. Loading a blocking artifact through v4, a v4 common artifact
through blocking, or an unknown adapter fails before QEMU execution.

`fuzz.py` accepts only `simple-single` and `blocking`, defaulting to
`simple-single`. The default performs the same legacy recovery before the same
v4 common campaign. `replay.py` first reads metadata: exact common metadata
dispatches by adapter ID; historical metadata without `adapter_id` is accepted
only by the unchanged legacy schema 1--3 validator. Merely adding or deleting
an adapter field cannot migrate an artifact.

## Coverage boundary

The `pipe-blocking-v1` target set contains the v4 pipe syscall/file paths plus
the scheduler and poll-wait implementations that own blocking and wakeup:

- Starry pipe file and fs syscall I/O/fd paths;
- Starry poll syscall paths already reached by pipe waiting;
- the `axtask` source implementing `poll_io`; and
- the `axpoll` source implementing `PollSet`.

Tests reject a missing target source. Coverage state remains scoped by target
set and exact Starry ELF digest.

## Difference policy

Any Linux/Starry difference first receives a deterministic regression in the
existing pipe raw-syscall system case. The regression must fail on the current
implementation without relying on a widened sleep. Only then is the production
pipe wait/wake implementation fixed. Acceptance reruns that regression and the
original saved v5 scenario.

Changing the host trace, classifying early completion as pending, widening
timeouts, lowering generator weight, or deleting the scenario is not a fix.
Changes to wait queues or atomic synchronization additionally require targeted
crate clippy and `cargo xtask sync-lint`.

## Validation and acceptance gates

Unit and integration tests cover codec round trips, v4/v5 rejection, illegal
actor lifecycles, blocking/completion proofs, aliases, shared `O_NONBLOCK`, zero
writes, EOF, full-pipe atomic writes, phased slot release, mutation, reduction,
origin preservation, mismatch fingerprints, model selection, strict artifact
tampering, and legacy/common replay isolation. Host tests cover three-record
stability and dedicated early-completion, schedule-timeout, and harness-error
classification.

Acceptance runs common, eventfd simple/blocking, and pipe simple/blocking Python
tests plus `py_compile`; workspace rustfmt; targeted `starry-kernel` clippy; the
pipe raw-syscall case; simple and blocking pipe/eventfd QEMU comparisons; and
`git diff --check`.

The blocking campaign uses seed 42, three batches, 16 candidates per batch,
and a 32-QEMU foreground budget. It must persist at least one exactly
attributed corpus entry and either reduce one entry or prove it already
minimal. Recovery then runs with zero new batches and a 64-QEMU bound until no
attribution or minimization task remains.

## Non-goals and rollback

Stage 6.2a intentionally excludes multiple waiters, fairness, allowed-result
sets, signals and restart, nonzero poll/epoll timeouts, reader-close `EPIPE`,
and general close/lifetime races. Stage 6.2b is a separate behavior-preserving
extraction of common actor machinery. These items do not weaken the single
worker stories because their schedules and completion conditions are fully
specified here.

The feature is selected only by `--model blocking`, owns no production state,
and can be rolled back by removing its adapter and v5 corpus without changing
v4 artifacts or defaults. Persisted blocking state remains self-identifying
and will fail closed if the adapter is unavailable.
