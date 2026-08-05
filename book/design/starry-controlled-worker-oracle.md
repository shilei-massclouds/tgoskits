# Stage 6.2b: shared controlled single-worker oracle framework

## Status

Proposed on 2026-08-05. This document is the independently reviewable
high-risk design for Stage 6.2b of the Starry Linux differential-testing
roadmap. Stage 6.2b is a behavior-preserving refactor of the accepted eventfd
v2 and pipe v5 blocking adapters. Design, Python extraction, C extraction, and
acceptance evidence remain separately reviewable commits.

This stage does not add a scenario operation, actor, syscall model, trace
field, persistence field, command-line choice, coverage target, or StarryOS
production behavior. Any change to canonical bytes, digests, host traces,
failure fingerprints, result classification, or replay routing is a failed
refactor and must be fixed rather than accepted through a version increase.

## Problem, users, and success criteria

Stage 6.1 intentionally kept the eventfd controlled-worker lifecycle local
until another adapter proved the same boundary. Stage 6.2a supplied that second
implementation for pipe. The two accepted adapters now independently maintain
the same controller/worker identities, lifecycle transitions, pending and join
preconditions, three-record host stability policy, pthread phase publication,
monotonic waits, timeout constants, and infrastructure-error routing.

The duplication is now a maintenance risk. A future correction to the
single-worker protocol could update one adapter but not the other, even though
their intended lifecycle and harness policy are identical. Direct users are
the maintainers of the eventfd and pipe differential adapters and authors of a
later controlled blocking adapter. They need one small boundary whose tests
state the shared invariants without forcing eventfd counter rules or pipe
buffer rules into common code.

A concrete use is: an adapter proves that its domain operation initially
blocks, asks the shared lifecycle to start one worker, confirms pending,
executes and models one or more domain triggers, marks whether the worker is
now completable, and joins only after that proof. The C harness uses the same
shared controller object to publish syscall entry and completion, observe the
50 ms pending guard, wait up to 5 s for completion, and join the pthread.

Stage 6.2b succeeds when:

- eventfd v2 and pipe v5 use one Python lifecycle implementation with typed
  lifecycle versus blocking-proof errors;
- both adapters translate those errors to their exact historical categories,
  line numbers, and messages;
- both blocking adapters use one three-record helper while retaining their
  existing adapter hook and test-injection entry points;
- both host harnesses compile one `controlled_worker.c` implementation while
  keeping syscall arguments, results, fd state, counter state, and pipe state
  local;
- the common C interface preserves release publication and acquire
  observation, the 50 ms pending guard, the 5 s completion deadline, and the
  1 ms polling interval;
- common unit tests exercise every lifecycle transition and C status class;
  and
- pre- and post-refactor checked corpora, generated seeds, digests, host
  traces, failure fingerprints, replay dispatch, and recovery-only campaign
  state compare unchanged.

Keeping the duplication would make shared protocol fixes harder to review.
Extracting a general actor scheduler would add unused flexibility and obscure
the two proven single-worker protocols.

## Risk classification and evidence sources

This extraction is high risk under
`book/guideline/feature-development.md` because it centralizes an existing
concurrency model and its atomic synchronization. The risk is semantic drift,
not a desired new capability. Therefore the design fixes ownership, state
transitions, error translation, synchronization, compatibility, and byte-level
acceptance before implementation.

The internal prior art is:

- Stage 6.1 eventfd v2 in
  `book/design/starry-eventfd-blocking-oracle.md`;
- Stage 6.2a pipe v5 in `book/design/starry-pipe-blocking-oracle.md`;
- the opaque multi-adapter framework under `scripts/linux_oracle`; and
- the two accepted C harnesses under
  `test-suit/starryos/qemu/{eventfd,pipe}-linux-oracle`.

Repository history through Stage 6.2a records that eventfd deferred extraction
until pipe demonstrated the same lifecycle and that pipe explicitly left the
common extraction to Stage 6.2b. The current open TGOSKits pull-request search
was checked on 2026-08-05; the Linux-oracle matches were unrelated scheduler
and board-benchmark changes, not competing actor or harness abstractions.

No new external syscall semantics are introduced. POSIX and Linux references
remain those recorded by the two source designs, and the running host traces
remain the comparison authority. The Starry syscall guideline is not directly
applicable to implementation because no production syscall, ABI, errno,
blocking rule, or wait queue changes. It remains an acceptance constraint:
raw syscall and QEMU differential results must show that the refactor did not
alter an observable path.

## Alternatives

| Alternative | Advantage | Cost or rejection reason |
|---|---|---|
| Keep both copies | No immediate edit | Shared invariants can drift silently |
| Extract Python only | Removes model duplication | Leaves timing and atomic protocol duplicated |
| Extract C only | Removes pthread duplication | Leaves lifecycle categories and preconditions duplicated |
| Put eventfd/pipe callbacks in one generic framework | Can centralize more lines | Leaks domain models into the common layer and hides audit paths |
| Build a configurable actor scheduler | Supports hypothetical future models | Adds unused actors, barriers, schedules, and result policies |
| Extract only the proven lifecycle, recorder, and pthread controller | Removes duplicated knowledge with two real consumers | Retains intentionally thin adapters |

The selected alternative is the last one. Common code owns only facts already
identical in both implementations. Domain validation, state mutation, codecs,
trace normalization, and failure policy remain visible in each adapter.

## Python architecture

### Ownership and dependency direction

`scripts/linux_oracle/actor.py` is an internal leaf module. It defines fixed
`CONTROLLER_ACTOR = 0` and `WORKER_ACTOR = 1`, a generic immutable
`WorkerCall[OperationT, ResourceT]`, a `SingleWorkerLifecycle`, and a typed
error containing only an error kind and stable detail text.

The lifecycle owns:

- whether one worker is active;
- its immutable operation and adapter resource identity;
- whether pending has been confirmed;
- whether domain analysis has proved completion possible; and
- the shared order constraints for start, pending, trigger, join, and scenario
  completion.

The lifecycle does not know an eventfd slot, counter, pipe endpoint, buffer,
fd flag, codec category, source line, or joined syscall effect. Eventfd and
pipe retain those models and call the lifecycle only after their domain proof
for `start`. Before a controller operation they request the active worker and
shared trigger preconditions. After applying the domain operation they publish
the computed `completable` fact. At join they provide the adapter-owned state
transition; the lifecycle clears the worker only after that transition
returns successfully.

The dependency remains one-way:

```text
eventfd blocking adapter ----\
                              > scripts/linux_oracle/actor.py
pipe blocking adapter -------/
```

The common module never imports an adapter.

### Lifecycle and error contract

The state machine is unchanged:

```text
idle -> started -> pending-confirmed -> triggered-completable -> idle
                     |        ^
                     +--------+  insufficient trigger plus another pending check
```

The common error kinds are `lifecycle` and `blocking-proof`:

| Shared failure | Kind | Stable detail |
|---|---|---|
| second start | lifecycle | `only one worker call may be active` |
| pending without worker | lifecycle | `assert-pending requires an active worker` |
| pending after completion is possible | blocking-proof | `worker may complete before assert-pending` |
| trigger after completion is possible | lifecycle | `join must immediately follow a completing trigger` |
| trigger before pending confirmation | lifecycle | `worker pending state was not confirmed` |
| join without worker | lifecycle | `join requires an active worker` |
| join without both proofs | blocking-proof | `worker is not proven completable before join` |
| unfinished scenario | lifecycle | `scenario ends with an unfinished worker` |

Eventfd translates `lifecycle` to `actor-lifecycle` and `blocking-proof` to
`blocking-proof`, retaining its optional source-line behavior. Pipe translates
`lifecycle` to `CodecErrorCategory.RESOURCE_CONFLICT` and `blocking-proof` to
`CodecErrorCategory.BLOCKING_IO`, retaining the caller-supplied operation line.
The adapter raises its historical `ScenarioCodecError`; common error types do
not cross the codec boundary.

### Stable host recording

A common helper accepts the adapter's one-shot recorder, host executable,
scenario path, final trace path, and adapter-specific temporary-directory
prefix. It runs exactly three sequential attempts named `linux-0.trace`
through `linux-2.trace`, stops at the first failed attempt, concatenates logs
exactly as before, rejects any byte difference with the existing message, and
copies the first trace to the target only after all bytes match.

The return type is always `linux_oracle.batch.HostRecordResult`. Each adapter
keeps `record_host_stable(elf, scenario, trace)` and its module-level
`record_host_once` name so `AdapterSpec.host_record` and existing injected tests
remain unchanged.

## C harness architecture

### Boundary and ownership

`test-suit/starryos/qemu/linux-oracle-common/controlled_worker.h` exposes one
controller object containing the pthread and atomic phase. Its implementation
owns pthread creation/join and monotonic polling. The caller owns a stable
worker argument object and a callback that performs the raw syscall and writes
the adapter-local normalized result before publishing completion.

The helper provides operations for initialization, start, release publication
of `entered`, release publication of `completed`, pending observation,
completion wait, and join. A harness cannot ask it to execute eventfd or pipe
logic. Eventfd keeps its fd, counter value, and read buffer. Pipe keeps its fd,
length, byte, buffer, pipe-object identity, endpoint counts, and queue state.

Both CMake cases add the same relative common source and include directory to
their existing executable. They remain independent C pipelines with the same
executable names, static linking, install paths, checked corpora, runtime
configuration, success/fail regexes, and discovery behavior.

### Synchronization and timing

The phase values are idle, started, entered, and completed. Initialization
happens before `pthread_create`. The worker publishes entered with release
ordering immediately before the raw syscall. It stores its complete local
result, then publishes completed with release ordering. Controller loads use
acquire ordering so observing a phase also observes the worker argument and
result writes that precede it.

The production helper fixes:

- pending guard: 50 ms;
- completion deadline: 5 s; and
- polling interval: 1 ms.

All deadlines use `CLOCK_MONOTONIC`. These values are harness policy and never
enter canonical input or trace bytes. Tests may compile the same implementation
with injected platform operations or explicit test-only timing values; the two
production entry points always use the fixed constants.

### Typed C statuses and adapter mapping

The helper reports statuses rather than printing adapter markers:

| Shared status | Meaning | Adapter result |
|---|---|---|
| `OK` | requested transition completed | continue |
| `COMPLETED_EARLY` | completed before the pending guard elapsed | ordinary semantic mismatch at `assert-pending` |
| `COMPLETION_TIMEOUT` | completion absent at the 5 s deadline | existing `schedule-timeout` marker |
| `PTHREAD_ERROR` | create or join failed | existing `harness-error` marker |
| `CLOCK_ERROR` | monotonic clock failed | existing `harness-error` marker |
| `SLEEP_ERROR` | polling sleep failed | existing `harness-error` marker |

The adapters retain line numbers, operation indexes, and exact marker text.
The helper does not write traces or choose an error category.

## Compatibility boundary

The following are frozen:

| Surface | Eventfd | Pipe |
|---|---|---|
| simple adapter | `eventfd-v1` | `pipe-v4` |
| blocking adapter | `eventfd-blocking-v1` | `pipe-blocking-v1` |
| corpus version | v1/v2 | v4/v5 |
| trace version | v1/v2 | v4/v5 |
| default model | `simple-single` | `simple-single` |
| campaign root | existing simple/blocking roots | existing simple/blocking roots |
| coverage target | existing adapter target | existing adapter target |
| replay routing | strict adapter ID | legacy v1--v3 plus strict common adapter ID |

Artifact schemas, filenames, metadata keys, canonical rendering, generator RNG
and version, mutation and reduction behavior, mismatch fingerprint operation
numbers, QEMU configuration, and test discovery are likewise unchanged.

## Validation and acceptance gates

Before implementation, preserve the five checked corpora, old host binaries,
and three traces for each corpus in a temporary baseline. Also preserve
canonical bytes and old-host traces for deterministic eventfd simple/blocking
and pipe v4/v5 seeds plus representative blocking mismatch fingerprints.

Python tests cover repeated start, pending and join without a worker, trigger
before pending, trigger after completion becomes possible, pending after
completion becomes possible, join before completion, successful join, failed
adapter join transition, unfinished scenario, and exact error translation in
both adapters. Recorder tests cover three equal traces, failure on each attempt,
and any unequal trace while adapter wiring tests preserve the hook seam.

C helper tests cover normal pending/wake/join, immediate completion, completion
timeout, and pthread/clock/sleep status mapping. Harness integration tests still
record each checked blocking corpus three times and compare it.

Serial acceptance includes:

1. common, eventfd, and pipe Python suites plus `py_compile`;
2. C helper unit tests and both host harness builds with warnings as errors;
3. byte comparison of all preserved corpora, seeds, digests, traces, and
   fingerprints;
4. `cargo fmt`, `cargo xtask clippy --package starry-kernel`, and
   `git diff --check`;
5. raw eventfd2, raw pipe syscall, eventfd simple, and pipe v4 QEMU cases;
6. eventfd and pipe blocking QEMU comparison using temporary artifact
   directories and the existing cases; and
7. recovery-only blocking campaigns with `--batches 0 --max-qemu 64`, no new
   baseline, no new batch, and no pending/running attribution or minimization.

QEMU commands run serially in one checkout. Physical-board, self-hosted,
multi-worker, signal, fairness, allowed-result-set, and performance testing are
not part of this refactor.

Only host C atomics change. No production Rust synchronization, wait queue, or
syscall implementation changes, so `cargo xtask sync-lint` is not applicable.
If implementation touches one of those production boundaries, Stage 6.2b
stops and the expanded risk is redesigned separately.

## Non-goals and rollback

Stage 6.2b excludes multiple workers, waiter fairness, allowed result sets,
signals and `EINTR`, restart behavior, nonzero poll/epoll waits, general close
races, new campaigns, new corpus versions, and any StarryOS semantic fix.

The extraction is stateless and internal. It can be rolled back by restoring
the adapter-local Python and C implementations without migrating any artifact
or campaign state. If acceptance discovers an existing Linux/Starry semantic
difference, that difference receives a separate fail-first raw-syscall test and
production fix; it is not mixed into this refactor.
