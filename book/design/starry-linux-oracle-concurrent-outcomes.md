# Stage 6.4 common multi-worker and allowed-outcome protocol

## Status and decision

This is the independently reviewable high-risk design for the common part of
Stage 6.4. The protocol and the resource design in
`starry-eventfd-pipe-concurrent-oracle.md` were reviewed independently before
implementation. The change is test infrastructure; a confirmed Linux/Starry
mismatch discovered by it requires a separate fail-first regression and
production fix.

Stage 6.4 adds two workers and a scenario-level allowed-outcome set. It does
not replace `SingleWorkerLifecycle`, change the three-record policy of any
historical adapter, or migrate a persisted corpus, trace, failure, campaign,
or replay route.

## Problem, users, and completion criteria

The accepted blocking adapters deliberately serialize one worker, one
controller transition, and one join. That is sufficient to prove blocking and
wakeup, but not to distinguish valid Linux scheduling alternatives from lost
wakeups when two workers compete. Comparing each operation independently is
unsafe: it can construct a cross-worker result combination that Linux never
produced.

The direct users are maintainers of Starry wait queues, signals, poll/epoll,
eventfd, and pipes. They need a bounded protocol that answers all of the
following without depending on scheduler luck:

- did both workers enter the intended syscall before a controller trigger;
- did every worker that the model declares completable finish within a fixed
  deadline;
- is the complete Starry scenario result one result vector observed on the
  pinned host Linux; and
- can every parse, model, compare, signal, or timeout failure clean up all
  started pthreads before the harness exits?

The common work is complete when two workers have independent typed
lifecycles, a host recorder captures complete alternatives without breaking
their correlation, persistent evidence grows monotonically per canonical
scenario, the aggregate trace is canonical and self-verifying, comparison
accepts exactly one witnessed alternative, failure or question evidence
identifies the earliest difference against the whole current set, and
reduction re-records Linux evidence for every candidate.

## Existing boundary and alternatives

The proven reusable boundaries are `scripts/linux_oracle/actor.py`,
`host_record.py`, `failure.py`, and
`test-suit/starryos/qemu/linux-oracle-common/controlled_worker.{c,h}`. Resource
state, operation codecs, generators, reducers, syscall arguments, and result
normalization stay in the pipe/eventfd adapters.

| Alternative | Decision |
|---|---|
| Keep one worker | Cannot exercise competing waiters or correlated results. |
| Compare a per-operation union | Rejected because it admits impossible cross-worker combinations. |
| Record a fixed winner | Rejected because Linux does not promise one scheduler order. |
| Put a scheduler in Python | Rejected because the syscall wait queues and delivery order must remain real kernel behavior. |
| Accept invariant-only results | Rejected for v1 because it weakens errno, data, event, and handler evidence. |
| Persist a monotonic empirical set of complete scenario vectors | Selected; nondeterminism is explicit, correlation is preserved, and later tool runs may add rare Linux outcomes. |

## Python worker lifecycle

`ControlledWorkers` owns worker actors 1 and 2; actor 0 remains the
controller. Each actor independently follows:

```text
absent -> started -> pending-confirmed -> completable -> completed -> joined
```

A worker call is immutable except for lifecycle facts. It records the
adapter-owned operation and resource identity, pending confirmation,
completion proof, observed completion, and optional completion ordinal.
Actor lookup is typed and accepts only 1 or 2.

The public transitions are:

- `start(actor, operation, identify_resource)`;
- `assert_pending(actor)` and `assert_all_pending()`;
- `before_trigger()` returning the active calls only after all applicable
  pending proofs;
- `update_completable(actor, value)`;
- `mark_completed(actor, ordinal)`;
- `join(actor, complete)` and `join_set((1, 2), complete)`; and
- `finish_scenario()`.

`join_set` validates and buffers both results before an adapter applies their
combined state transition. It never calls a comparator after the first join.
The order written in the corpus is not treated as the pthread completion
order; the result record carries the completion ordinal.

Shared error kinds remain `lifecycle` and `blocking-proof`. New details are
stable and actor-qualified: invalid actor, repeated actor start, grouped
pending with an absent worker, grouped join with duplicates or an absent
worker, completion ordinal reuse, partial grouped completion, and unfinished
actors. Adapters continue translating the shared kind into their historical
codec category.

## C worker slots and cleanup

The common C harness uses a fixed array of two address-stable worker slots.
Each slot owns a pthread, atomic phase, kernel TID published after start, and
completion ordinal. Adapter state owns the syscall argument and normalized
result buffer referenced by a slot.

The controller provides single and grouped operations corresponding to the
Python lifecycle. `observe_all_pending` first waits for both workers to publish
entered, then runs the pending guard while checking both for early completion.
Each worker gets an independent five-second completion deadline. A grouped
join waits for all selected slots, assigns ordinals with one atomic fetch-add,
then joins all selected pthreads before returning their buffered results.

The helper statuses distinguish:

| Category | Examples |
|---|---|
| early completion | one or both workers finish before pending confirmation |
| completion timeout | a proven-completable worker misses its five-second deadline |
| pthread error | create, targeted signal, or join fails |
| clock error | `CLOCK_MONOTONIC` cannot be read |
| sleep error | pending/deadline polling fails |
| cleanup error | adapter cleanup cannot wake and join every started worker |

All worker writes preceding phase publication use release ordering; controller
loads use acquire ordering. Completion ordinal allocation uses AcqRel because
the ordinal is both a uniqueness claim and part of the published result.

Every resource adapter supplies a cleanup callback. On parser, model, compare,
or controller failure, common orchestration invokes it once, waits for every
started worker, and joins them. The callback may send `SIGUSR1`, make a peer
transition, or close a peer endpoint. Cleanup must not close an arbitrary fd
number that may already have been reused. Failure to clean up is a typed
harness error, not a QEMU timeout.

## Scenario-level result representation

One normalized operation result contains:

- scenario and operation index;
- operation kind and actor;
- raw return value and errno;
- scalar value;
- exact data or ordered epoll `(events, data)` entries;
- signal-handler count; and
- worker completion ordinal, or zero for controller operations.

One alternative is the exact ordered vector of all results in a scenario.
The vector includes controller operations so an alternative cannot be
combined with a different setup or trigger result. Alternatives are sorted by
their serialized bytes and deduplicated. The allowed-set digest is SHA-256 of
the versioned scenario index, vector length, alternative count, and sorted
alternative bytes.

The v4/v7 aggregate trace contains a fixed header followed by scenario blocks.
Each block records scenario index, operation count, alternative count, set
digest, and the complete alternatives. The trace rejects:

- a wrong magic, exact version, corpus digest, host ABI metadata, count, or
  digest;
- zero alternatives or a count that cannot be represented by the format;
- an unsorted or duplicate alternative;
- an alternative with a different operation identity or vector length; and
- trailing bytes.

Historical v1--v6 trace layouts and online operation comparison remain
unchanged.

## Host observation and persistence policy

The concurrent recorder executes the complete canonical corpus 32 times on
one host executable and kernel. This is a fixed evidence budget, not a
statistical convergence claim. Each raw run produces one vector per scenario.
After every run, the recorder updates per-scenario alternative counts.

An adapter may use the recorder's zero-based run index to alternate a bounded
worker-entry delay. This changes only which real pthread reaches the kernel
wait queue first; it does not choose a winner, synthesize a return value, or
alter the corpus. The delay is host-record-only and is absent from guest
comparison. It improves exploration but makes no probability guarantee.

Every successful recording is merged into an `outcomes/` store keyed by the
SHA-256 of one canonical scenario. Stored result vectors normalize their
temporary batch scenario index to zero; an artifact rebases them to its current
batch position. The store records observation counts and every contributing
Linux kernel release. Merges take an exclusive file lock and replace JSON
evidence atomically. Existing alternatives are never removed, and replay with
`--refresh-host` may extend the set.

There is no minimum observation count, quiet-tail requirement, or fixed
alternative cap. Scenarios declared deterministic by the adapter must still
have exactly one persistent alternative; multiple alternatives there are an
evidence or model error and fail before QEMU. Parser rejection, an initial
scenario schedule timeout, inconsistent operation identity, and harness or
storage errors also remain fatal. A schedule timeout from a strictly smaller
reduction candidate rejects only that candidate and is retained in its audit.

Without a lower bound on an outcome's probability, no finite number of
repetitions can prove that a rare legal outcome is absent. The comparator
therefore claims exact membership only in the empirical Linux set witnessed so
far. On success, the recorder writes one canonical aggregate snapshot
atomically. Once persistent evidence stops changing for the checked inputs,
the checked aggregate is independently recorded three times and must be
byte-identical. Elapsed times and pthread identities never enter results.

## Compare and failure evidence

Starry buffers a complete scenario before comparison. It succeeds only if the
actual bytes equal one allowed alternative. Otherwise it computes the first
difference against every alternative using this field order:

```text
operation-index, kind, actor, result, errno, value, data, handler-count,
completion-ordinal
```

The reported representative is the alternative whose first difference is
earliest; ties use canonical alternative order. For a deterministic scenario
or an explicit invariant violation, this is a confirmed mismatch. For a
nondeterministic concurrent scenario whose result is merely outside the
current empirical set, the run is classified as `unexplained-outcome`, saved
under `questions/`, and excluded from coverage admission. Future Linux runs
may extend the evidence set; deciding or automatically resolving old question
artifacts is outside Stage 6.

Both failure and question evidence contain the actual full-vector digest,
allowed-set digest, selected alternative index, operation identity, differing
fields, aggregate snapshot, canonical scenario, host ELF, Starry ELF, log, and
available profraw files.

## Reduction and campaign integration

The common campaign continues treating corpus bytes as opaque. A concurrent
reducer must run this sequence for every candidate:

1. validate and serialize the candidate canonically;
2. record a fresh 32-run Linux set and merge it with that scenario's persistent
   evidence;
3. execute Starry with the resulting immutable snapshot; and
4. retain the candidate only when the original semantic or coverage predicate
   remains true.

It is forbidden to reuse only the parent's snapshot or add an alternative
because Starry produced it. A candidate must obtain its own Linux observation
and persistent merge. Candidate schedule timeout makes that candidate invalid;
parser, storage, initial-input, and harness failures remain fatal.
Attribution, minimization, ELF pinning, and corpus admission retain the
existing adapter-ID and coverage-target isolation.

Coverage evidence has a separate uncertainty boundary from syscall outcomes.
If a concurrent adapter's representative replay cannot reproduce every target
region, the attribution task completes as `unreproducible-coverage` with the
candidate-to-region map, representative set, proof regions, and missing regions
preserved. It admits no corpus entry and does not advance the stable coverage
baseline. This is neither a Linux outcome question nor a Starry semantic
mismatch. Historical adapters retain their strict representative-proof failure
behavior; only concurrent adapters use this classification.

## Frozen historical state

The preimplementation audit on Linux
`5.15.0-186-generic #196-Ubuntu SMP` recorded these checked corpus SHA-256
values:

| Adapter corpus | SHA-256 |
|---|---|
| eventfd v1 | `09a00230ddaa7703b4f81e685c29a020a45de7441a7301bdd4519acd5e3ded70` |
| eventfd v2 | `2a539e3c47b403c0103e3c77768ed0632fde7bca70d758a10f28538c80695b4e` |
| eventfd v3 | `e501023e9e5156583819fbd10583079faf7a3c22e80c465d06d538674124d4c3` |
| pipe v4 | `82a44681f889b990cf85b587fd41802a16c4283c9bd90d2100d7441965fc50cc` |
| pipe v5 read | `4d8fd3d216ac1c9989880bb192ee6a87a11ee26f8fe668a97a96e8560e2df366` |
| pipe v5 write | `3135128891b64e2f29ec7c4484c0d00cdee6f4bf3d7c284aa3b51706591210f5` |
| pipe v6 | `0b8bbd92dc1dbfbdc7234d0d78f2d53e987b7b1bec6bd5393bfaa1187fd5e10c` |

The six historical campaign roots are read-only to Stage 6.4. The audit found
pre-existing pending/running work only in the synchronous
`coverage/eventfd-oracle-fuzz` root. Concurrent implementation must not claim
that state, rewrite it, or consume its RNG. Recovery is valid only while the
active Starry executable and coverage sections still match the task's pinned
ELF. Once production changes make that identity stale, the old task remains
frozen evidence: it is not deleted, marked complete, replayed against a
different kernel, or counted as Stage 6 concurrent background work. Stage
closure audits and records such tasks, while requiring both new concurrent
campaign roots to have no pending or running task.

## Validation and rollback

Fail-first tests cover actor 2, grouped pending/join, early and partial
completion, independent deadlines, every helper error, cleanup, alternative
correlation, canonical sorting, monotonic persistence, scenario-index
normalization, set digest, trace rejection, failure/question selection, and
fresh-set reduction. Both C harnesses build with
`-Wall -Wextra -Werror`; checked traces are independently aggregate-recorded
three times and self-compared.

The 2026-08-07 aggregate closure passed 380 Python tests with one
environmental skip, both common C tests, the two bounded concurrent campaigns,
the raw and focused Starry QEMU suites, and the SMP=4 lockdep and remote-wake
cases. Workspace formatting, Python bytecode compilation, two `axpoll` clippy
configurations, 23 `starry-kernel` clippy configurations, and sync-lint across
186 packages were clean. The select/poll QEMU family includes both the loop and
many-fd stress subtests.

Rollback removes only the new concurrent adapters, campaign roots, and v4/v7
branches. Historical code and persisted artifacts require no migration.
