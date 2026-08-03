# Stage 5: eventfd differential adapter and Linux-oracle framework

## Status

Proposed for implementation on 2026-08-03. This is the independently reviewable
high-risk design for Stage 5 of the Starry Linux differential testing roadmap.
Acceptance evidence is recorded only after the implementation and all gates in
this document complete.

The fixed production reference is Linux commit
[`a2cf4ef33184df0ae9e1a2b05b550133dde1698c`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L118-L280).
The public contract is [`eventfd(2)`](https://man7.org/linux/man-pages/man2/eventfd.2.html).

## Problem, users, and success criteria

The pipe oracle proved that a host Linux execution can provide higher-signal
syscall compatibility evidence than a handwritten semantic model. Its Python
campaign implementation is nevertheless pipe-shaped: artifact names, QEMU
selection, coverage targets, canonical codec calls, and persistent roots are
embedded throughout the orchestration. Copying that implementation for every
new syscall family would duplicate recovery and fail-closed persistence logic;
generalizing it before a second real adapter would guess at the wrong boundary.

Stage 5 therefore adds eventfd as the second complete vertical adapter and then
extracts only the behavior that pipe and eventfd demonstrably share. Direct
users are Starry filesystem/syscall maintainers running manual compatibility
and coverage campaigns. A later adapter author is also a user of the internal
framework contract.

The stage succeeds when:

- one static x86_64 eventfd harness records on the host and compares in Starry;
- the checked-in and generated corpora are synchronous, deterministic, and
  cannot block on a correct Linux implementation;
- exact results include return value, errno, read value, buffer side effects,
  normalized flags, and ordered poll `revents`;
- eventfd campaign state supports deterministic generation, structured
  mutation, resource-aware reduction, strict persistence, replay, exact
  coverage attribution, and bounded minimization;
- pipe command paths and every retained pipe schema remain readable and
  byte-compatible without moving or rewriting historical data;
- a third fake adapter proves that the common layer has no pipe/eventfd branch;
  and
- the eventfd QEMU comparison reports no Linux/Starry semantic difference.

Keeping the pipe-only implementation would make a third oracle copy lifecycle,
coverage, and persistence code again. Stage 5 pays the framework extraction
cost now because there are two real adapters with different codecs, artifacts,
QEMU cases, persistent roots, and coverage files.

## Scope and non-goals

The eventfd is the primary resource, while fd lifecycle, `fcntl`, and timeout-
zero `poll` are supporting syscalls. Version 1 covers:

- raw `eventfd` and `eventfd2` creation;
- scalar `read` and `write` with explicit lengths and valid/invalid pointers;
- `dup`, `dup2`, `dup3`, and `close`;
- `F_GETFL`, `F_SETFL`, `F_GETFD`, and `F_SETFD`; and
- one-entry and bounded multi-entry `poll` with timeout zero.

The following remain out of scope and must not be admitted indirectly:

- blocking calls, threads, fork, scheduler interleavings, wake timing, signals,
  or nonzero/infinite timeouts;
- `epoll`, `select`, `ppoll`, `readv`, `writev`, AIO overflow signaling, or
  kernel-side eventfd signal posts;
- syzkaller import, multi-architecture execution, default CI, or a pinned Linux
  VM; and
- changing Starry semantics merely to add the tool. A discovered difference
  stops acceptance and follows the regression-first repair process below.

## Linux semantic reference

The fixed Linux implementation establishes the following observable state
machine:

- creation rejects unknown flags, stores the 32-bit initial count in a 64-bit
  counter, keeps `EFD_SEMAPHORE` on the event object, maps `EFD_NONBLOCK` to the
  open-file-description, and maps `EFD_CLOEXEC` to the new fd
  ([`do_eventfd`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L379-L414));
- a read with length below eight returns `EINVAL`; a length of eight or more
  transfers exactly eight bytes. Normal mode returns the whole count and
  resets it, while semaphore mode returns one and decrements by one. An empty
  nonblocking read returns `EAGAIN`
  ([`eventfd_read`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L214-L245));
- a write requires length exactly eight, faults while copying the value,
  rejects `UINT64_MAX`, adds every other value including zero, and returns
  `EAGAIN` in nonblocking mode when the sum would exceed `UINT64_MAX-1`
  ([`eventfd_write`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L247-L280)); and
- poll reports readable when count is nonzero and writable only while a value
  of at least one can be added. Kernel-only overflow is excluded from the v1
  input language
  ([`eventfd_poll`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L118-L174)).

The fd alias rules follow [`dup(2)`](https://man7.org/linux/man-pages/man2/dup.2.html):
aliases share one open-file-description and its `O_NONBLOCK`, but each fd owns
its `FD_CLOEXEC`. `dup` and successful `dup2` clear the new descriptor flag;
`dup3(O_CLOEXEC)` sets it; `dup2`/`dup3` replace the destination atomically.

The Python resource model exists only to reject malformed or potentially
blocking inputs. It does not predict result values or errno for comparison;
the trace recorded by the same C harness on the running host is authoritative.

## Canonical eventfd input and trace

`eventfd.ops` v1 is strict, UTF-8, newline-terminated, and canonically rendered
with generated scenario names and unsigned decimal integer fields. It has at
most four scenarios per entry, 32 operations per scenario, 16 logical fd
slots, four poll entries, and 4096 encoded bytes. The operation forms are:

```text
eventfd SLOT INITVAL
eventfd2 SLOT INITVAL FLAGS
read SLOT LENGTH POINTER_MODE
write SLOT LENGTH POINTER_MODE VALUE
dup SOURCE_SLOT DESTINATION_SLOT
dup2 SOURCE_SLOT DESTINATION_SLOT
dup3 SOURCE_SLOT DESTINATION_SLOT FLAGS
close SLOT
get-status-flags SLOT
set-status-flags SLOT FLAGS
get-fd-flags SLOT
set-fd-flags SLOT FLAGS
poll-many COUNT [FD_MODE FD_ARG EVENTS]...
```

`POINTER_MODE=0` selects harness-owned memory and `1` selects address `1`.
Poll fd mode `0` resolves a logical slot; mode `1` admits only the literals
`-2`, `-1`, and `INT_MAX`. Flags come from bounded dictionaries containing all
valid v1 combinations and fixed unknown bits. Other spellings fail closed.

Real fds returned by creation and duplication never enter canonical bytes or
trace identity. The harness maps them to logical slots; successful duplication
results are normalized to zero. Before a read it fills a 16-byte buffer with
`0xa5`, then traces the syscall result, exact errno, decoded first eight bytes,
and all 16 bytes. This distinguishes `<8`, `=8`, and `>8` lengths, invalid
pointers, successful values, and an untouched suffix. Write traces result and
errno. Flag operations trace only normalized `O_NONBLOCK` or `FD_CLOEXEC`.
Poll traces every two-byte `revents` in input order after initializing them to
`0x5a5a`, so ignored, invalid, duplicate, and unready entries remain visible.

Trace v1 binds its normalized records to the canonical scenario count and host
`uname`. Malformed input, version mismatch, incomplete trace, trailing records,
or operation-kind mismatch returns nonzero. The trace is run-owned expected
data and is never checked into the corpus.

## Nonblocking and resource validity invariant

The immutable IR tracks event objects, open-file-description identities, live
logical fd aliases, shared nonblocking state, and per-fd close-on-exec state.
Validation applies operations in order and commits modeled state only for calls
whose success is statically guaranteed by the bounded input:

- valid creation flags create a live object; deliberately invalid creation is
  an error-path operation and creates no resource;
- a valid `dup*` source updates the destination alias according to Linux fd
  rules; an invalid source, illegal flags, or `dup3` same-slot call leaves state
  unchanged;
- close of a live slot closes that alias; close or use of a dead slot remains a
  safe explicit `EBADF` path;
- positive valid-pointer read on an empty object is allowed only when the
  shared description is known nonblocking;
- a write that could exceed `UINT64_MAX-1` is allowed only when that shared
  description is known nonblocking; and
- invalid lengths, invalid pointers, invalid/dead resources, zero writes, flag
  queries/mutations, and timeout-zero poll are accepted only where the fixed
  Linux ordering proves they cannot sleep.

Generation and mutation update a conservative counter interval solely for the
blocking proof. Unknown-result error paths do not guess a state transition.
Mutation may synthesize an explicit nonblocking setup while repairing an
otherwise useful candidate. Reduction never synthesizes setup; it deletes or
simplifies operations and accepts only codec-valid, nonblocking candidates with
a strictly smaller complexity key.

## Adapter and common-framework boundary

The internal `scripts/linux_oracle/` package receives one immutable
`AdapterSpec`. The spec owns identity and injected capabilities:

- adapter, corpus, generator, and metadata compatibility versions;
- campaign root, artifact filenames, QEMU case, environment variable, success
  marker, profraw path, coverage object, target-set ID, and source set;
- codec parse/serialize/combine/validation and canonical digest;
- deterministic generator, structured mutation, resource-aware reducer, and
  complexity/fingerprint hooks;
- host build/record, parser-rejection classification, guest result
  normalization, and adapter-specific legacy metadata loaders; and
- optional extensions such as the pipe importer/projection, which call the
  common execution boundary without entering the common package.

The common package owns only mechanics with identical meaning for both real
adapters:

- deterministic batch preparation and one host-record/guest-compare lifecycle;
- QEMU command construction, artifact validation, pinned-ELF handling, typed
  guest failures, and fresh profraw ownership;
- atomic directory/file replacement, campaign locking, batch/run storage,
  strict new-schema validation, resumable tasks, and failure classification;
- profraw merge, source-set coverage region extraction, exact attribution,
  deterministic representative selection, minimization scheduling, and replay
  argument construction.

No common module may import pipe or eventfd scenario modules, contain their
artifact names, QEMU case names, environment variables, target IDs, source
paths, or operation types. The contract test instantiates a third fake adapter
with different values and exercises save/load/batch/replay construction.

Pipe and eventfd retain their IR, resource model, canonical codec, generator,
mutation, reducer, C harness, target-source definition, semantic fingerprint,
and normalization. The existing `scripts/pipe-oracle/*.py` paths remain
executable compatibility wrappers. The pipe syzkaller importer and projection
remain pipe-only extensions and continue to call the same pipe wrapper API.

## Persistence and compatibility

New shared metadata uses a distinct strict schema. Every document includes:

```json
{
  "schema_name": "linux-oracle-...",
  "schema_version": 1,
  "adapter_id": "eventfd-v1",
  "scenario_sha256": "...",
  "target_set_id": "eventfd-v1"
}
```

Each schema defines an exact key set. Unknown/missing fields, unknown versions,
the wrong adapter, noncanonical scenario bytes, scenario digest mismatch,
artifact digest/size mismatch, symlinks, unexpected files, trace replacement,
or ELF replacement fail closed before replay or recovery.

All pipe corpus schemas v1-v4, run schemas through v7, failure schemas v1-v3,
attribution schemas v2-v6, minimization schemas v1-v5, coverage-state schemas
v1-v4, and import-job schema v1 remain owned by their existing strict readers.
Their paths stay under `coverage/pipe-oracle-fuzz`; `pipe.ops`, canonical bytes,
digests, metadata, and completed/ignored job directories are never rewritten
merely because the common package exists. Existing pipe wrapper calls preserve
their current objects, exceptions, CLI options, output, and ordering. New
generic schemas are used for eventfd and for new explicitly generic tasks only.

Rollback stops creating eventfd/generic work. Existing pipe state continues to
load through its legacy readers. Existing eventfd work must be resumed or
archived as an owned unit; it is never silently converted to pipe or another
adapter.

## Coverage, attribution, and minimization

The eventfd target set contains the Starry event object, eventfd syscall entry,
shared fd flag/dup implementation, scalar read/write path, and timeout-zero poll
path. Stable region IDs are `source:line:column`. Coverage state is scoped by
both the exact instrumented Starry ELF digest and target-set ID.

A passing batch with regions outside that baseline creates a resumable exact-
attribution task. Every canonical entry is replayed separately with a fresh
host trace and profraw. The common greedy cover chooses the entry with greatest
uncovered gain and canonical digest as tie-breaker, removes redundant entries,
then proves the selected union in a fresh replay before baseline admission.
Incomplete or unstable attribution preserves all evidence and leaves the
baseline unchanged.

The resource-aware reducer deletes scenarios/operations and simplifies typed
parameters while preserving operation origins. Coverage minimization preserves
the representative's assigned region set. Mismatch minimization preserves the
original operation and complete normalized difference fingerprint. One original
validation and two consecutive final proofs are mandatory; a bounded candidate
budget may produce `already-minimal`, `minimized`, or `budget-limited`, never a
false success.

## Linux/Starry difference policy

Any eventfd semantic mismatch stops Stage 5 acceptance. The response is:

1. add a raw-`syscall(SYS_...)` regression to the existing eventfd2 Starry test
   that necessarily fails on the observed implementation;
2. record the Linux return value, errno, buffer/state effect, fixed source line,
   and the Starry call path;
3. fix the production boundary rather than the comparator or corpus weights;
4. run `cargo fmt`, `cargo xtask clippy --package starry-kernel`, the raw
   regression, and the original saved differential scenario; and
5. resume acceptance only after the exact scenario compares cleanly.

Filtering the parameter, lowering its generation probability, changing the
expected trace, relaxing errno/data comparison, or increasing a timeout is not
an acceptable resolution.

## Validation and acceptance gates

Unit and contract tests must cover:

- canonical codec round trips and every operation;
- normal/semaphore counters, zero and boundary writes, short/exact/long reads
  and writes, invalid pointers, and untouched read suffixes;
- alias state, use after close, shared `O_NONBLOCK`, independent `FD_CLOEXEC`,
  `dup2`/`dup3` replacement, illegal flags, and poll readiness/order;
- deterministic generation/mutation, resource-valid reduction, origin and
  mismatch fingerprint preservation;
- strict metadata keys, wrong-adapter/digest/trace/ELF tampering, recovery
  ordering, and repeatability;
- every existing pipe Python regression and the importer-v2/projection-v3
  golden contracts; and
- a fake adapter with distinct artifact, QEMU, environment, root, and coverage
  values, plus a static no-adapter-constant scan of `scripts/linux_oracle/`.

Runtime acceptance runs serially:

1. pipe, eventfd, and common Python unittest groups;
2. `py_compile` for every affected Python module;
3. host record three times for the fixed eventfd corpus, requiring identical
   normalized traces, followed by host compare;
4. `cargo fmt` and `cargo xtask clippy --package starry-kernel`;
5. the existing `qemu/system/syscall-test-eventfd2` subcase;
6. explicit x86_64 `qemu/pipe-linux-oracle` and
   `qemu/eventfd-linux-oracle` comparisons with fresh coverage;
7. fixed `seed=42`, four batches, 32 candidates per batch, and `max-qemu=64`,
   requiring one exactly attributed, stable corpus entry;
8. at least one completed coverage minimization (`minimized` or
   `already-minimal`) followed by a passing final replay; and
9. `git diff --check`.

The case remains `default_run = false`, so default test discovery and CI cost
do not change. Physical-board and self-hosted validation are not applicable:
this adapter deliberately uses one native/static x86_64 ELF on host Linux and
Starry x86_64 QEMU.

## Syscall impact map

This stage adds a test adapter and does not intentionally change production
syscall behavior. The comparator nevertheless observes each entry separately.

| Syscall | Required differential observation | Standard/reference |
| --- | --- | --- |
| `eventfd` | 32-bit initial value, default normal/blocking flags, logical fd result | [`eventfd(2)`](https://man7.org/linux/man-pages/man2/eventfd.2.html), [Linux source](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L379-L419) |
| `eventfd2` | valid/unknown flags, initial value, nonblock/semaphore/cloexec ownership | [`eventfd(2)`](https://man7.org/linux/man-pages/man2/eventfd.2.html), [Linux source](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L379-L414) |
| `read` | length, pointer, errno, returned value, consumed count, buffer suffix | [`eventfd(2)`](https://man7.org/linux/man-pages/man2/eventfd.2.html), [Linux source](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L214-L245) |
| `write` | exact length, pointer, zero/max value, counter addition and overflow errno | [`eventfd(2)`](https://man7.org/linux/man-pages/man2/eventfd.2.html), [Linux source](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L247-L280) |
| `dup` | same description, new independent descriptor flags, logical result | [`dup(2)`](https://man7.org/linux/man-pages/man2/dup.2.html) |
| `dup2` | same-fd behavior and atomic occupied-destination replacement | [`dup(2)`](https://man7.org/linux/man-pages/man2/dup.2.html) |
| `dup3` | same-fd/unknown-flag `EINVAL`, replacement, optional close-on-exec | [`dup(2)`](https://man7.org/linux/man-pages/man2/dup.2.html) |
| `close` | alias lifetime and use-after-close `EBADF` | [`close(2)`](https://man7.org/linux/man-pages/man2/close.2.html) |
| `fcntl` | shared `O_NONBLOCK`, per-fd `FD_CLOEXEC`, exact invalid-fd/flag results | [`fcntl(2)`](https://man7.org/linux/man-pages/man2/fcntl.2.html) |
| `poll` | timeout-zero readable/writable state, invalid/negative/duplicate ordered entries | [`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html), [Linux eventfd poll](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/eventfd.c#L118-L174) |
