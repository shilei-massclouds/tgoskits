# Starry pipe differential testing with a Linux execution oracle

## Status

Implemented on 2026-07-30, extended with structured scenario generation,
persistent canonical coverage corpus, resumable exact coverage attribution,
and persistent coverage/mismatch minimization on 2026-07-31. Stage 3.2a added
pipe fd/status flags and `dup2`/`dup3` coverage on 2026-07-31. Stage 3.2b-1
added bounded `readv`/`writev`, vector-aware reduction, and the Starry access
capability fix on 2026-08-01. Stage 3.2b-2 added bounded timeout-zero multi-fd
`poll`, per-entry result vectors, and the shared Starry `poll`/`ppoll` scan fix
on 2026-08-01. This document records the design and implementation of the
script-driven pipe differential oracle. Stage 4.1 added the restricted
syzkaller program importer, external-source provenance, and opt-in stable-input
admission on 2026-08-01. Stage 4.2 added lossless pinned `readv`/`writev`
conversion, report schema v2, and deterministic admission selection on
2026-08-01 without changing the oracle IR, trace, harness, coverage target, or
Starry syscall ABI. Stage 4.3 designs an explicit, auditable vector-slice
projection for mixed programs; its implementation and aggregate acceptance are
not yet recorded in this design-only change.

Base: `dev-cov2` at `fb399d055`.

## Decision

Starry pipe compatibility is checked by executing one static x86_64 Linux-ABI
test program twice:

1. the host Linux execution records the result of every operation in a corpus;
2. the same ELF and corpus run in Starry x86_64 QEMU and compare their results
   with the host trace.

Linux is therefore the executable reference. The test does not maintain a second
implementation of pipe semantics in Rust, does not use `strace` as the oracle,
and does not pin a Linux release. Every run records the host release and
architecture so a failure remains reproducible.

x86_64 QEMU is the primary differential platform because the same static ELF
can run natively on the x86_64 Linux host and as a Starry x86_64 userspace
program.

## Problem

Previous iterations introduced three coupled pieces for pipe fuzzing:

- a handwritten Rust pipe state machine (`components/pipe-model`);
- a coverage-guided batch orchestrator in axbuild (`ktest fuzz`);
- a Starry adapter that executes kernel objects and compares them with the
  handwritten model.

The implementation was expensive in two ways. First, it duplicated Linux
behavior: the model had to separately encode empty I/O, reader/writer lifetime,
`PIPE_BUF` atomicity, partial writes, poll masks, capacity rounding, data
ordering, and errno selection. Passing a model comparison could mean that Starry
and the model shared the same wrong assumption. Second, the execution path was
operationally heavy: a coverage baseline QEMU, then one QEMU boot and rootfs
copy per batch.

The audit also identified why a byte-count-only model is especially risky.
Linux pipes use a ring of page-backed `pipe_buffer` slots. Readiness and some
nonblocking writes depend on whether a slot is free and whether the last slot
can be merged, not only on the total number of vacant bytes.

## Users and success criteria

The direct users are Starry filesystem maintainers and developers who need a
high-signal Linux compatibility check.

The implementation is complete when all of the following hold:

- `cargo xtask starry test qemu --arch x86_64 -c qemu/pipe-linux-oracle`
  executes the host oracle and one Starry QEMU boot;
- `cargo xtask starry test qemu --arch x86_64` (without `-c`) does NOT run
  `pipe-linux-oracle` (zero default-run burden);
- `--list` without `-c` does NOT show `pipe-linux-oracle`;
- `--list -c qemu/pipe-linux-oracle` still discovers it;
- one statically linked x86_64 ELF is used for both executions;
- the checked-in corpus contains operations only, never checked-in expected
  results;
- a direct manual case invocation executes the checked-in corpus on the running
  host Linux and generates a fresh expected trace;
- fuzz and replay runs inject their exact saved/generated ELF, corpus, and trace
  into the guest instead of re-recording or substituting checked-in artifacts;
- Starry compares return values, exact errno, scalar poll events, ordered
  multi-fd `revents` vectors, capacity/query values, queued byte counts, bytes
  returned by reads, normalized `O_NONBLOCK`, and per-fd `FD_CLOEXEC`;
- a mismatch identifies the scenario, operation index, operation text, expected
  result, actual result, and recorded host environment;
- malformed corpus or trace input fails closed and returns a nonzero status;
- a deferred fail marker (`AXTEST_COVERAGE_DEFERRED_FAIL`) ensures profraw
  extraction completes before the failure is propagated;
- coverage capture is triggered by writing to `/proc/starry-test-coverage`,
  which is only compiled under `cfg(axtest_coverage)`;
- the manual x86_64 case uses a case-local build config with
  `AXTEST_COVERAGE=y`, and coverage analysis uses the instrumented StarryOS ELF;
- the old Rust semantic model, model adapter, model-only axtest target, and
  coverage-batch orchestrator are removed;
- `scripts/pipe-oracle/fuzz.py` drives coverage-guided mutation using `--seed`,
  `--batches`, `--batch-size`;
- compatible canonical corpus entries and ELF-scoped coverage baselines survive
  campaign restart without admitting duplicate scenarios;
- every region from a productive batch is attributed to at least one concrete
  entry, and only a deterministically selected representative cover is admitted;
- an interrupted attribution job resumes before new batches, while unstable
  attribution preserves its complete evidence and leaves the coverage baseline
  unchanged;
- guest execution has typed results so infrastructure failures cannot be
  reported as semantic mismatches;
- productive coverage representatives and semantic mismatches are minimized by
  a deterministic structured reducer with a bounded QEMU budget;
- minimization resumes before new RNG consumption, pins one Starry ELF, and
  requires one original validation plus two consecutive final proofs;
- coverage minimization preserves each representative's assigned region set,
  while mismatch minimization preserves the original operation and complete
  semantic fingerprint;
- `scripts/pipe-oracle/replay.py` replays saved failure artifacts;
- `scripts/pipe-oracle/import_syz.py` classifies a pinned, restricted
  syzkaller program subset without mutating persistent state by default;
- explicit `import_syz.py --admit` requires three byte-identical host traces,
  persists every QEMU result before attribution, and admits only exactly
  attributed new coverage;
- importer v2 losslessly maps the bounded pinned `readv`/`writev` syntax into
  the existing v4 vector operations;
- explicit `--project-vector-slices` first attempts the unchanged lossless
  conversion and only projects a rejected mixed program;
- importer v3 emits at most four deterministic resource-closed scenarios,
  repairs only the execution environment needed for synchronous vector I/O,
  and records every retained, dropped, synthesized, and rejected target call;
- `--max-admit-unique N` selects the lexicographically first `N` accepted
  canonical digests before any host or QEMU execution while retaining every
  source for each selected digest;
- imported corpus and failure artifacts retain the original `.syz`, pinned
  syzkaller revision, importer version, and conversion-log digest;
- failure artifacts include `input.bin`, `pipe.ops`, `linux.trace`,
  `pipe-linux-oracle` ELF, `guest.log`, profraw files, and `metadata.json`;
- Starry's production pipe fixes are retained.

## Non-goals

The first implementation deliberately excludes:

- blocking operations, timing comparisons, scheduler interleavings, multiple
  concurrent writers, and signal-delivery timing;
- `epoll`, `select`, FIFO pathname/open semantics, `splice`, `tee`, and
  `vmsplice`;
- `preadv`/`pwritev`, multi-fd `poll`, `select`/`epoll`, exec-time fd lifecycle,
  and blocking fd/pipe semantics in stage 3.2b-1;
- `ppoll` differential input, bad `pollfd *`, excessive `nfds`, nonzero or
  infinite poll timeouts, signal masks, thread-close races, and blocking poll
  semantics in stage 3.2b-2;
- a general syscall differential framework or a stable public corpus/trace
  protocol;
- a Linux VM pinned to a specific kernel release;
- coverage-guided mutation in the regular PR path or CI;
- a globally minimal scenario or an unbounded minimization search;
- using output from `strace` as expected data;
- dynamic `axbuild` subcommands for fuzzing (all host orchestration is in
  Python scripts outside `cargo xtask`).
- building or running `syz-manager`, `syz-executor`, or another syzkaller
  runtime as part of import;
- accepting arbitrary syzkaller calls, threaded/async/repeat properties,
  blocking I/O, memory aliases, nonzero poll timeouts, or vector calls other
  than bounded `readv`/`writev` in the Stage 4.2 importer;
- claiming that a Stage 4.3 projected scenario is semantically equivalent to
  its complete source program, or using projection without a fresh Linux
  oracle trace;
- repairing vector count, segment length, pointer mode, payload, memory alias,
  fd direction, or source call order during Stage 4.3 projection;
- changing `pipe.ops` v4, trace v4, the C harness operation set, or the
  `pipe-poll-v4` coverage target for imported programs.

## Alternatives considered

| Alternative | Benefit | Cost or failure mode | Decision |
|---|---|---|---|
| Keep and repair `pipe-model` | Fast unit-level comparisons | Permanently duplicates Linux semantics; already drifted; can share Starry's incorrect abstraction | Reject |
| Pin Linux 5.15 | Stable long-lived golden behavior | Adds image/toolchain maintenance | Reject |
| Use the running Linux host | No kernel image lifecycle; tests the environment developers actually use | A Linux upgrade can change the oracle; metadata and review required | Select |
| Record `strace` output | Easy ad-hoc inspection | Text is unstable; incomplete as a comparison protocol | Reject |
| axbuild subcommand for fuzzing | Integration with existing CLI | Adds coupling to axbuild's already complex surface; fuzzing is a dev-time activity | Reject; use Python scripts |
| Default CI integration | Catches regressions automatically | Adds QEMU boot overhead to every PR; signal may not justify cost | Reject; manual-only `default_run=false` |
| Coverage-guided in default path | Better corpus growth | Too heavy for regular CI; belongs in manual fuzz workflow | Reject for v1 |
| Byte-level minimization | Simple implementation | Breaks resource relationships and spends QEMU launches on malformed inputs | Reject; reduce the scenario IR |
| Structured hierarchical delta debugging | Preserves operation/resource structure and gives deterministic checkpoints | Does not guarantee a global minimum | Select with a bounded candidate budget |
| Encode vector I/O as one flat byte count | Reuses scalar operations | Cannot compare segment boundaries, short-transfer placement, or untouched memory | Reject; use typed bounded segments |
| Fix vector errno ordering with pipe-specific syscall branches | Small local patch | Duplicates access policy and leaves regular files/directories/memfd inconsistent | Reject; add a `FileLike` capability boundary |
| Encode multiple poll entries as repeated scalar `poll` operations | Reuses version-1 result fields | Loses array order, duplicate-fd counting, mixed invalid/ready behavior, and one-call semantics | Reject; add a typed bounded poll array |
| Fix only `sys_poll` | Narrows the immediate patch | Leaves `ppoll` inconsistent even though both enter the shared implementation | Reject; fix shared `do_poll` and add direct regressions for both syscalls |
| Run the syzkaller runtime during import | Reuses upstream execution and scheduling | Adds Go/runtime dependencies, a second executor, and non-deterministic features outside the oracle ABI | Reject; parse a pinned syntax subset in Python |
| Treat accepted `.syz` files as corpus immediately | Simple ingestion | Admits host-unstable inputs and entries with no new, attributable coverage | Reject; require explicit stable admission |
| Add new importer-only vector operations | Can mirror arbitrary syzkaller vectors | Forks the v4 codec, C harness, trace, reducer, and comparator contracts | Reject; accept exactly the vector boundary already represented by v4 |
| Stop after the first `N` host-stable or QEMU-tested inputs | Avoids some later execution | Selection depends on host results, batching, and interruption point | Reject; select a canonical-digest prefix before execution |
| Select the first `N` source paths | Simple to explain | Duplicate canonical inputs consume the limit and path renames change execution | Reject; bound unique canonical digests and retain all selected sources |
| Loosen the lossless importer for mixed programs | Fewer explicit modes | Silently changes the established importer-v2 contract and makes dropped behavior unauditable | Reject; keep v2 byte-compatible and require an opt-in v3 mode |
| Minimize the complete syzkaller program first | Reuses upstream reduction concepts | Requires executor semantics and still cannot guarantee synchronous pipe execution | Reject; derive a bounded resource slice and re-record Linux truth |
| Keep every call that parses | Preserves more source text | Unsupported consumers can mutate or close a selected fd through semantics the oracle cannot represent | Reject; use fail-closed resource barriers |
| Project one scenario per source | Smaller reports | Conflates independent vector targets and makes the chosen target depend on incidental source shape | Reject; create one ordered scenario per target and deduplicate canonically |

## Architecture

### Manual-only QEMU case

The pipe oracle is a QEMU case with `default_run = false` and
`asset_cache = "bypass"`:

```toml
# test-suit/starryos/qemu/pipe-linux-oracle/qemu-x86_64.toml
asset_cache = "bypass"
default_run = false
```

`default_run` controls default discovery:
- `true` (default): the case participates in batch execution and `--list`
- `false`: the case is skipped unless explicitly requested via `-c`

Only `pipe-linux-oracle` uses `default_run = false`. All existing cases are
unaffected.

### One executable, two modes

The C harness has two modes:

```
pipe-linux-oracle --record  CORPUS TRACE
pipe-linux-oracle --compare CORPUS TRACE
```

During `--record`, the harness executes every operation on the host Linux,
saves the operation results in binary trace format, and records host `uname`
metadata.

During `--compare`, the same ELF reads the ops corpus, executes operations in
Starry, and compares each result with the expected trace.

### Version-2 fd and flag operations

`pipe.ops` version 1 remains readable byte-for-byte. Its two-argument `pipe2`
continues to mean `O_NONBLOCK | O_CLOEXEC`, so legacy canonical digests do not
change. New generation and mutation use version 2, whose added forms are:

```
pipe2 READ_SLOT WRITE_SLOT FLAGS
get-status-flags SLOT
set-status-flags SLOT FLAGS
get-fd-flags SLOT
set-fd-flags SLOT FLAGS
dup2 SOURCE_SLOT DESTINATION_SLOT
dup3 SOURCE_SLOT DESTINATION_SLOT FLAGS
```

Flags are canonical unsigned decimal integers. The version-2 pipe dictionary
contains the four combinations of `O_NONBLOCK` (`2048`) and `O_CLOEXEC`
(`524288`), plus the fixed unknown bit `1073741824` for `EINVAL`. The `dup3`
dictionary contains `0`, `O_CLOEXEC`, deterministic illegal nonblocking
combinations, and the same unknown bit. Other spellings fail codec validation
instead of depending on host-specific flag discovery.

The IR assigns each live logical fd an endpoint, an open-file-description
identity, and a per-fd close-on-exec bit. `O_NONBLOCK` belongs to the shared
description, while `FD_CLOEXEC` belongs to one descriptor. Successful `dup`
and `dup2` clear the destination close-on-exec bit; successful
`dup3(O_CLOEXEC)` sets it. `dup2`/`dup3` atomically replace an occupied
destination. A failed `pipe2`, `fcntl`, `dup2`, or `dup3` leaves the modeled
state unchanged.

The harness stores only `O_NONBLOCK` in `value` for `F_GETFL` and only
`FD_CLOEXEC` for `F_GETFD`. Successful `dup2`/`dup3` results are normalized to
zero, so host and guest fd allocation numbers never enter comparison. Empty
logical destinations use an internal reserved fd range; this detail is not part
of corpus identity. Errno remains exact.

Version 2 rejects positive-length I/O whenever a live description is not
statically known to have `O_NONBLOCK`. Zero-length I/O, operations on a known
invalid slot, and pure fd/flag operations remain safe. Mutation repair may add
explicit nonblocking setup; the reducer never synthesizes initialization.

The trace writer emits version 2 and appends operation-kind numbers 12 through
17 for the six new kinds. It does not reorder the version-1 numbering. Compare
mode still accepts a version-1 trace for a version-1 corpus, while a version-2
corpus requires a version-2-or-newer trace.

### Version-3 vectored I/O

`pipe.ops` version 3 preserves every version-1/version-2 spelling and canonical
digest and adds two bounded forms:

```
readv SLOT IOV_MODE IOVCNT SEGMENT_COUNT [BASE_MODE LENGTH]...
writev SLOT IOV_MODE IOVCNT SEGMENT_COUNT [BASE_MODE LENGTH BYTE]...
```

`IOV_MODE` and `BASE_MODE` are decimal enums: `0` selects harness-owned valid
memory and `1` selects the fixed invalid address `1`. `iovcnt` is restricted to
`-1`, `0..4`, and `1025`; a valid vector has exactly `iovcnt` typed segments,
while an invalid vector pointer or invalid count has none. Segment lengths and
the valid-segment total are bounded by 8192 bytes. These restrictions keep the
grammar strict, the trace fixed-size, and every generated call synchronous.

Positive-length calls on the correct live endpoint require a statically known
`O_NONBLOCK` open-file description. Zero total length, invalid fd, wrong access
endpoint, invalid iovec pointer, and invalid count remain safe because they
return before pipe I/O. A positive invalid base is not treated as proof of
nonblocking safety: an empty pipe may wait for readiness before userspace is
touched.

Trace version 3 appends `readv` and `writev` as operation kinds 18 and 19 without
renumbering older kinds. Before `readv`, every valid destination segment is
filled with `0xa5`; after the syscall, all valid destination segments are
flattened in iovec order into the trace. The comparison therefore observes
cross-segment placement, short reads, and untouched suffixes in addition to the
exact return value and errno. Version-1 and version-2 corpora remain readable;
version-3 corpora require a version-3 trace.

The checked-in version-3 corpus covers empty vectors, zero-length segments,
cross-segment transfer, a 5000-byte nonblocking partial write into a 4096-byte
pipe, invalid vector/base pointers, `iovcnt` boundaries, and bad descriptors.
It contains 142 operations and records/compares self-consistently on the host.

### Version-4 multi-fd poll

`pipe.ops` version 4 preserves every version-1 through version-3 spelling and
canonical digest and adds one bounded form:

```
poll-many COUNT [FD_MODE FD_ARG EVENTS]...
```

`COUNT` is `0..4`, followed by exactly that many triples. `FD_MODE=0` resolves
`FD_ARG` as a logical slot in `0..15`; `FD_MODE=1` uses a literal fd and only
accepts `-2`, `-1`, or `2147483647`. `EVENTS` is a decimal value in
`0..32767`. The syscall timeout is always zero. This represents an empty
array, different descriptors, repeated slots, dup aliases, ignored negative
fds, invalid positive fds, and mixed invalid/ready entries without admitting a
bad array pointer, unbounded `nfds`, or a blocking execution path.

Trace version 4 appends operation kind 20 without renumbering older kinds.
`result` and `errno` retain the exact syscall outcome, `value` is the entry
count, and `data` stores every `revents` value in array order as an unsigned
two-byte little-endian value. Thus `data_len` is exactly `2 * COUNT`. Before
the syscall, the harness fills every `revents` with `0x5a5a`; ignored and
unready entries must therefore be visibly cleared by the kernel rather than
passing because the harness initialized them to zero. Version-4 corpora
require a version-4 trace, while older corpus/trace pairs remain readable.

The immutable IR uses `PollMany`, `PollFdEntry`, and a typed slot/literal fd
mode; the older scalar `Poll` remains unchanged. Generator version 5 emits new
version-4 entries and strictly restores corpus created by generator versions
2, 3, 4, and 5. Mutation changes entry count, insertion/deletion/duplication,
order, fd mode/argument, and event masks. Repair preserves valid mode/argument
combinations and may construct executable nonblocking resource setup; the
reducer never constructs setup, deduplicates candidates, preserves operation
origins, and accepts only a strictly lower well-founded complexity key.

The checked-in version-4 corpus covers an empty array, multiple slots, repeated
slots, dup aliases, both negative literals, an invalid positive literal,
invalid/ready mixtures in both orders, different masks, and closed-peer
`HUP`/`ERR`. It contains 162 operations and records/compares
self-consistently on the host.

### Linux ordering evidence and Starry boundary

The production ordering reference is Linux commit
[`a2cf4ef33184df0ae9e1a2b05b550133dde1698c`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/read_write.c#L989-L1113),
observed on 2026-08-01. `do_readv`/`do_writev` first resolve the fd, then
`vfs_readv`/`vfs_writev` reject missing `FMODE_READ`/`FMODE_WRITE`, and only then
call `import_iovec`. This is also the ordering required by the project syscall
compatibility target for `readv` and `writev`.

The same commit's
[`import_iovec`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/lib/iov_iter.c#L1342-L1443)
uses `access_ok` to reject a segment outside the user address limit without
requiring its pages to be mapped. Actual mapping faults occur during iterator
copy. For an empty nonblocking pipe,
[`anon_pipe_read`](https://github.com/torvalds/linux/blob/a2cf4ef33184df0ae9e1a2b05b550133dde1698c/fs/pipe.c#L361-L491)
therefore returns `EAGAIN` before touching an unmapped in-range destination.

The development host was Linux `5.15.0-186-generic`. Its raw syscalls returned
`EBADF` for bad-fd plus bad-iovec conflicts, but returned `EFAULT` for a valid
wrong-access fd plus a bad iovec. That older-host behavior is recorded as
environment evidence; it does not weaken the comparator or change the fixed
upstream production target.

Before the fix, the Starry raw-syscall regression produced 70 passes and four
failures: `writev` imported a bad vector/count before rejecting a bad fd, and
both vector syscalls imported a bad vector before rejecting the wrong access
mode. `FileLike::readable`/`writable` now expose this capability explicitly.
Regular files and directories derive it from open access flags (including
`O_PATH`), pipes derive it from their endpoint, and memfd delegates to its
backing file. `sys_readv` and `sys_writev` check the fd and capability before
constructing an `IoVectorBuf`; there is no pipe-specific syscall branch. The
same guest regression then produced 74 passes and zero failures.

The complete version-3 oracle subsequently exposed a second ordering defect:
Starry's iovec import used the ordinary mapped-user-memory boundary, so address
`1` failed before an empty nonblocking pipe could report `EAGAIN`.
`IoVectorBuf` now performs only the Linux-style user-limit range check at
import and defers mapping faults until a file operation actually reaches the
segment. A raw-syscall regression necessarily failed with 75 passes and one
failure before this fix and passed all 76 checks afterward.

| Raw syscall conflict | Required result | Starry before | Starry after |
|---|---:|---:|---:|
| `readv(-1, bad_iov, 1)` | `EBADF` | `EBADF` | `EBADF` |
| `readv(O_WRONLY, bad_iov, 1)` | `EBADF` | `EFAULT` | `EBADF` |
| `writev(-1, bad_iov, 1)` | `EBADF` | `EFAULT` | `EBADF` |
| `writev(-1, valid_iov, IOV_MAX+1)` | `EBADF` | `EINVAL` | `EBADF` |
| `writev(O_RDONLY, bad_iov, 1)` | `EBADF` | `EFAULT` | `EBADF` |
| `readv(empty_nonblock_pipe, bad_base, 1)` | `EAGAIN` | `EFAULT` | `EAGAIN` |

The separate invalid-count `readv` conflict already returned `EBADF` before
the fix. Keeping it in the regression guards the complete fd-before-count
contract even though it did not expose the original bug.

For multi-fd poll, the authoritative production reference is upstream Linux
`v6.12.37` commit
[`fbad404f04d758c52bae79ca20d0e7fe5fef91d3`](https://github.com/torvalds/linux/blob/fbad404f04d758c52bae79ca20d0e7fe5fef91d3/fs/select.c#L854-L1122).
The local comparison tree at `~/gitStudy/linux-6.12.37` had HEAD
`1f2a63ab718d6a052a3afd2516db319b9b317b63` on 2026-08-01. In the fixed
upstream source, `do_pollfd` ignores every `fd < 0` and writes zero to
`revents`; an invalid positive fd produces `POLLNVAL`. `do_poll` still scans
every array element, counts each nonzero `revents` entry separately, and
therefore counts duplicate descriptors independently. Both `poll` and `ppoll`
enter the same `do_sys_poll`/`do_poll` path.

Before the fix, Starry ignored only `fd == -1`, so `fd=-2` produced
`POLLNVAL` instead of zero and retained the wrong result count. It also
returned immediately after finding an invalid positive fd, leaving a later
ready pipe entry unobserved. The new raw-syscall module mirrors both cases
through timeout-zero `poll` and zero-timespec/null-sigmask `ppoll`; before the
production change it necessarily reported 8 passes and 8 failures.

The shared Starry `do_poll` now clears every entry first, skips all negative
fds, records invalid positive entries, and builds the valid entry set without
returning early. When any invalid entry exists, it collects one immediate
readiness snapshot from every valid array entry and returns without registering
a waiter or blocking. The return count is the number of array elements with a
nonzero `revents`, including repeated fds. There is no pipe-specific branch.
The same raw regression then passed all 16 checks, and the complete select/poll
family passed all 45 modules for both affected syscall entry points.

`poll` is the only new differential ABI in version 4. `ppoll` is documented and
directly regression-tested because it shares the repaired implementation, but
signal-mask, timeout, and `ppoll` corpus encoding remain non-goals.

### Coverage capture and deferred fail

The coverage flow:

1. Guest shell runs oracle `--compare` and captures its exit status immediately.
2. On any nonzero status, the shell prints
   `AXTEST_COVERAGE_DEFERRED_FAIL` after the oracle's detailed diagnostic.
3. Shell writes to `/proc/starry-test-coverage` (a write-only proc node gated
   on `cfg(axtest_coverage)`). Writing to that node calls
   `axtest::dump_coverage()`, which calls `xcover::write_profraw()` and prints
   an `AXTEST_COVERAGE status=ready` marker.
4. The host-side `AxtestCoverageCaptureGuard` filters the deferred fail
   marker from the terminal output during profraw extraction.
5. After profraw extraction completes via QEMU monitor `memsave`, the capture
   layer emits `AXTEST_COVERAGE_DONE`, asks the same monitor to quit QEMU, and
   then propagates the deferred fail marker (if mismatch occurred).
6. In coverage mode, the QEMU runner's success regex set is replaced completely
   by `AXTEST_COVERAGE_DONE`; ordinary case-specific success markers cannot stop
   QEMU early. The original regexes remain the outer host-side success contract,
   while `capture.finish()` requires a complete profraw before accepting the
   monitor-driven exit. If the deferred fail marker is present or the
   `STARRY_PIPE_LINUX_ORACLE_PASSED` marker is absent, the test fails with the
   profraw already saved.

This ensures that a mismatch never loses the coverage profile: the profraw
is extracted before the failure is propagated.

### `default_run` support in axbuild

The `QemuCaseExtraConfig` struct in `scripts/axbuild/src/test/qemu/types.rs`
gains `default_run: bool` (default `true`). When a case has `default_run = false`
and no `-c` is specified:

- `discover_qemu_cases` filters it out in `load_qemu_cases_for_selection`
  (`starry/test/qemu_discovery.rs`);
- `discover_all_qemu_cases_with_archs` filters it out in
  `qemu_case_has_default_run` (`starry/test/suite.rs`).

All `TestQemuCase` constructors in the codebase set `default_run: true` so
existing cases are unaffected.

### `/proc/starry-test-coverage`

Gated on `#[cfg(axtest_coverage)]`, the procfs builder in
`os/StarryOS/kernel/src/pseudofs/proc.rs` registers a write-only node. Writing
to it calls `axtest::dump_coverage()`. Without `cfg(axtest_coverage)`, the node
does not exist and the production kernel carries no coverage-related code.

### Script-driven fuzz and replay

`scripts/pipe-oracle/` contains:

- `common.py`: SHA-256 hashing, atomic directory save, `build_metadata()` that
  captures git commit, dirty state, host uname, page size, and file digests.
- `corpus.py`: Canonical digest map, strict schema-v1/v2/v3/v4 persistent entry
  validation, active/superseded lifecycle, minimization lineage, atomic
  entry/run/coverage-state saves, typed external source provenance, ELF-scoped
  region baselines, and exact-attribution admission.
- `campaign_lock.py` and `corpus_errors.py`: Process-lock ownership and shared
  persistent-state error types.
- `attribution.py` and `attribution_schema.py`: Atomic schema-v6 attribution
  jobs (plus strict schema-v2/v3/v4/v5 recovery), target-set-aware evidence
  validation, deterministic representative selection, and resumable state
  transitions.
- `attribution_campaign.py`: Fresh host-trace and QEMU replay orchestration,
  cross-campaign ELF restart, final representative proof, and baseline commit.
- `scenario.py`: Immutable scenario/operation IR plus the version-1 through
  version-4 `pipe.ops` parser, canonical serializer, digest, typed codec errors,
  shared open-file-description state, per-fd flags, typed vector segments,
  typed poll arrays, and campaign limits.
- `generator.py`: Version-5 deterministic operation generation using a
  versioned SHA-256 counter stream and rejection sampling. It maintains only
  logical fd resource state and never predicts return values, errno, poll
  readiness, or any semantic result. The version-1 LCG remains only for the five
  initial-seed migrations and offline comparison.
- `mutation.py`: Structured insertion, deletion, replacement, adjacent swap,
  fragment duplication/deletion, donor splice, and parameter mutation. It
  repairs dependencies needed for executable candidates and explicitly labels
  codec/limit failures as malformed.
- `guest_result.py` and `fingerprint.py`: Typed guest result classification,
  stable harness-difference parsing, and mismatch fingerprints anchored to an
  original operation identity.
- `artifact.py`: Strict failure schema-v1/v2/v3 replay validation, fixed Starry
  and host ELF digests, typed result/fingerprint metadata, imported source
  evidence, and atomic save.
- `reducer.py` and `minimization.py`: Pure deterministic hierarchical reduction,
  operation-origin tracking, coverage responsibility assignment, mismatch
  predicate checks, digest deduplication, and shared candidate-QEMU budgets.
- `minimization_schema.py` and `minimization_store.py`: Strict schema-v5 job and
  evidence validation (plus schema-v1/v2/v3/v4 recovery), atomic checkpoints,
  reducer cursor persistence, target-set pinning, and stale/unstable failure
  preservation.
- `minimization_source.py`, `minimization_campaign.py`, and `minimize.py`:
  failure/attribution source import, fresh trace/profraw predicate execution,
  two final proofs, corpus/failure commit, automatic recovery, and the manual
  minimization CLI.
- `runner.py`: validates one absolute artifact directory, passes it to the QEMU
  build through `STARRY_PIPE_ORACLE_ARTIFACT_DIR`, deletes the fixed profraw
  before every launch, and returns only this run's
  `starryos-x86_64-unknown-none.profraw` as a typed execution result.
  Attribution and minimization replays also pass their content-addressed Starry
  ELF to axbuild's internal kallsyms pinning contract.
- `coverage.py`: `llvm-profdata merge -sparse` and `llvm-cov export` against
  `target/x86_64-unknown-none/release/starryos`; target-set source regions use
  stable `source:line:column` string IDs.
- `fuzz.py`: Batch fuzzing with seed, batch count, batch size, minimization
  budget, and a `--no-minimize` rollback switch. Startup resumes attribution,
  creates or resumes minimization, reloads active corpus entries, and only then
  initializes RNG. Selection remains 30% new generation and 70% structured
  mutation. Malformed candidates are counted and filtered before host/QEMU
  execution. Each executable batch runs one QEMU; mismatch/panic/timeout/
  coverage failure stops immediately and saves a complete failure artifact to
  `coverage/pipe-oracle-fuzz/failures/`.
- `batch_execution.py` and `host_runtime.py`: Scenario-independent shared batch
  preparation, host recording, and Starry comparison used by both `fuzz.py`
  and the importer.
- `syz_parser.py`, `syz_ast.py`, and `syz_converter.py`: Strict parser and
  typed conversion for the pinned syzkaller syntax subset, with stable syntax
  and semantic rejection categories.
- `syz_import.py` and `import_syz.py`: Deterministic discovery, check-only JSON
  reporting, and the opt-in admission CLI.
- `import_schema.py`, `import_store.py`, and `syz_admission.py`: Atomic
  source/conversion evidence, resumable host/QEMU progress, exact attribution,
  minimization, and imported run/failure recording.
- `replay.py`: Replays a saved failure. Validates schema, digests, ELF type.
  Runs the same guest QEMU with the saved artifacts. `--refresh-host`
  re-records the host trace without overwriting original evidence.

Constraints:
- A canonical corpus entry is UTF-8 `pipe.ops` and is at most 4096
  bytes; failure `input.bin` and `inputs/*.{bin,ops}` store those exact bytes.
- One entry contains at most four scenarios and one scenario contains at most
  32 operations.
- A fixed seed and generator version produce byte-identical corpus selection,
  batch serialization, and mutations across processes.
- Codec failures carry a stable category and line number. Malformed mutation
  candidates never enter host or StarryOS execution batches.

### Restricted syzkaller import

Stage 4.2 accepts external programs only through the pinned syzkaller revision
`e611ffe1caa28a0228c8f3642cc768f0dba3dd0c`. The importer is pure Python: it
does not build or invoke Go code, `syz-manager`, `syz-executor`, or
`syz-prog2c`. The pinned checkout is optional and is used only for a one-time
fixture compatibility check. The accepted grammar is based on the pinned
[program syntax](https://github.com/google/syzkaller/blob/e611ffe1caa28a0228c8f3642cc768f0dba3dd0c/docs/program_syntax.md)
and Linux descriptions in pinned
[`sys/linux/sys.txt`](https://github.com/google/syzkaller/blob/e611ffe1caa28a0228c8f3642cc768f0dba3dd0c/sys/linux/sys.txt).

The default command only discovers, parses, converts, and reports:

```sh
./scripts/pipe-oracle/import_syz.py \
  --syzkaller-revision e611ffe1caa28a0228c8f3642cc768f0dba3dd0c \
  --report /tmp/pipe-syz-report.json \
  PATH...
```

`PATH` is an ordinary `.syz` file or a recursively scanned directory. Results
are sorted by absolute path, duplicate paths are collapsed, symlinks are
reported as rejections, and an individual file is limited to 64 KiB.
Classification returns zero even when some programs are rejected. Discovery,
I/O, revision, persistent-state, host-build, QEMU, and semantic failures return
nonzero. The optional report is atomically replaced. Check-only mode never
creates or changes `coverage/pipe-oracle-fuzz/`. Report schema v2 retains every
classification and adds `admission_selection`: policy `canonical-digest`, the
optional unique limit, eligible/selected/deferred unique counts, and sorted
selected/deferred digest lists. With no admission limit, every eligible digest
is selected.

The Stage 4.2 call allowlist is:

- `pipe` and `pipe2`;
- `read`, `write`, `readv`, `writev`, `close`, `dup`, `dup2`, and `dup3`;
- `fcntl$getflags`, `fcntl$setflags`, `fcntl$setstatus`, and `fcntl$setpipe`
  only for the commands represented by the v4 IR;
- `ioctl$int_out` only for `FIONREAD`; and
- `poll` only with timeout zero and `nfds` from zero through four.

Result captures are assigned deterministic logical slots `0..15`. Conversion
rejects undefined or duplicate resources, resource arithmetic, use after
close, positive blocking I/O, nonuniform positive write payloads, unsupported
buffers or vectors, overlapping anchored memory, nonzero `poll` timeout,
nonzero input `revents`, array/`nfds` disagreement, call properties,
pseudo-syscalls, and every call outside the allowlist. `&AUTO` denotes an
independent valid region. Positive writes preserve only a uniform effective
prefix; zero-length I/O preserves whether the pointer is valid. Poll arrays
preserve entry order, duplicate resources, literal fds, events, and zero input
`revents`. The existing IR validator remains authoritative for nonblocking
proofs and entry, operation, slot, and encoding limits.

Importer version 2 accepts assignment-free, three-argument `readv` and
`writev` calls only. The fd follows the same live-resource and close-generation
rules as scalar I/O. The outer iovec pointer remains either valid or invalid;
supported `iovcnt` values are `-1`, `0..4`, and `1025`. A valid pointer has
exactly `iovcnt` entries for counts `0..4` and no entries for the two invalid
count boundaries. Each entry is the pinned two-field iovec struct. The sum of
at most four segment lengths is at most 8192 bytes. Each base independently
preserves valid/invalid pointer state, including at length zero. Valid buffers
must be initialized ordinary strings of at least the segment length; every
positive `writev` segment prefix must repeat one byte, while different segments
may use different bytes. Positive executable vector I/O still requires the v4
validator's static `O_NONBLOCK` proof.

The stable `vector-shape` rejection covers invalid array/count relationships,
more than four segments, invalid or complex nested buffer shapes, and per-
segment or total sizes outside the v4 boundary. Existing stable categories
continue to distinguish nonuniform payloads, anchored overlap within a call or
across calls, blocking I/O, and entry limits. `preadv`, `pwritev`, `preadv2`,
`pwritev2`, and `vmsplice` remain `unsupported-call`. Anchored x86_64 iovec
descriptors use their 16-byte ABI extent for overlap checks; `&AUTO` regions are
independent allocations under the pinned serializer contract.

Admission is explicit:

```sh
./scripts/pipe-oracle/import_syz.py \
  --syzkaller-revision e611ffe1caa28a0228c8f3642cc768f0dba3dd0c \
  --workspace . \
  --admit --max-admit-unique 8 \
  --host-repetitions 3 --batch-size 8 --max-qemu 64 \
  PATH...
```

`--max-admit-unique` is optional, requires `--admit`, and must be positive.
Before persistence or execution, accepted canonical digests are sorted and the
first `N` are selected. Every original source that maps to a selected digest is
retained, while rejected and deferred sources remain only in the top-level
report. Deferred digests perform zero host records and zero QEMU launches. The
import-job schema remains v1 and therefore records the selected set implicitly
through its canonical inputs; no persistent schema migration is required.

The command holds the campaign lock for recovery and new work. It first
resumes import jobs, including their child attribution and minimization jobs,
then resumes unrelated global attribution and minimization work. This ordering
keeps every resumed child launch inside its import job's total QEMU budget.
Saved jobs, including importer-v1 jobs, are always resumed before applying the
new report's selection. A v1 job cannot match or suppress an importer-v2 report.
Every unique canonical input is recorded on the host three times by default,
and the normalized trace bytes must be identical. Stable inputs are grouped in
canonical-digest order. Each group gets one fresh host trace and one Starry
comparison. The complete batch evidence is atomically saved before its
progress record, so a restart does not repeat that QEMU execution.

A passing batch with no regions outside the active ELF baseline completes as
`passed-no-new-coverage` and does not enter canonical corpus. A productive
batch continues through the existing exact attribution and structured
minimization state machines. Only proved representatives are admitted; their
corpus provenance contains every sorted, deduplicated `ExternalSource` that
converted to that canonical digest. The total import QEMU budget includes the
initial batch, attribution replays, minimization validation, candidates, and
two final proofs. Insufficient budget is a terminal
`qemu-budget-exhausted` result rather than an implicit overrun.

Guest mismatch, panic, lockdep, timeout, oracle failure, missing coverage, or
infrastructure failure stops admission. An imported failure uses schema v3 and
contains `source.syz`, `conversion-log.json`, their digests, the full revision,
importer version, combined `pipe.ops`, trace, guest log, ELFs, and profraws.
Mismatch minimization preserves that v3 source evidence. No importer-specific
operation or comparator exception is added to the C harness.

The version bump changes only new conversion provenance and report matching.
Strict readers continue to accept existing importer-v1 jobs, external-source
provenance, imported failures, and corpus entries because importer version is a
nonempty provenance identifier rather than a persistent schema discriminator.
Rollback can stop creating importer-v2 jobs without rewriting existing state;
active saved jobs must still be resumed or archived under the normal campaign
ownership rules.

#### Stage 4.2 pinned-corpus acceptance gate

The aggregate external acceptance remains blocked until a user supplies a
corpus directory known to come from the pinned revision. The raw external
corpus is never committed. Acceptance will recursively inspect ordinary `.syz`
files, reject symlinks, deduplicate by raw SHA-256, and retain only programs
whose AST contains both `pipe`/`pipe2` and `readv`/`writev`. Candidates are
ordered by `(program SHA-256, path)` and the first 100 are used. Fewer than 100
eligible programs blocks acceptance; handwritten samples do not fill the gap.

The 100 inputs first run check-only classification. Admission then uses
`--max-admit-unique 8 --max-qemu 64 --batch-size 8 --host-repetitions 3`.
The acceptance-only documentation commit will record the SHA-256 of the whole
ordered input manifest, accepted/rejected/unique counts, rejection categories,
host stability, QEMU counts, coverage across the seven target files, exact
attribution rate, and sizes before/after minimization. Until that evidence
exists, fixed fixtures and local regression/host/QEMU validation prove the
implementation boundary but do not claim pinned-corpus aggregate acceptance.

### Auditable vector-slice projection (Stage 4.3 design)

#### Problem, users, and acceptance boundary

The Stage 4.2 lossless importer intentionally rejects a complete program when
any call is outside its synchronous v4 boundary. In the pinned 100-program
sample, this admitted one program even though many rejected programs contained
a bounded `readv` or `writev` whose descriptor originated from a pipe. Running
the complete programs would require the syzkaller executor, unsupported
syscalls, blocking and scheduling semantics, and resources outside the pipe
oracle. Discarding every such program, however, leaves useful vector shapes and
payloads unexamined.

Stage 4.3 serves pipe-oracle maintainers who want to derive independently
executable pipe scenarios from those mixed programs without weakening the
lossless contract. It is a high-risk feature because it adds report and
conversion-evidence formats and deliberately transforms external input. It is
complete only when:

- the default command remains importer v2/report schema v2 and produces the
  same canonical bytes and schema-v1 conversion logs as Stage 4.2;
- `--project-vector-slices` explicitly selects importer v3/report schema v3,
  tries the unchanged lossless conversion first, and projects only after that
  conversion rejects the program;
- every projected scenario contains a `readv` or `writev` target whose fd
  resource resolves to `pipe`/`pipe2`, preserves its vector and memory shape,
  and passes the existing v4 codec and resource validator;
- every dropped, retained, repaired, synthesized, deduplicated, or rejected
  decision is path-independent and attributable to source line numbers;
- the pinned 100-program manifest with SHA-256
  `792ec290d50098cb43eba9ec6f8fdd5b5755851dfb74ac044a9c237ebb50adb5`
  yields at least 20 accepted sources and 10 unique canonical documents; and
- bounded admission records three identical host traces for every selected
  input and completes without a mismatch, panic, timeout, missing coverage,
  attribution failure, exhausted budget, or failed job.

The projection is a derived test scenario, not an equivalence claim about the
complete source program. Its expected trace is always regenerated by executing
the derived `pipe.ops` on the current Linux host.

#### Prior art and local boundary

The dependency model follows syzkaller's resource-aware minimization at pinned
revision `e611ffe1caa28a0228c8f3642cc768f0dba3dd0c`, specifically
[`prog/minimization.go`](https://github.com/google/syzkaller/blob/e611ffe1caa28a0228c8f3642cc768f0dba3dd0c/prog/minimization.go).
That implementation demonstrates that a call cannot be removed independently
of the resource producers and consumers that make the remaining program
executable. Stage 4.3 borrows that resource-closure principle, but does not
reuse syzkaller's serializer, type database, executor, or equivalence
predicate. The local parser remains pinned, the existing `scenario.py` v4
validator remains the final boundary, and Linux execution supplies truth.

Internally, the Stage 4.2 converter already owns the allowlist, fd generation
checks, anchored-memory overlap checks, vector-shape conversion, payload
validation, and operation/slot/encoding limits. Projection therefore produces
a typed `SyzProgram` slice and sends it through that converter rather than
duplicating or relaxing those rules. A separate projection module owns only
resource selection, environmental repair, scenario ordering, and diagnostics.

#### Opt-in conversion flow

For each ordinary input that parsed successfully, importer v3 performs these
steps in order:

1. Run the unchanged lossless converter over the complete AST.
2. If it succeeds, emit its exact one-scenario document with
   `conversion_kind=lossless`; do not inspect, rewrite, or project calls.
3. If it fails, enumerate `readv`/`writev` targets in source-call order.
4. For each target, resolve its plain fd resource through resource producers,
   descriptor replacement, and `dup*` dependencies to one pipe creation.
5. Retain the selected pipe's connected prefix through the target, repair only
   the synchronous execution environment, and run the resulting typed program
   through the lossless converter.
6. Keep successful target scenarios in target order and discard later
   canonical duplicates while retaining their diagnostics.
7. Accept the source when at least one target succeeds. If no target succeeds,
   reject it as `projection-no-accepted-target`. If the program contains no
   vector target, reject it as `projection-no-vector-target`.
8. If more than four distinct target scenarios succeed, reject the complete
   source as `projection-entry-limit`; do not truncate the source-dependent
   result to the first four.

Only calls at or before a target can enter its scenario. The resource closure
contains the selected `pipe`/`pipe2`, all producer calls needed for a retained
descriptor, and allowlisted calls connected to either endpoint or an alias of
that pipe. This preserves preceding reads, writes, vector operations, closes,
fd/status/size queries and mutations, `FIONREAD`, timeout-zero poll, and `dup*`
effects that can change the target's observable state. A separate pipe and a
call with no selected-pipe resource edge are dropped. Calls remain in original
order; projection never moves a source call across another source call.

The projection fails closed for a target when its selected resource prefix
contains any of these barriers:

- an unsupported or pseudo-syscall call that references a selected pipe fd;
- resource arithmetic on a selected fd reference;
- `dup2`/`dup3` between the selected pipe and an external or different-pipe
  resource;
- call properties on a retained or selected-pipe call;
- an undefined resource, duplicate result, stale descriptor generation, or
  use-after-close needed by the slice; or
- an allowlisted connected call that the lossless converter cannot represent.

These are target-local barriers: another vector target in the same source can
still produce an accepted scenario when its resource prefix is independent.
The diagnostic retains the stable lossless rejection category and detail when
the final converter rejects a target. Unsupported calls that do not reference
the selected pipe are ordinary dropped calls, not barriers.

#### Bounded deterministic repair

Projection repairs only two facts needed to make a selected scenario
synchronously executable:

- Each retained pipe output field is rewritten to the integer zero expected by
  the pinned serializer while preserving its result-capture name. A retained
  `pipe` becomes `pipe2(..., O_NONBLOCK)`. A retained `pipe2` becomes
  `pipe2(..., O_NONBLOCK | (original_flags & O_CLOEXEC))`. No other original
  flag is carried into the derived creation call.
- Projection tracks the open-file-description identity shared by descriptor
  aliases. If a retained `fcntl$setstatus(..., F_SETFL, flags)` can clear
  `O_NONBLOCK`, it marks that description as requiring repair. Immediately
  before the next retained positive-length scalar or vector I/O on that
  description, projection synthesizes
  `fcntl$setstatus(fd, F_SETFL, O_NONBLOCK)` and marks every alias of the same
  description nonblocking again. No restore is emitted for zero-length,
  invalid-vector, or invalid-count I/O.

The synthesized restore uses the exact fd operand of the following I/O, so it
cannot redirect the target to another endpoint. Creation repair and restores
are explicitly identified in diagnostics. Projection does not change iovec
count, segment count or length, outer or per-segment pointer mode, payload
bytes, fd direction, or any non-pipe memory address. Nonuniform payload,
anchored overlap, vector shape, use-after-close, operation count, slot count,
scenario count, and encoded entry size remain hard rejections at the existing
converter/codec boundary.

#### Report and conversion evidence

The default path keeps report schema v2 and conversion-log schema v1 byte for
byte. The opt-in path uses report schema v3 and importer version `3`. Every v3
input adds `conversion_kind` (`lossless`, `projected`, or null) and a
`projection` object. The object records whether projection was attempted, the
complete lossless rejection that triggered it, and one diagnostic per vector
target. Each target diagnostic contains:

- source target index, call name, and line number;
- accepted, rejected, or duplicate status and its canonical scenario digest;
- stable rejection category and detail when it did not produce a scenario;
- retained source calls with line, name, converted operation, and repair
  reasons;
- dropped source calls with line, name, and the resource-selection reason; and
- synthesized calls with the source line they precede, converted operation,
  and repair reason.

Report-v3 summary data includes lossless/projected conversion counts, target
status and rejection-category distributions, and retained/dropped/synthesized
transformation counts. All arrays use source order unless explicitly described
as sorted canonical digest sets. No absolute path enters conversion evidence.

Importer-v3 conversion logs use schema v2 and include the new conversion kind
and projection object in addition to the existing source digest, canonical
digest, operation mapping, and rejection. Their digest remains the external
source identity used by corpus and failure provenance. A projected operation
mapping includes a scenario index so repeated source lines in independent
target scenarios are unambiguous.

Admission reads `importer_version` from the validated report rather than a
module constant. Import-job schema remains v1: its existing nonempty importer
version string distinguishes v2 and v3 jobs, while its source and conversion
digest fields preserve the original `.syz` and schema-v2 log. Existing
importer-v1/v2 jobs, old reports used only for their owning saved job, corpus
entries, failures, and provenance require no migration. Saved jobs always
resume before a new report is matched or admitted. A conversion-log digest or
file mismatch remains a fail-closed persistent-state error.

#### Validation, rollout, and rollback

Deterministic regressions must prove default-v2 byte compatibility, lossless
priority, unrelated-call slicing, pipe placeholder and flag repair,
nonblocking restoration, `dup*` closure, every resource barrier, unchanged
vector/payload/alias validation, target ordering/deduplication, the four-
scenario limit, path-independent logs, repeatability, v2/v3 schema selection,
provenance, restart, old import-job loading, and conversion-log tamper
rejection. The checked-in 162-operation corpus must still record and compare on
the host, and the explicit x86_64 QEMU case must still pass.

Aggregate check-only acceptance uses exactly the Stage 4.2 manifest and records
all source rejections, projection transformations, and target diagnostics.
Bounded admission uses `--max-admit-unique 8 --max-qemu 64 --batch-size 8
--host-repetitions 3`. Any Linux/Starry semantic difference stops acceptance;
the remedy is a necessarily failing raw-syscall regression and production
semantic fix, never a weaker comparator or projection rule.

The feature is default-off and stateless before admission. Operational rollback
is to stop passing `--project-vector-slices`; this immediately restores the v2
report and conversion path. Existing v3 jobs remain owned persistent work and
must be resumed or explicitly archived under the same campaign rules as older
jobs. No `pipe.ops`, trace, harness, Starry ABI, coverage target, or default CI
rollback is needed.

### Persistent corpus ownership and schema

The ignored campaign state has this layout:

```
coverage/pipe-oracle-fuzz/
  corpus/<canonical-sha256>/{pipe.ops,metadata.json}
  runs/<run-id>/metadata.json
  coverage-state/<starry-elf-sha256>-<target-set-id>.json
  attribution-jobs/<job-id>/...
  minimization-jobs/<job-id>/...
  import-jobs/<job-id>/{sources,conversions,inputs,batch-evidence,metadata.json}
  failures/...
  .campaign.lock
```

`CorpusStore` owns these paths. `CanonicalCorpus` owns only the deduplicated
in-memory selection map. On startup the store strictly loads finalized entry
directories, then the orchestrator merges them with the five built-in seeds and
prints the built-in, disk, and deduplicated counts. A nonblocking process-level
`flock` is held for the complete campaign so two fuzzers cannot concurrently
update the same corpus, coverage baseline, or fixed profraw path.

Corpus metadata schema v1 remains a strict readable legacy format. It records
the canonical and `pipe.ops` digests, generator version, provenance,
first-observed and last-verified environments, and its original
`batch-pending` coverage claim. Schema v2 replaces that claim with `exact`, the
sorted union of `attributed_regions`, the attribution job IDs that proved it,
and a successful-attribution verification count. Schema v3 adds an
`active`/`superseded` lifecycle and minimization lineage. A v1/v2 entry is
upgraded atomically and lazily only when exact attribution or minimization
changes it; merely loading or selecting it does not rewrite metadata.

Schema v4 retains the schema-v3 lifecycle and adds a sorted, deduplicated
`external_sources` list to provenance. Each `ExternalSource` contains the raw
program SHA-256, complete 40-character syzkaller revision, importer version,
and conversion-log SHA-256. When multiple `.syz` files produce one canonical
digest, corpus admission merges all sources atomically. Existing schema-v1/v2/
v3 entries remain readable and gain v4 metadata only when imported provenance
is materially merged.

A proved minimized entry is activated as schema v3, or schema v4 when it owns
external-source provenance, before any original entry is marked superseded.
The supersede update is a separate atomic metadata replace, so a crash can
expose both active entries but can never leave only an uncommitted replacement.
Historical directories are never deleted. Corpus loading validates every
finalized v1/v2/v3/v4 entry, then exposes only active entries to mutation. If a
minimized digest already exists, its historical region union and minimization
lineage are merged instead of creating a duplicate directory.

The current generator strictly reads corpus entries created by generator v2,
v3, v4, or v5. Existing metadata and provenance are not rewritten merely
because the entry is loaded; a newly generated or mutated child records
generator v5 and uses `pipe.ops` v4. Loading fails closed on an unknown schema
or generator version, a directory or
file digest mismatch, noncanonical UTF-8 encoding, codec/resource-limit error,
invalid metadata, symlink, or unexpected finalized file. The only implicit
transition is the contributor-triggered v1-to-v2 atomic upgrade described
above. Mutation provenance adds no RNG calls and does not participate in the
canonical digest, preserving generator and mutation output for a fixed seed.

A new entry is written to a hidden uniquely named temporary directory, fsynced,
and atomically renamed to its digest directory. Revalidation updates
`last_verified` and its count through a temporary metadata file plus atomic
replace. Run directories use the same temporary-directory/rename protocol.
Only finalized 64-hex digest directories are loaded, so a process killed during
its initial write cannot expose a half entry.

Coverage state schema v4 is keyed by both the SHA-256 of the instrumented
StarryOS ELF and a fixed target-set ID. New campaigns use `pipe-poll-v4`, which
contains the five `pipe-vector-v3` files plus
`kernel/src/syscall/io_mpx/poll.rs` and
`kernel/src/syscall/io_mpx/mod.rs`. Schema-v1 state is read only as the
implicit `pipe-v1` target; schema-v2 state is restricted to `pipe-fd-v2`, and
schema-v3 state is restricted to `pipe-vector-v3`. None seeds a `pipe-poll-v4`
baseline. A nonproductive batch
saves the same baseline; a productive batch must finish exact attribution and
the final representative replay before the enlarged baseline is atomically
committed. Different ELFs and target sets therefore have independent
baselines.

Persistent target ownership is schema-bound and fail-closed: attribution v2
and minimization v1 imply `pipe-v1`; attribution v3 and minimization v2 require
`pipe-fd-v2`; attribution v4 and minimization v3 require `pipe-vector-v3`;
attribution v5/v6 and minimization v4/v5 require `pipe-poll-v4`. Schema v6
attribution and schema v5 minimization add external-source provenance without
changing target ownership. Replay evidence must use the same schema and target
as its owning job. Unknown schemas, target mismatches, symlinks, and digest
corruption are rejected rather than migrated. Imported raw and minimized
failures use schema v3; legacy failure schemas v1/v2 remain strict and readable.

Run metadata schema v7 stores the fixed `target_set_id`, seed, exact command,
measured duration,
candidate/executable/malformed/unique counts, sources and ancestry, new regions,
admitted digests, Starry ELF digest, result category, attribution job ID, every
entry-to-region mapping, the representative digests, and the number of extra
QEMU replays. It also records the minimization job, original/minimized digests,
candidate/proof QEMU counts, completion mode, and size changes. Run records are
observational; corpus entry directories remain the authoritative identity used
for selection.

Import-job schema v1 owns the classification report, exact raw source bytes,
path-independent conversion logs, canonical v4 inputs, host-stability status,
deterministic batch partition, durable batch evidence, QEMU count, child
attribution/minimization job IDs, and terminal result. Every file and metadata
transition is digest-checked and atomically saved. Finished batch metadata also
stores admitted digests and new regions so a restart can reconstruct the same
run report without replaying QEMU.

### Exact attribution state machine

Exact attribution is enabled by default for every productive batch. After the
initial batch QEMU reports regions outside the active ELF baseline, the
orchestrator atomically creates a schema-v6 job containing the canonical input
set and the initial batch evidence. It then:

1. re-records a fresh Linux trace and starts a fresh QEMU for each of the `N`
   unique entries;
2. intersects each entry's covered regions with the batch target and persists
   the complete `entry -> region` mapping, including empty mappings;
3. greedily chooses the entry with the largest uncovered-region gain, breaking
   ties by canonical digest, then removes redundant choices in deterministic
   order to obtain an inclusion-minimal representative cover;
4. re-records a fresh Linux trace and starts one final QEMU for the complete
   representative set; and
5. only after that replay covers every target region, admits new
   representatives, updates existing contributing entries, and commits the
   ELF-scoped baseline.

Thus a successful productive batch adds at most `N + 1` QEMU invocations beyond
its initial batch execution. Exact attribution and deterministic set
deduplication establish the representative and target-region inputs consumed by
the subsequent structured minimizer.

The job states are `entry-replays`, `representative-replay`, and `completed`.
Metadata, replay directories, and initial job directories use fsync plus atomic
replace/rename. Campaign startup strictly loads resumable jobs before consuming
RNG state or generating a new batch. Saved replay evidence is reconciled with
metadata, so termination between evidence persistence and a state update does
not repeat a completed QEMU. A completed job also remains resumable until its
run record is atomically saved and `run_recorded` is set.

Each job owns its canonical inputs, host oracle, content-addressed Starry ELF
copies, and per-replay `pipe.ops`, fresh `linux.trace`, `guest.log`, profraw
files, and coverage metadata. Schema validation checks the exact directory
shape, canonical input digests, ELF and evidence digests, sorted region sets,
state invariants, and rejects symlinks or unknown fields.

The Starry ELF digest must remain constant throughout one continuous
attribution attempt. Repeated validation exposed that `gen_ksym` can emit a
different `.kallsyms` byte order for an otherwise identical build. The initial
batch and a cross-campaign full-batch rebase therefore build normally, while
each entry and representative replay sets the internal
`AXBUILD_STARRY_KALLSYMS_SOURCE_ELF` contract to the job's content-addressed
ELF. Before copying the saved `.kallsyms`, axbuild requires every nonzero-address
runtime section plus `__llvm_covfun` and `__llvm_covmap` to match the saved ELF.
After replacement it requires the complete generated ELF to be byte-identical
to that saved file. This removes kallsyms-only nondeterminism without accepting
a changed executable or changed coverage metadata.

A digest change during an entry or representative replay remains instability.
If campaign restart observes that the active ELF differs from the saved job,
the fixed recovery flow first re-records and replays the full saved batch
against the active build, recomputes that ELF's baseline and target, records the
digest transition, clears the old mapping, and restarts attribution as a new
attempt. It never mixes coverage from two ELFs.

Any host replay failure, guest mismatch, missing profraw, coverage extraction
failure, missing target region, representative-proof failure, or continuous-run
ELF change stops the campaign. The job is marked `unstable` and atomically moved
to `failures/attribution-<job-id>/` with all evidence retained. Corpus admission
and coverage-baseline update do not occur on that path.

### Persistent coverage and mismatch minimization

Minimization is automatic after successful exact attribution and after a saved
semantic mismatch. It is also available explicitly as:

```
scripts/pipe-oracle/minimize.py SOURCE --max-qemu 64
```

`SOURCE` is either a completed attribution job or a failure artifact. Failure
schema v2 or v3 provides its fixed Starry ELF and fingerprint directly. A
schema-v1 failure remains replayable, but is imported for minimization only
when its old guest log contains exactly one strict semantic difference. The
importer derives the fingerprint, pins the active Starry ELF, and the normal original-validation
replay must reproduce it before reduction begins. Source artifacts are never
rewritten.

The pure reducer tracks an immutable origin for every operation and yields
canonical, strictly lower-complexity candidates in this order:

1. delete operations after the critical mismatch operation;
2. delete coarse-to-fine contiguous scenario blocks;
3. delete coarse-to-fine contiguous operation blocks;
4. try individual operations in reverse order;
5. compress `dup`/`dup2`/`dup3` chains, redirect compatible resource
   references, and
   rename live slots densely; and
6. reduce scalar/vector length, vector count/base/byte, pipe size, scalar poll
   masks, multi-fd poll entry count/order/mode/argument/masks, pipe/status/fd
   flags, and `dup3` flags through fixed simple values.

It neither consumes campaign RNG nor synthesizes initialization operations.
Every candidate passes the canonical codec and must lower a well-founded
complexity key. Invalid candidates do not consume QEMU budget, and a previously
seen canonical digest is never executed twice.

Coverage target regions are assigned to the first covering representative in
canonical-digest order. Each representative's responsibility is the union of
that assignment and its historical `attributed_regions`. Representatives are
scheduled round-robin in digest order and share one candidate budget, default
64. A candidate re-records a Linux trace, launches the job's fixed Starry ELF,
uses only that launch's fresh profraw, and is accepted only when it covers the
representative's complete responsibility. Final proof combines the current
representative set and must cover the union of all responsibilities twice
consecutively. The minimizer does not update the ELF coverage baseline.

A mismatch fingerprint contains the original operation origin, operation kind,
the ordered difference-field set (`result`, `errno`, `value`, `data_len`, or
`data`), expected and actual result classes, and exact errno for each failing
side. A mismatch candidate is accepted only when the observed difference maps
back to that same origin and produces the identical fingerprint. A pass or a
different fingerprint is an ordinary rejection, not a new failure.

Each strict schema-v5 minimization job owns its fixed target set, source
identity, original
inputs, fixed host and Starry ELFs, current-best checkpoints with operation
origins, reducer cursors and seen digests, shared budget/cursor, compact attempt
summaries, original validation, and two final proofs. States are
`validating`, `reducing`, `final-proof`, and `completed`; abnormal terminal
states are `stale` and `unstable`. Evidence and checkpoints are saved before the
metadata transition. A crash in between may repeat one candidate, but cannot
skip it or expose an unproved corpus entry. Normal rejected candidates retain
only digest, transform, typed category, region/fingerprint summary, and evidence
digest. Full trace/log/profraw evidence is retained for original validation,
the current best, abnormal observations, and both final proofs.

Candidate execution happens once; the final current-best result executes twice
consecutively. Validation and proof launches do not count toward the candidate
budget. When the budget is exhausted, the current best still enters final
proof; success completes as `budget-limited`. The algorithm promises bounded,
deterministic improvement rather than a global minimum.

Startup ordering is fixed: resume attribution, create or resume minimization,
reload active corpus, then initialize campaign RNG and generate new work. If the
active Starry ELF changed before a minimization resume, the job is marked
`stale`, moved intact to `failures/minimization-<job-id>/`, and is not rebased.
Panic, lockdep, timeout, infrastructure/oracle failure, a new mismatch during a
coverage reduction, or a failed final proof retains full abnormal evidence,
marks the job `unstable`, and stops the campaign without changing source corpus,
failure artifacts, or coverage baseline. Successful coverage minimization may
continue the campaign. Mismatch minimization always stops it and retains both
the original and minimized failure artifacts. Imported mismatch artifacts stay
on schema v3 and retain their raw program and conversion evidence.

The stage-2.3 acceptance run used the completed exact-attribution job for Starry
ELF `de330f7778459ac401f5891dab69f130812b2064a9845657db5687051f5b7c3d`.
With a four-candidate budget it executed one original validation, four
candidates, and two final proofs. The representative shrank from 637 to 503
bytes; both proof launches produced independent fresh profraw files and covered
all 346 responsibility regions. Only then was the original corpus entry marked
superseded and the minimized entry activated.

The stage-3.2a acceptance used the version-2 checked-in corpus for 115
host/Starry operations and exported a fresh x86_64 coverage profile without a
semantic mismatch. Two small real-campaign runs used separate fixed Starry ELF
digests and attributed 693 and 674 new `pipe-fd-v2` regions, respectively. Each
coverage minimization executed one validation, four candidates, and two final
proofs; the entries shrank from 631 to 476 bytes and from 1171 to 843 bytes.
Both jobs completed as `budget-limited`, retained every responsibility region
in both fresh final profiles, activated the minimized entries, and preserved
the originals as superseded. An ENOSPC interruption after the first batch also
demonstrated schema-v3 attribution recovery from its atomic checkpoint. No
production Starry syscall change was required.

The stage-3.2b-1 acceptance used the version-3 checked-in corpus for 142
host/Starry operations. Host record/compare and the x86_64 QEMU oracle both
passed, and QEMU exported a fresh coverage profile. The final raw vectored-I/O
regression passed 76 checks. The fixed `seed=2`, two-candidate campaign generated
both `readv` and `writev`, admitted both executable inputs, and added 1000
`pipe-vector-v3` regions: 345 in `file/pipe.rs`, 33 in `syscall/fs/pipe.rs`,
342 in `syscall/fs/fd_ops.rs`, 171 in `syscall/fs/io.rs`, and 109 in `mm/io.rs`.
Exact attribution used three additional QEMU replays, mapped 993 and 956
regions to the two entries, and retained two representatives. With a
four-candidate budget, coverage minimization used one validation, four
candidates, and two final proofs. One input remained 1308 bytes; the other
shrunk from 672 to 629 bytes. The job completed `budget-limited` only after both
fresh final proofs preserved all assigned regions. The run metadata uses schema
v5, attribution schema v4, minimization schema v3, and target set
`pipe-vector-v3`.

The stage-3.2b-2 acceptance used the version-4 checked-in corpus for 162
host/Starry operations. Host record/compare and the x86_64 QEMU oracle both
passed and exported a fresh coverage profile. The direct shared-path regression
passed 16 checks inside the complete 45-module select/poll family. The fixed
`seed=0`, two-candidate campaign generated 11 `poll-many` operations, admitted
both executable inputs, and added 1205 `pipe-poll-v4` regions: 353 in
`file/pipe.rs`, 33 in `syscall/fs/pipe.rs`, 342 in `syscall/fs/fd_ops.rs`, 169
in `syscall/fs/io.rs`, 121 in `mm/io.rs`, 179 in `syscall/io_mpx/poll.rs`, and
8 in `syscall/io_mpx/mod.rs`. Exact attribution used three additional QEMU
replays, mapped 1187 and 1078 regions to the two entries, and retained two
representatives. Coverage minimization used one validation, four candidates,
and two final proofs. The responsibility sets required both inputs to remain at
1653 and 555 bytes; the job completed `budget-limited` only after both fresh
proofs preserved all assigned regions. The persistent formats are run schema
v6, coverage-state schema v4, attribution schema v5, minimization schema v4,
corpus schema v3, and failure schema v2.

The Stage 4.1 acceptance imported one real restricted `.syz` program. It
classified one input as accepted, zero as rejected, and produced one unique
canonical scenario. All three host records were byte-identical. Admission used
six QEMU launches: one initial batch comparison, two exact-attribution replays,
one minimization validation, and two final proofs. The input added 965
`pipe-poll-v4` regions: 240 in `file/pipe.rs`, 33 in
`syscall/fs/pipe.rs`, 279 in `syscall/fs/fd_ops.rs`, 144 in
`syscall/fs/io.rs`, 84 in `mm/io.rs`, 177 in
`syscall/io_mpx/poll.rs`, and 8 in `syscall/io_mpx/mod.rs`. Exact attribution
mapped all 965 regions to the input. The zero-candidate minimization budget
kept the scenario at 127 bytes and completed `budget-limited` only after the
validation and both proofs. An ENOSPC interruption during attribution resumed
the same durable import job without repeating its initial batch QEMU launch.
The resulting corpus entry records the pinned syzkaller source provenance.
The persistent formats are run schema v7, coverage-state schema v4,
attribution schema v6, minimization schema v5, corpus schema v4, import-job
schema v1, and imported-failure schema v3; generator v5 and target set
`pipe-poll-v4` remain unchanged. No Starry syscall or comparator change was
required. All 156 Python regressions, `py_compile`, all 23 `starry-kernel`
clippy configurations, workspace rustfmt, host record/compare for 162
operations, the checked-in x86_64 QEMU case, and `git diff --check` passed. The
optional upstream compatibility test was skipped because no pinned syzkaller
checkout was configured.

The Stage 4.2 acceptance used syzbot's immutable `corpus.db` objects for the
`ci-upstream-kasan-gce`, `ci-upstream-kasan-gce-root`, and
`ci-qemu2-arm64-mte` managers at GCS generations `1785647672872099`,
`1785646365757143`, and `1785660534694398`. Their SHA-256 digests were
`da360ca9d5cbb02bb8df601f78a51d17f60e0c361dbf412269da0702bab71d1`,
`a37d7e06b70f52a8d5402dd29d5a6c055029d2ddee990ca2540b59a4e1c8333`,
and `7af49216f53b5077578fce4fd43aba461ef50aa0a5ad8016b95e6205f23d5398`.
The source revision was pinned to
`e611ffe1caa28a0228c8f3642cc768f0dba3dd0c`. Recursive ordinary-file
selection without following symlinks found 311745 `.syz` files, 302242
distinct raw-content digests, and 102 parser-confirmed programs containing
both `pipe`/`pipe2` and `readv`/`writev`. Sorting by raw SHA-256 and relative
path selected the first 100. The newline-terminated UTF-8 manifest SHA-256 was
`792ec290d50098cb43eba9ec6f8fdd5b5755851dfb74ac044a9c237ebb50adb5`.
The manifest and source corpora remain outside Git.

Check-only classified 1 input as accepted and 99 as rejected, producing 1
unique canonical scenario. The complete rejection distribution was 47
`unsupported-call`, 45 `pointer-shape`, 3 `unsupported-constant`, 2
`file-too-large`, and 2 `pseudo-syscall`. Bounded admission selected that one
unique digest and deferred zero. Job
`import-20260802T113905858318Z-pid-14948` completed
`passed-new-coverage`: its three host records were stable, with zero unstable
records, and its 10 QEMU launches comprised one initial comparison, two exact
attribution replays, one minimization validation, four minimization candidates,
and two final proofs. It admitted one corpus digest,
`b2168a1c49679305472341a7608ddcebfcbb4cab73df4f1eaec0c1d30e14f058`.
The single attribution child completed, for an exact attribution rate of 1/1
(100%). The single minimization job recorded `original_size=60` and
`best_size=60`, also 60 to 60 bytes in total; validation and both final proofs
passed.

The admitted program added 957 `pipe-poll-v4` regions: 224 in
`file/pipe.rs`, 29 in `syscall/fs/pipe.rs`, 278 in
`syscall/fs/fd_ops.rs`, 161 in `syscall/fs/io.rs`, 87 in `mm/io.rs`, 170 in
`syscall/io_mpx/poll.rs`, and 8 in `syscall/io_mpx/mod.rs`. All seven target
files were present. Existing durable import, attribution, and minimization jobs
were already terminal, so no prior resumable job consumed this acceptance
budget. Three disclosed environment-bootstrap attempts
(`import-20260802T105848336172Z-pid-2`,
`import-20260802T112737727709Z-pid-2`, and
`import-20260802T113248274906Z-pid-2`) each stopped as an infrastructure
failure after being charged one QEMU attempt, recorded no run, and started no
attribution or minimization child. They respectively exposed an absent rootfs
registry, an unavailable OVMF download in the restricted environment, and a
denied QEMU monitor socket in the sandbox. The acceptance decision treats
these retained preflight records as environment preparation rather than Stage
4.2 admission; their three attempts are excluded from the successful job's
metrics.

At unchanged HEAD `211f1c708e0d356ed4f26491cbc6e288d57ef182`, the previously
completed 172 Python checks, all 23 `starry-kernel` clippy configurations, and
host record/compare evidence for 162 operations remained applicable. The
explicit x86_64 QEMU oracle case was rerun serially and passed all 162
operations with fresh coverage. No importer, comparator, Starry syscall, test
configuration, or build-input change was required.

The Stage 4.3 acceptance reused that exact 100-program manifest and pinned
syzkaller revision. Opt-in check-only classified 23 sources as accepted and 77
as rejected, producing 12 unique canonical documents and exceeding the 20/10
gate. One accepted source used unchanged lossless conversion and 22 used
projection. Source rejections were 75 `projection-no-accepted-target` and two
`file-too-large`. Across all 100 vector targets, projection accepted 22 and
rejected 78, with target rejections comprising 59 `unrelated-vector`, 10
`unsupported-resource-call`, five `vector-shape`, and four
`non-uniform-payload`. The transformation audit recorded 95 retained calls,
1428 dropped calls, and no synthesized restore in this sample; deterministic
regressions separately exercise restoration, target deduplication, and the
four-scenario limit.

Bounded admission selected the first eight of 12 canonical digests and deferred
four. Job `import-20260802T153254724852Z-pid-25344` completed
`passed-new-coverage`: all eight inputs produced three byte-identical host
traces, with zero unstable inputs. Its 29 QEMU launches comprised one initial
batch comparison, nine exact-attribution replays, one minimization validation,
16 minimization candidates, and two final proofs; the 64-launch and
51-candidate budgets were not exhausted. There was no mismatch, panic,
timeout, coverage inconsistency, failed child, or failed final proof.

The batch added 1013 `pipe-poll-v4` regions: 255 in `file/pipe.rs`, 33 in
`syscall/fs/pipe.rs`, 279 in `syscall/fs/fd_ops.rs`, 161 in
`syscall/fs/io.rs`, 107 in `mm/io.rs`, 170 in
`syscall/io_mpx/poll.rs`, and 8 in `syscall/io_mpx/mod.rs`. Exact attribution
replayed all eight entries, attributed 1013/1013 regions, and retained three
representatives whose union also covered 1013/1013. Coverage minimization
completed as `minimized`; its three representatives changed from 69 to 67, 64
to 64, and 60 to 60 bytes, respectively, and admitted corpus digests
`e8049f8472ac73c028cfd02ba7a8398b102aa8cbb2d57f9c01c4efef33f54d7f`,
`6cd8781e7fc370015652ce54a9fab33a6004fd2eaca75a8faafde8c227d234d3`,
and `b2168a1c49679305472341a7608ddcebfcbb4cab73df4f1eaec0c1d30e14f058`.

One retained environment attempt,
`import-20260802T151522878111Z-pid-4`, charged one QEMU launch before guest boot
and failed when the restricted child process could not bind its Unix monitor
socket. It recorded no coverage and started no attribution or minimization
child. The successful job ran unchanged inputs and settings in an execution
environment that permitted that socket; the earlier failure remains preserved
as infrastructure evidence and is excluded from the successful job's metrics.

The exercised implementation was committed as `435f6cb1c`
(`feat(pipe-oracle): project repaired vector slices`) after adding one
post-run fail-closed check that rejects a projected-call/conversion-log length
mismatch; every accepted mapping in the run already satisfied that invariant.
All 186 Python regressions then passed, with only the optional pinned-upstream
parser check skipped because `SYZKALLER_CHECKOUT` was not configured.
`py_compile`, all 23 `starry-kernel` clippy configurations, workspace rustfmt,
host record/compare for 162 operations, and the explicit x86_64 QEMU oracle
also passed. No comparator, `pipe.ops` format, C harness, Starry syscall, test
configuration, or default CI path changed.

Before implementation, the previous Python codec and saved version-3 C harness
both rejected the version-4 checked-in corpus. After implementation, all 120
Python/host-harness regressions, `py_compile`, all 23 `starry-kernel` clippy
configurations, workspace rustfmt, and `git diff --check` passed.

The retained schema-v1 poll-mismatch artifact also passed strict lazy import:
its old log yielded a fingerprint at original operation 16 with
`result`/`errno`/`value` differences. The active fixed ELF now passes all 397
operations because that historical ABI defect was repaired, so original
validation correctly saved the job as `unstable` with zero candidate launches
and left the source artifact byte-identical. No matching old Starry ELF exists
locally for a positive real reduction. The positive mismatch path is therefore
covered by the deterministic end-to-end campaign regression (one validation,
one candidate, two proofs, identical fingerprint, and separate original and
minimized schema-v2 artifacts). Two other legacy artifacts previously labeled
as mismatches contain only infrastructure/profraw failures and are rejected
before QEMU.

### Artifact injection contract

`STARRY_PIPE_ORACLE_ARTIFACT_DIR` is an internal orchestration interface. When
set, it must be an absolute directory containing all three files:

```
pipe-linux-oracle
pipe.ops
linux.trace
```

The case CMake project validates and installs those files byte-for-byte. It does
not compile a replacement oracle or record a replacement trace. Without the
variable, the regular manual case keeps its original behavior: build the static
oracle, use the checked-in corpus, and record the host trace during the case
build. Fuzz creates a temporary directory for the current batch; replay passes
the validated failure directory directly.

### Failure artifact schema

```
coverage/pipe-oracle-fuzz/failures/<case-id>/
  input.bin              (or inputs/ for multi-input batches; canonical pipe.ops)
  pipe.ops
  linux.trace
  pipe-linux-oracle      (static ELF)
  starryos               (fixed instrumented ELF for schema-v2 mismatch)
  guest.log
  profraws/*.profraw
  source.syz             (schema-v3 imported failure only)
  conversion-log.json    (schema-v3 imported failure only)
  metadata.json
```

Failure schema v1 remains strictly replayable. Schema v2 includes git state,
host uname, page size, fuzz seed, batch index, SHA-256 and size for every
artifact, exact command, and one typed guest result: `passed`,
`semantic-mismatch`, `oracle-failure`, `kernel-panic`, `lockdep-failure`,
`timeout`, or `infrastructure-failure`. A semantic mismatch additionally
requires its fixed Starry ELF and stable mismatch fingerprint. QEMU startup,
monitor-socket, or other infrastructure errors therefore cannot be imported or
reported as semantic mismatches.

Schema v3 extends schema v2 only for imported failures. It requires the raw
syzkaller program, path-independent conversion log, their sizes and SHA-256
digests, the complete pinned revision, and importer version. Strict validation
binds both files to the typed `ExternalSource`. Automatic mismatch
minimization copies that source evidence into the minimized schema-v3 artifact;
it never rewrites or replaces the original failure.

Saves use a temp-directory + atomic rename to prevent half-written artifacts.
Attribution instability uses the separate schema-v6 job layout described above
under `failures/attribution-<job-id>/`; moving the complete job preserves all
initial, per-entry, representative, and ELF-transition evidence.

### Data flow and ownership

```
checked-in pipe.ops  +  canonical structured corpus entries
         |
         v
static x86_64 harness --record -- host Linux syscalls
         |                         |
         |                         +-- uname/page-size metadata
         v
generated trace (owned by one test run)
         |
         +-- harness + corpus + trace collected in one absolute artifact dir
                                       |
                                       +-- STARRY_PIPE_ORACLE_ARTIFACT_DIR
                                       |
                                       v
                             per-case rootfs overlay
                                       |
                                       v
                          Starry x86_64 QEMU, same ELF
                                       |
                                       v
                 compare, write /proc/starry-test-coverage,
                 print PASSED or DEFERRED_FAIL marker
                                       |
                                       v
              host QEMU monitor memsave -> profraw
                                       |
                                       v
              coverage region extraction (llvm-cov export)
              object: target/x86_64-unknown-none/release/starryos
```

The checked-in regression corpus is repository-owned. The fuzz campaign owns a
canonical-digest-sorted selection map merged from built-in and active persistent
entries; the ignored `CorpusStore` owns cross-process corpus identity, run
records, and ELF-scoped coverage baselines. `AttributionStore` owns resumable
attribution jobs and their immutable replay evidence. `MinimizationStore` owns
fixed ELFs, reducer checkpoints, summaries, and selected heavy evidence until a
proved corpus/failure result is committed. Trace, profraw, guest log, and
prepared rootfs are run-owned build artifacts until copied into a job or
failure artifact. Failure artifacts are saved under
`coverage/pipe-oracle-fuzz/failures/`. Version-1 failure replay keeps using the
saved `pipe.ops`; it does not reinterpret an old raw `input.bin`.

## Linux version and environment policy

There is no pinned release check. The test requires:
- a Linux x86_64 host;
- ability to execute the statically linked x86_64 harness;
- existing x86_64 Starry/QEMU prerequisites;
- enough permission for controlled pipe-size decreases.

The host release, machine, and page size are printed and stored in the trace.
If a Linux upgrade changes an observable result, the differential test fails.

The fd semantics follow the public Linux contracts in
[`pipe2(2)`](https://man7.org/linux/man-pages/man2/pipe.2.html),
[`fcntl(2)`](https://man7.org/linux/man-pages/man2/fcntl.2.html), and
[`dup(2)`](https://man7.org/linux/man-pages/man2/dup.2.html). Vector contracts
follow [`readv(2)`](https://man7.org/linux/man-pages/man2/readv.2.html), with
fd/access/iovec ordering checked against the fixed Linux source commit linked
in the version-3 section. Poll contracts follow
[`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html), with negative-fd,
invalid-fd, array-scan, and shared `poll`/`ppoll` ordering checked against the
fixed Linux 6.12.37 source commit linked in the version-4 section. The execution
oracle, rather than a hard-coded kernel version, determines the exact result
and errno for the recorded host release. Where an older host disagrees with a
fixed source ordering, the discrepancy is documented and the production
regression remains strict.

## Syscall impact map

| Syscall | Comparison scope |
|---|---|
| `pipe2` | Four `O_NONBLOCK`/`O_CLOEXEC` combinations, fixed unknown-bit `EINVAL`, and logical slots |
| `read` | Zero-length success, nonblocking `EAGAIN`, EOF, byte count, exact bytes |
| `write` | Zero-length success, `EPIPE`, `PIPE_BUF` atomicity, partial writes |
| `readv` | Empty/count/pointer boundaries, fd/access error priority, cross-segment and short-read placement, untouched sentinel suffix |
| `writev` | Empty/count/pointer boundaries, fd/access error priority, per-segment bytes, nonblocking partial writes |
| `close` | Endpoint lifetime transitions, `EBADF` for invalid slots |
| `dup` | Success/error; shared description state and cleared destination `FD_CLOEXEC` |
| `dup2` | Same-fd behavior, invalid source, occupied-destination replacement, cleared destination `FD_CLOEXEC`, normalized success |
| `dup3` | Same-fd/invalid-flag `EINVAL`, replacement, optional destination `FD_CLOEXEC`, normalized success |
| `poll` | Timeout-zero scalar and bounded arrays; ordered per-entry `revents`, ignored negative fds, invalid positive fds, duplicates/aliases, mixed readiness, and element return count |
| `ppoll` | Direct zero-timespec/null-sigmask regression for the shared `do_poll` behavior; not part of the differential corpus protocol |
| `fcntl` | `F_SETPIPE_SZ`/`F_GETPIPE_SZ`; normalized `F_GETFL`/`F_GETFD`; shared `F_SETFL(O_NONBLOCK)` and per-fd `F_SETFD(FD_CLOEXEC)` |
| `ioctl(FIONREAD)` | Return/errno, exact unread-byte count |

## Cost, rollback, and limitations

The regular path performs one small static C build, one host execution, one
case-rootfs preparation, and one Starry QEMU boot. This is materially cheaper
than the previous per-batch QEMU baseline.

The default `cargo xtask starry test qemu --arch x86_64` test path is
unchanged from `origin/dev`. `pipe-linux-oracle` is only run when explicitly
selected with `-c qemu/pipe-linux-oracle`.

Persistent-state rollback does not require a code change: with no campaign
running, remove or archive `corpus/`, `runs/`, and `coverage-state/` to return to
the five built-in seeds while preserving `failures/`. Full feature rollback can
remove the `pipe-linux-oracle` case directory and the `default_run` field from
axbuild. Production pipe fixes and existing axtest coverage remain valid
independently.

## Roadmap

- Stages 1 through 3.2b-2 are complete: executable Linux oracle, persistent
  coverage campaign, exact attribution/minimization, fd flags, vector I/O, and
  bounded timeout-zero multi-fd poll.
- Stage 4.1 is complete: pinned restricted syzkaller parsing, durable external
  provenance, check-only reporting, and opt-in stable admission.
- Stage 4.2 is complete: importer-v2 vector conversion and bounded
  canonical-digest admission preserve the existing v4/runtime contracts, and
  the pinned 100-program aggregate acceptance passed.
- Stage 4.3 is complete: explicit importer-v3 projection derives
  resource-closed vector slices, repairs only synchronous execution state,
  persists auditable transformation diagnostics, and passed the pinned
  100-program and bounded-admission gates while the default importer-v2 path
  remained byte-compatible.
- Stage 5 is complete: eventfd provides the second synchronous vertical
  adapter, pipe and eventfd now share an adapter-neutral campaign framework,
  a third fake adapter verifies the extension boundary, and the retained pipe
  162-operation host/QEMU comparison remains compatible. See
  `book/design/starry-eventfd-linux-oracle.md` for the design and acceptance
  evidence.
- Stage 6.1 is complete: eventfd has a controlled single-worker blocking model,
  and bounded recovery completed every attribution and minimization task with
  no pending background work.
- Stage 6.2a is complete: pipe has an independently versioned controlled
  blocking model for read wakeup, aliasing, zero-write non-wakeup, EOF,
  full-pipe atomic write, and phased slot release. Historical pipe v4 bytes,
  traces, artifacts, persistence, replay, and default CLI behavior remain
  compatible.
- Stage 6.2b will independently extract the common actor/concurrency machinery
  from the two stable blocking adapters without changing their behavior.
  Multiple waiters, fairness, allowed-result sets, signals, poll/epoll wakeup
  interleavings, and general close competition remain later stages.
- A later stage may also evaluate cross-architecture differential coverage or
  automatic CI regression detection. It must receive separate design evidence,
  must not silently expand the Stage 4.1 allowlist, and must keep the default
  test path clean.
