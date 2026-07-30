# Starry pipe differential testing with a Linux execution oracle

## Status

Implemented and locally validated on 2026-07-30. This document was added to the
working tree as the implementation plan before the code migration started; the
results below record how that plan was realized.

Base: `dev-cov2` at `45f8fab9330f08b306f8a573cf10e70ed044d7d7`.

## Decision

Starry pipe compatibility will be checked by executing one static x86_64
Linux-ABI test program twice:

1. the host Linux execution records the result of every operation in a corpus;
2. the same ELF and corpus run in Starry x86_64 QEMU and compare their results
   with the host trace.

Linux is therefore the executable reference. The test will not maintain a
second implementation of pipe semantics in Rust, will not use `strace` as the
oracle, and will not pin a Linux release. Every run records the host release and
architecture so a failure remains reproducible.

x86_64 QEMU is the primary differential platform because the same static ELF
can run natively on the x86_64 Linux host and as a Starry x86_64 userspace
program. Other Starry architectures retain deterministic syscall regressions;
they do not pretend to execute the exact x86_64 oracle binary.

## Problem

The current branch introduced three coupled pieces for pipe fuzzing:

- `components/pipe-model`, a handwritten pipe state machine;
- `scripts/axbuild/src/ktest/fuzz.rs`, a coverage-guided batch orchestrator;
- a Starry `axtest_pipe_fuzz` adapter that executes kernel objects and compares
  them with the handwritten model.

The implementation is expensive in two different ways.

First, it duplicates Linux behavior. The model must separately encode empty
I/O, reader/writer lifetime, `PIPE_BUF` atomicity, partial writes, poll masks,
capacity rounding, data ordering, and errno selection. During the first audit,
the model itself already needed corrections for zero-length I/O, read data,
resize results, error classification, and malformed input handling. Passing a
model comparison can therefore mean that Starry and the model share the same
wrong assumption.

Second, the execution path is operationally heavy. The current default runs a
coverage baseline QEMU, then one QEMU boot and rootfs copy per batch. The
implementation currently contains about 1,045 lines in `pipe-model`, 895 lines
in the fuzz orchestrator, and additional Starry-only adapter and axtest code.
That cost is disproportionate to the compatibility signal.

The audit also identified why a byte-count-only model is especially risky.
Linux pipes use a ring of page-backed `pipe_buffer` slots. Readiness and some
nonblocking writes depend on whether a slot is free and whether the last slot
can be merged, not only on the total number of vacant bytes. Starry currently
stores bytes in a `HeapRb`; a handwritten byte model can reproduce Starry's
assumption while missing Linux page-slot fragmentation behavior.

## Evidence and prior art

The public behavior is described by the Linux man-pages for
[`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html),
[`read(2)`](https://man7.org/linux/man-pages/man2/read.2.html),
[`write(2)`](https://man7.org/linux/man-pages/man2/write.2.html), and
[`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html).

The local Linux 6.12.37 source at
`/home/cloud/gitStudy/linux-6.12.37/fs/pipe.c` provides an implementation
cross-check:

- `pipe_read` returns zero before locking when the iterator length is zero;
- `anon_pipe_write` returns zero before checking whether readers remain;
- `pipe_poll` reports writer readiness from ring-slot availability and reports
  `EPOLLERR` independently when no reader remains;
- `anon_pipe_write` first tries to merge into the last page buffer, then
  allocates ring slots, which makes fragmentation observable.

Direct tests on the current host, Linux `5.15.0-186-generic` x86_64, confirmed
the boundary behaviors that motivated this change: zero-length read/write
return zero, a positive nonblocking read of an empty pipe with a writer returns
`EAGAIN`, a small write that cannot fit atomically returns `EAGAIN` without
changing queued bytes, and a writer with no reader polls as `POLLOUT|POLLERR`.

The checked source version and the current host version are evidence, not a
version constraint. The reference used by a test run is the Linux kernel that
actually executes that run.

## Users and success criteria

The direct users are Starry filesystem maintainers and CI jobs that need a
high-signal Linux compatibility check.

The migration is complete when all of the following hold:

- `cargo xtask starry test qemu --arch x86_64 -c qemu/pipe-linux-oracle`
  executes the host oracle and one Starry QEMU boot;
- one statically linked x86_64 ELF is used for both executions;
- the checked-in corpus contains operations only, never checked-in expected
  results;
- every test invocation executes the corpus on the running host Linux and
  generates a fresh expected trace;
- Starry compares return values, normalized errno, poll events, capacity/query
  values, queued byte counts, and bytes returned by reads;
- a mismatch identifies the scenario, operation index, operation text,
  expected result, actual result, and recorded host environment;
- malformed corpus or trace input fails closed and returns a nonzero status;
- the old Rust semantic model, model adapter, model-only axtest target, and
  coverage-batch orchestrator are removed;
- the deterministic grouped pipe regression remains runnable on every Starry
  QEMU architecture that supports the system suite;
- Starry's production pipe fixes are retained and any additional mismatch
  exposed by the corpus is fixed in the production pipe state, not hidden by
  normalization.

## Non-goals for the first implementation

The first implementation deliberately excludes:

- blocking operations, timing comparisons, scheduler interleavings, multiple
  concurrent writers, and signal-delivery timing;
- `epoll`, `select`, FIFO pathname/open semantics, `splice`, `tee`, and
  `vmsplice`;
- a general syscall differential framework or a stable public corpus/trace
  protocol;
- a Linux VM pinned to a specific kernel release;
- coverage-guided mutation and multiple QEMU boots in the regular PR path;
- using output from `strace` as expected data.

`strace` remains useful when diagnosing a mismatch, but it is not a semantic
authority and does not remove the need to execute the syscall workload.

## Alternatives considered

| Alternative | Benefit | Cost or failure mode | Decision |
| --- | --- | --- | --- |
| Keep and repair `pipe-model` | Fast unit-level comparisons and arbitrary kernel-object sequences | Permanently duplicates Linux semantics; already drifted; can share Starry's incorrect abstraction | Reject |
| Pin Linux 5.15 | Stable long-lived golden behavior | Adds image/toolchain maintenance and is not a Starry compatibility requirement | Reject |
| Use the running Linux host | No kernel image lifecycle; tests the environment developers and CI actually use | A Linux upgrade can intentionally change the oracle, so metadata and review are required | Select |
| Record `strace` output | Easy ad-hoc inspection | Text is unstable and incomplete as a comparison protocol; `strace` is still only observing an execution | Reject |
| Run different host and guest programs | Easier native/cross builds | Harness drift can create false differences; doubles syscall-driving code | Reject |
| Return guest results to a Rust host comparator | Keeps comparison logic on the host | Requires serial parsing or a transport/RPC path and more orchestration | Reject for v1 |
| Generate expected data while preparing the guest image | Reuses the existing C asset pipeline | Rootfs cache hits can skip host execution | Select only with per-case cache bypass |
| Add a generic incremental host-pre-run injection hook | Could reuse a cached rootfs and only replace the trace | Expands test-runner API and implementation before runtime cost is measured | Defer |
| Keep only fixed golden regressions | Lowest runtime and implementation cost | Does not prove behavior against the running Linux reference and offers poor sequence growth | Retain only as secondary cross-architecture regression |

## Architecture

### Test case placement

The primary case will be a direct C-pipeline case:

```text
test-suit/starryos/qemu/pipe-linux-oracle/
  qemu-x86_64.toml
  c/
    CMakeLists.txt
    src/pipe_linux_oracle.c
    corpus/pipe.ops
```

It lives under the existing `qemu` build wrapper, so it reuses
`build-x86_64-unknown-none.toml`. It intentionally has only
`qemu-x86_64.toml`; other architectures continue to execute
`qemu/system/bugfix-bug-pipe-linux-semantics` as a deterministic regression.

This placement keeps the primary differential test separate from the aggregate
system suite. A host-generated result must be refreshed for each invocation,
whereas the aggregate grouped C pipeline is designed to build and cache many
static assets together.

### One executable, two modes

The harness has two externally used modes:

```text
pipe-linux-oracle --record  CORPUS TRACE
pipe-linux-oracle --compare CORPUS TRACE
```

The C target is statically linked. During asset preparation, CMake builds the
x86_64 target once and directly executes that target on the x86_64 Linux host
in `--record` mode. CMake installs that exact ELF, the operation corpus, and
the generated trace into the Starry rootfs overlay. Starry boots once and runs
the installed ELF in `--compare` mode.

The installed binary must be byte-identical to the host-executed binary. The
build fails if the host is not Linux x86_64 or if the static target cannot run
natively. There is no fallback to a separately compiled native executable.

### Fresh host execution

The normal test asset cache stores a post-injection rootfs image. Reusing that
image would also reuse its expected trace and silently skip the Linux oracle.
The QEMU extra config therefore gains a typed per-case policy:

```toml
asset_cache = "bypass"
```

The default remains `reuse`, so existing cases are unaffected. `bypass` skips
both cache lookup and cache write for that case. It still uses the existing C
asset pipeline and one QEMU boot; it only forces the small harness build,
record execution, and rootfs overlay preparation to occur for every run.

This is the initial cost/correctness tradeoff. An incremental pre-run trace
injection hook is deferred until measurements show asset preparation, rather
than QEMU boot, is a material bottleneck.

### Corpus

`pipe.ops` is a versioned, line-oriented, reviewable operation file. It uses
logical descriptor slots rather than host fd numbers. Scenario boundaries
close all live slots, so one failure cannot leak state into the next scenario.

The initial operation vocabulary is intentionally small:

- `pipe2` with `O_NONBLOCK|O_CLOEXEC`;
- zero-length and bounded `read`/`write`, including an intentionally invalid
  pointer with a zero count;
- deterministic byte-pattern writes and exact-byte reads;
- logical `dup` and `close` operations;
- `poll` with timeout zero;
- `fcntl(F_SETPIPE_SZ)` and `fcntl(F_GETPIPE_SZ)` with controlled sizes;
- `ioctl(FIONREAD)`.

The harness issues the relevant calls through `syscall(SYS_...)` so libc does
not retry or translate their return values. `SIGPIPE` is ignored before corpus
execution; signal delivery itself is outside this test's scope.

The first corpus must cover at least:

- zero-length read from an empty nonblocking pipe while a writer remains;
- positive read from the same state returning `EAGAIN`;
- zero-length write after the last reader closes;
- positive write after the last reader closes returning `EPIPE`;
- small nonblocking all-or-`EAGAIN` behavior and unchanged `FIONREAD`;
- large nonblocking partial write behavior;
- read data ordering across multiple writes and partial reads;
- duplicate reader/writer lifetime and EOF/error transitions;
- writer poll masks when near full and after the reader closes;
- capacity rounding/query and shrinking below occupied slot requirements;
- a fragmented two-page pipe where total vacant bytes and free Linux
  `pipe_buffer` slots imply different answers.

The final item is a deliberate guard against implementing Linux readiness from
byte count alone.

### Trace and comparison

The generated trace is test-internal and versioned. Its header contains:

- magic and format version;
- corpus digest and operation count;
- `uname` release and machine from the recording host;
- host page size.

Each operation record contains a normalized operation kind, signed return
value, errno captured immediately after the syscall, operation-specific scalar
output, and bounded returned bytes where applicable.

Normalization is limited to values that are not semantic:

- successful `pipe2` and `dup` record logical-slot success rather than numeric
  fd values;
- unused errno after success is normalized to zero;
- poll compares the requested descriptor's `revents`, not unrelated bits in
  uninitialized memory.

Capacity values, byte counts, errno, poll masks, `FIONREAD`, and read bytes are
not normalized away. Unsupported operations, malformed input, overflow,
truncation, unknown versions, and corpus/trace digest mismatch are hard
failures.

### Data flow and ownership

```text
checked-in pipe.ops
        |
        v
static x86_64 harness --record -- host Linux syscalls
        |                         |
        |                         +-- uname/page-size metadata
        v
generated trace (owned by one test run)
        |
        +-- harness + corpus + trace installed in fresh case rootfs
                                      |
                                      v
                         Starry x86_64 QEMU, same ELF
                                      |
                                      v
                          compare + precise pass/fail marker
```

The corpus is repository-owned. The trace and prepared rootfs are run-owned
build artifacts and are removed or overwritten by the existing case lifecycle.
The harness owns all logical descriptors during execution and closes them at
scenario end and on error. No kernel state or shared service is added.

## Linux version and environment policy

There is no `5.15` check and no expected release string. The test requires:

- a Linux x86_64 host;
- the ability to execute the statically linked x86_64 harness;
- the existing x86_64 Starry/QEMU prerequisites;
- enough permission for the controlled pipe-size decreases used by the
  corpus.

The host release, machine, and page size are printed and stored in the trace.
If a Linux upgrade changes an observable result, the differential test fails.
Maintainers then determine whether Linux intentionally changed, the corpus
depends on an uncontrolled host policy, or Starry is incompatible. The test
must not silently regenerate a result and report success without executing the
Starry comparison.

Default pipe capacity is not compared because Linux can reduce it based on
per-user pipe limits. Scenarios that need a capacity first request a controlled
decrease and compare the returned effective size. Environment-dependent
capacity increases are outside v1.

## Production implementation rule

The oracle is test code, not a replacement implementation for Starry. When a
mismatch is found, the fix belongs in `os/StarryOS/kernel/src/file/pipe.rs` (or
the owning syscall/VFS boundary) and must preserve the existing locking and
wakeup invariants.

In particular, if the fragmentation scenario confirms the expected gap,
Starry's `PipeState` must track enough page-slot information to implement
Linux merge, atomic-write, resize, and poll rules. The test must not hide the
gap by changing expected values, dropping the scenario, or teaching another
model to agree with the byte ring.

## Migration plan

Implementation proceeds in independently reviewable steps:

1. Add `asset_cache = "reuse" | "bypass"` to QEMU case metadata, keep `reuse`
   as the default, cover parsing and cache-bypass behavior with axbuild tests,
   and document it in `test-suit/starryos/GUIDE.md`.
2. Add the x86_64 direct C case, static harness, operation corpus, precise
   success/failure markers, and host environment logging.
3. Prove the comparator fails by corrupting a generated trace in a host-side
   validation; prove host record followed by host compare succeeds.
4. Run the case against Starry. Preserve every deterministic mismatch as a
   corpus operation, then fix the production pipe implementation until the
   same case passes without result normalization that erases semantics.
5. Keep `qemu/system/bugfix-bug-pipe-linux-semantics` as the small
   cross-architecture regression. It remains a fixed expectation test and is
   not described as a Linux oracle.
6. Remove `components/pipe-model`, both duplicate workspace entries and the
   workspace dependency, the axbuild dependency and `ktest fuzz pipe` command,
   the Starry optional dependency, model adapter/exports, and
   `axtest_pipe_fuzz` target.
7. Retain low-layer deterministic axtests that directly protect production
   invariants and do not reproduce a Linux semantic model.
8. Regenerate `Cargo.lock`, format Rust code, run targeted clippy, and execute
   the validation matrix below.

The model is removed only after the executable oracle is wired into the normal
runner, so the branch never ends in a state with neither differential coverage
nor a deterministic regression.

## Regression-first evidence

The earlier audit already established red behavior before the production fix:
the buggy implementation disagreed on zero-length I/O, small atomic writes, and
writer poll readiness. The deterministic C regression was then added for those
boundaries.

The new infrastructure adds two red gates before it is considered valid:

- a one-byte corruption of an expected record must make host `--compare`
  return nonzero and identify the exact operation;
- the page-slot fragmentation scenario must remain in both the differential
  corpus and the small deterministic regression, so the previous byte-vacancy
  implementation cannot satisfy either test.

These gates distinguish a working comparator from a test that merely executes
two paths and always prints a success marker.

## Validation plan

| Claim or risk | Layer | Command or check | Required observation |
| --- | --- | --- | --- |
| Corpus and trace parsers fail closed | Host harness | malformed/truncated corpus and trace cases | Nonzero status with no pass marker |
| Comparator observes differences | Host harness | record, corrupt one result, compare | Exact operation mismatch and nonzero status |
| Same ELF is self-consistent | Host Linux | record then compare with the installed static ELF | All operations match |
| Host oracle runs on every invocation | axbuild asset test and two consecutive case preparations | `asset_cache=bypass`, no cache hit, fresh host metadata log twice | Linux record command executes twice |
| Primary compatibility path | Starry x86_64 QEMU | `cargo xtask starry test qemu --arch x86_64 -c qemu/pipe-linux-oracle` | Oracle pass marker and runner success |
| Original fixed behaviors stay portable | Starry grouped QEMU | `cargo xtask starry test qemu --arch <arch> -c qemu/system/bugfix-bug-pipe-linux-semantics` | Grouped pass marker on supported regression architectures |
| Axbuild changes remain clean | Rust tooling | `cargo xtask clippy --package axbuild` | All targeted checks pass |
| Starry pipe changes remain clean | Rust tooling | `cargo xtask clippy --package starry-kernel` | All targeted checks pass |
| Repository formatting | Rust tooling | `cargo fmt --all --check` | No diff |
| Removed model has no consumers | Repository | search workspace and lockfile for `pipe-model`, `pipe_fuzz`, and `axtest_pipe_fuzz` | No live references |

QEMU commands are run sequentially. Missing rootfs/toolchain prerequisites are
reported as environment failures, not converted into skips or semantic pass
results.

## Implementation and validation record

The migration implemented the planned boundaries:

- the handwritten `pipe-model`, fuzz batch runner, model adapter, and
  model-only axtest were removed;
- `asset_cache = "bypass"` was added as an opt-in QEMU case policy, with
  `reuse` retained as the default;
- the direct x86_64 case builds one static ELF, executes it on host Linux to
  create a fresh trace, and installs that exact ELF with the corpus and trace
  for the Starry comparison;
- Starry pipe state now tracks page-backed buffer-slot lengths in addition to
  queued bytes, and applies them to merge, atomic nonblocking write, resize,
  read-consumption, and poll decisions;
- the grouped C regression covers zero-length operations, atomic writes,
  writer poll state, and page-slot fragmentation without depending on a host
  trace.

The host harness completed all 78 corpus operations in both record and compare
modes. The recording host for this validation happened to run Linux
`5.15.0-186-generic` on x86_64 with 4096-byte pages; the harness contains no
release check. A deliberately truncated trace failed closed at the responsible
operation. The installed static executable was also checked to be identical to
the one executed on the host.

The primary x86_64 QEMU command passed repeatedly. Its final run printed a
fresh host record marker followed by
`STARRY_PIPE_LINUX_ORACLE_PASSED: operations=78` in Starry. With the shared base
image already downloaded, that run spent about 17.1 seconds preparing the
uncached case rootfs and 5.3 seconds in QEMU, for about 26.7 seconds end to end.
The small C regression passes as a native harness test and is discovered for
the x86_64 and RISC-V grouped system suites. Architecture QEMU regression runs
remain ordinary matrix coverage rather than alternative Linux oracles.

Targeted clippy completed for all axbuild and Starry kernel feature checks, the
new axbuild cache-policy tests passed, Rust formatting and repository diff
checks passed, and no live code references the removed model or fuzz target.
The full axbuild unit suite also ran: 787 tests passed, while three unrelated
environment/repository-state tests failed (a pre-existing removed platform
feature, a local Git branch-name collision, and a sandboxed network timeout).

## Syscall impact map

The table covers the syscalls directly exercised by the initial oracle and the
production pipe state they can observe.

| Syscall | Intended comparison | Reference |
| --- | --- | --- |
| `pipe2` | Create nonblocking close-on-exec endpoints; normalize only allocated fd numbers into logical slots. | [`pipe(2)`](https://man7.org/linux/man-pages/man2/pipe.2.html), [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html) |
| `read` | Compare zero-length success, nonblocking `EAGAIN`, EOF, returned byte count, and exact bytes. | [`read(2)`](https://man7.org/linux/man-pages/man2/read.2.html), [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html) |
| `write` | Compare zero-length success, `EPIPE`, `PIPE_BUF` atomicity, partial writes, and byte counts. | [`write(2)`](https://man7.org/linux/man-pages/man2/write.2.html), [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html) |
| `close` | Compare endpoint lifetime transitions and `EBADF` for invalid logical slots. | [`close(2)`](https://man7.org/linux/man-pages/man2/close.2.html), [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html) |
| `dup` | Compare success/error while mapping the new numeric fd to a logical slot; verify duplicated endpoints keep the pipe alive. | [`dup(2)`](https://man7.org/linux/man-pages/man2/dup.2.html), [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html) |
| `poll` | Compare timeout-zero return count and `revents`, including slot-based writer readiness and closed-peer events. | [`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html), [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html) |
| `fcntl` | Compare controlled `F_SETPIPE_SZ` results, `F_GETPIPE_SZ`, errno, rounding, and busy shrink behavior. | [`F_GETPIPE_SZ(2const)`](https://man7.org/linux/man-pages/man2/F_GETPIPE_SZ.2const.html), [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html) |
| `ioctl` | Compare `FIONREAD` return/errno and the exact unread-byte count. | [`ioctl(2)`](https://man7.org/linux/man-pages/man2/ioctl.2.html), [`pipe(7)`](https://man7.org/linux/man-pages/man7/pipe.7.html) |

## Cost, rollback, and future work

The regular path performs one small static C build, one host execution, one
case-rootfs preparation, and one Starry QEMU boot. This is materially cheaper
than a baseline QEMU plus one QEMU per fuzz batch, while keeping the semantic
reference authoritative.

The deliberate first-version cost is bypassing the rootfs asset cache for this
case. Local measurements show that uncached rootfs preparation is the dominant
recurring stage, but the approximately 26.7-second total remains reasonable for
one primary compatibility case. Keep the simpler v1 boundary unless CI data
shows that cost is material; only then add a generic incremental trace-injection
hook that preserves fresh host execution.

Rollback is local: remove the direct case and the `asset_cache` policy support.
No production ABI, persistent format, board workflow, or default Starry runtime
configuration depends on the oracle. Production pipe bug fixes and the
deterministic grouped regression remain valid independently.

Future work may add a host-side corpus generator, coverage-guided corpus growth,
blocking/concurrent scenarios, or a generic differential-test facility. Those
changes require their own evidence and must continue to store operations rather
than expected Linux results.
