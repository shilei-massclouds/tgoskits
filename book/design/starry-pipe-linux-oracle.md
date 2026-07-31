# Starry pipe differential testing with a Linux execution oracle

## Status

Implemented on 2026-07-30, extended with structured scenario generation and a
persistent canonical coverage corpus on 2026-07-31. This document records the
design and implementation of the script-driven pipe differential oracle.

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
- Starry compares return values, normalized errno, poll events, capacity/query
  values, queued byte counts, and bytes returned by reads;
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
- `scripts/pipe-oracle/replay.py` replays saved failure artifacts;
- failure artifacts include `input.bin`, `pipe.ops`, `linux.trace`,
  `pipe-linux-oracle` ELF, `guest.log`, profraw files, and `metadata.json`;
- Starry's production pipe fixes are retained.

## Non-goals

The first implementation deliberately excludes:

- blocking operations, timing comparisons, scheduler interleavings, multiple
  concurrent writers, and signal-delivery timing;
- `epoll`, `select`, FIFO pathname/open semantics, `splice`, `tee`, and
  `vmsplice`;
- a general syscall differential framework or a stable public corpus/trace
  protocol;
- a Linux VM pinned to a specific kernel release;
- coverage-guided mutation in the regular PR path or CI;
- using output from `strace` as expected data;
- dynamic `axbuild` subcommands for fuzzing (all host orchestration is in
  Python scripts outside `cargo xtask`).

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
- `corpus.py`: Canonical digest map, schema-v1 persistent entry validation,
  atomic entry/run/coverage-state saves, ELF-scoped region baselines, and the
  workspace campaign lock.
- `scenario.py`: Immutable scenario/operation IR plus the version-1 `pipe.ops`
  parser, canonical serializer, digest, typed codec errors, and campaign limits.
- `generator.py`: Version-2 deterministic operation generation using a
  versioned SHA-256 counter stream and rejection sampling. It maintains only
  logical fd resource state and never predicts return values, errno, poll
  readiness, or any semantic result. The version-1 LCG remains only for the five
  initial-seed migrations and offline comparison.
- `mutation.py`: Structured insertion, deletion, replacement, adjacent swap,
  fragment duplication/deletion, donor splice, and parameter mutation. It
  repairs dependencies needed for executable candidates and explicitly labels
  codec/limit failures as malformed.
- `artifact.py`: Failure artifact validation (ELF header, digest match) and
  atomic save.
- `runner.py`: validates one absolute artifact directory, passes it to the QEMU
  build through `STARRY_PIPE_ORACLE_ARTIFACT_DIR`, and returns only this run's
  `starryos-x86_64-unknown-none.profraw`.
- `coverage.py`: `llvm-profdata merge -sparse` and `llvm-cov export` against
  `target/x86_64-unknown-none/release/starryos`; covered pipe regions use stable
  `source:line:column` string IDs.
- `fuzz.py`: Batch fuzzing with seed, batch count, batch size. Startup merges
  five built-in seeds with compatible disk entries into a canonical-digest-
  sorted map; each selection remains 30% new generation and 70% structured
  mutation. Malformed candidates are counted and filtered before host/QEMU
  execution. Each executable batch runs one QEMU; mismatch/panic/timeout/
  coverage failure stops immediately and saves a complete failure artifact to
  `coverage/pipe-oracle-fuzz/failures/`.
- `replay.py`: Replays a saved failure. Validates schema, digests, ELF type.
  Runs the same guest QEMU with the saved artifacts. `--refresh-host`
  re-records the host trace without overwriting original evidence.

Constraints:
- A version-2 corpus entry is canonical UTF-8 `pipe.ops` and is at most 4096
  bytes; `input.bin` and `inputs/*.bin` store those exact bytes.
- One entry contains at most four scenarios and one scenario contains at most
  32 operations.
- A fixed seed and generator version produce byte-identical corpus selection,
  batch serialization, and mutations across processes.
- Codec failures carry a stable category and line number. Malformed mutation
  candidates never enter host or StarryOS execution batches.

### Persistent corpus ownership and schema

The ignored campaign state has this layout:

```
coverage/pipe-oracle-fuzz/
  corpus/<canonical-sha256>/{pipe.ops,metadata.json}
  runs/<run-id>/metadata.json
  coverage-state/<starry-elf-sha256>.json
  failures/...
  .campaign.lock
```

`CorpusStore` owns these paths. `CanonicalCorpus` owns only the deduplicated
in-memory selection map. On startup the store strictly loads finalized entry
directories, then the orchestrator merges them with the five built-in seeds and
prints the built-in, disk, and deduplicated counts. A nonblocking process-level
`flock` is held for the complete campaign so two fuzzers cannot concurrently
update the same corpus, coverage baseline, or fixed profraw path.

Corpus metadata schema v1 records the canonical and `pipe.ops` digests,
generator version, generated/mutation origin, parent and selected donor digest,
mutation type, first batch's new regions, first-observed and last-verified Git
and host environment, stability state, and batch compare/replay state. New
regions are explicitly attributed as `batch-pending`: stage 2.1 admits all
unique executable entries from a productive batch and makes no claim that an
individual entry covered a region by itself. Exact attribution and minimization
remain separate later stages.

Loading fails closed on an unknown schema or generator version, a directory or
file digest mismatch, noncanonical UTF-8 encoding, codec/resource-limit error,
invalid metadata, symlink, or unexpected finalized file. There is no implicit
migration. Mutation provenance adds no RNG calls and does not participate in
the canonical digest, preserving generator and mutation output for a fixed
seed.

A new entry is written to a hidden uniquely named temporary directory, fsynced,
and atomically renamed to its digest directory. Revalidation updates
`last_verified` and its count through a temporary metadata file plus atomic
replace. Run directories use the same temporary-directory/rename protocol.
Only finalized 64-hex digest directories are loaded, so a process killed during
its initial write cannot expose a half entry.

Coverage state schema v1 is keyed by the SHA-256 of the instrumented StarryOS
ELF. A batch loads only that ELF's region set, admits productive inputs, and
then atomically saves the enlarged baseline. Saving entries before the baseline
ensures an interrupted baseline update can retry admission, rather than losing
the productive batch permanently. A different ELF starts with an independent
empty baseline.

Each atomic run record stores the seed, exact command, measured batch duration,
candidate/executable/malformed/unique counts, sources and ancestry, new regions,
admitted digests, Starry ELF digest, and result. Run records are observational;
corpus entry directories remain the authoritative identity used for selection.

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
  guest.log
  profraws/*.profraw
  metadata.json
```

`metadata.json` includes `schema_version`, git state, host uname, page size,
fuzz seed, batch index, SHA-256 digests, exact command, coverage region
summary, and `guest_result_category`.

Saves use a temp-directory + atomic rename to prevent half-written artifacts.

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
canonical-digest-sorted selection map merged from built-in and persistent
entries; the ignored `CorpusStore` owns cross-process corpus identity, run
records, and ELF-scoped coverage baselines. Trace, profraw, guest log, and
prepared rootfs are run-owned build artifacts. Failure artifacts are saved
under `coverage/pipe-oracle-fuzz/failures/` for replay. Version-1 failure replay
keeps using the saved `pipe.ops`; it does not reinterpret an old raw
`input.bin`.

## Linux version and environment policy

There is no pinned release check. The test requires:
- a Linux x86_64 host;
- ability to execute the statically linked x86_64 harness;
- existing x86_64 Starry/QEMU prerequisites;
- enough permission for controlled pipe-size decreases.

The host release, machine, and page size are printed and stored in the trace.
If a Linux upgrade changes an observable result, the differential test fails.

## Syscall impact map

| Syscall | Comparison scope |
|---|---|
| `pipe2` | Create nonblocking close-on-exec endpoints; normalize fd numbers to logical slots |
| `read` | Zero-length success, nonblocking `EAGAIN`, EOF, byte count, exact bytes |
| `write` | Zero-length success, `EPIPE`, `PIPE_BUF` atomicity, partial writes |
| `close` | Endpoint lifetime transitions, `EBADF` for invalid slots |
| `dup` | Success/error; verify duplicated endpoints keep the pipe alive |
| `poll` | Timeout-zero return count and `revents` (slot-based writer readiness, closed-peer events) |
| `fcntl` | `F_SETPIPE_SZ` / `F_GETPIPE_SZ` controlled sizes, errno, rounding, busy shrink |
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

Future work may add precise coverage attribution and minimization,
blocking/concurrent scenarios, cross-architecture differential coverage, or
automatic CI regression detection. Those changes require their own design
evidence and must continue to keep the default test path clean.
