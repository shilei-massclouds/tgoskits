# Starry pipe differential testing with a Linux execution oracle

## Status

Implemented on 2026-07-30, extended with structured scenario generation,
persistent canonical coverage corpus, resumable exact coverage attribution,
and persistent coverage/mismatch minimization on 2026-07-31. Stage 3.2a added
pipe fd/status flags and `dup2`/`dup3` coverage on 2026-07-31. This document
records the design and implementation of the script-driven pipe differential
oracle.

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
- Starry compares return values, exact errno, poll events, capacity/query
  values, queued byte counts, bytes returned by reads, normalized
  `O_NONBLOCK`, and per-fd `FD_CLOEXEC`;
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
- failure artifacts include `input.bin`, `pipe.ops`, `linux.trace`,
  `pipe-linux-oracle` ELF, `guest.log`, profraw files, and `metadata.json`;
- Starry's production pipe fixes are retained.

## Non-goals

The first implementation deliberately excludes:

- blocking operations, timing comparisons, scheduler interleavings, multiple
  concurrent writers, and signal-delivery timing;
- `epoll`, `select`, FIFO pathname/open semantics, `splice`, `tee`, and
  `vmsplice`;
- `readv`/`writev`, multi-fd `poll`, `select`/`epoll`, exec-time fd lifecycle,
  and blocking fd/pipe semantics in stage 3.2a;
- a general syscall differential framework or a stable public corpus/trace
  protocol;
- a Linux VM pinned to a specific kernel release;
- coverage-guided mutation in the regular PR path or CI;
- a globally minimal scenario or an unbounded minimization search;
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
| Byte-level minimization | Simple implementation | Breaks resource relationships and spends QEMU launches on malformed inputs | Reject; reduce the scenario IR |
| Structured hierarchical delta debugging | Preserves operation/resource structure and gives deterministic checkpoints | Does not guarantee a global minimum | Select with a bounded candidate budget |

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
corpus requires a version-2 trace.

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
- `corpus.py`: Canonical digest map, strict schema-v1/v2/v3 persistent entry
  validation, active/superseded lifecycle, minimization lineage, atomic
  entry/run/coverage-state saves, ELF-scoped region baselines, and
  exact-attribution admission.
- `campaign_lock.py` and `corpus_errors.py`: Process-lock ownership and shared
  persistent-state error types.
- `attribution.py` and `attribution_schema.py`: Atomic schema-v3 attribution
  jobs (plus strict schema-v2 recovery), target-set-aware evidence validation,
  deterministic representative selection, and resumable state transitions.
- `attribution_campaign.py`: Fresh host-trace and QEMU replay orchestration,
  cross-campaign ELF restart, final representative proof, and baseline commit.
- `scenario.py`: Immutable scenario/operation IR plus the version-1/version-2
  `pipe.ops` parser, canonical serializer, digest, typed codec errors, shared
  open-file-description state, per-fd flags, and campaign limits.
- `generator.py`: Version-3 deterministic operation generation using a
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
- `artifact.py`: Strict failure schema-v1/v2 replay validation, fixed Starry and
  host ELF digests, typed result/fingerprint metadata, and atomic save.
- `reducer.py` and `minimization.py`: Pure deterministic hierarchical reduction,
  operation-origin tracking, coverage responsibility assignment, mismatch
  predicate checks, digest deduplication, and shared candidate-QEMU budgets.
- `minimization_schema.py` and `minimization_store.py`: Strict schema-v2 job and
  evidence validation (plus schema-v1 recovery), atomic checkpoints, reducer
  cursor persistence, target-set pinning, and stale/unstable failure
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
- `replay.py`: Replays a saved failure. Validates schema, digests, ELF type.
  Runs the same guest QEMU with the saved artifacts. `--refresh-host`
  re-records the host trace without overwriting original evidence.

Constraints:
- A canonical corpus entry is UTF-8 `pipe.ops` and is at most 4096
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
  coverage-state/<starry-elf-sha256>-<target-set-id>.json
  attribution-jobs/<job-id>/...
  minimization-jobs/<job-id>/...
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

A proved minimized entry is activated as schema v3 before any original entry is
marked superseded. The supersede update is a separate atomic metadata replace,
so a crash can expose both active entries but can never leave only an
uncommitted replacement. Historical directories are never deleted. Corpus
loading validates every finalized v1/v2/v3 entry, then exposes only active
entries to mutation. If a minimized digest already exists, its historical
region union and minimization lineage are merged instead of creating a duplicate
directory.

The current generator strictly reads corpus entries created by generator v2 or
v3. Existing v2 metadata and provenance are not rewritten merely because the
entry is loaded; a newly generated or mutated child records generator v3 and
uses `pipe.ops` v2. Loading fails closed on an unknown schema or generator
version, a directory or
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

Coverage state schema v2 is keyed by both the SHA-256 of the instrumented
StarryOS ELF and a fixed target-set ID. New campaigns use `pipe-fd-v2`, which
contains exactly `kernel/src/file/pipe.rs`, `kernel/src/syscall/fs/pipe.rs`, and
`kernel/src/syscall/fs/fd_ops.rs`. Schema-v1 state is read only as the implicit
`pipe-v1` target and never seeds a `pipe-fd-v2` baseline. A nonproductive batch
saves the same baseline; a productive batch must finish exact attribution and
the final representative replay before the enlarged baseline is atomically
committed. Different ELFs and target sets therefore have independent
baselines.

Run metadata schema v4 stores the fixed `target_set_id`, seed, exact command,
measured duration,
candidate/executable/malformed/unique counts, sources and ancestry, new regions,
admitted digests, Starry ELF digest, result category, attribution job ID, every
entry-to-region mapping, the representative digests, and the number of extra
QEMU replays. It also records the minimization job, original/minimized digests,
candidate/proof QEMU counts, completion mode, and size changes. Run records are
observational; corpus entry directories remain the authoritative identity used
for selection.

### Exact attribution state machine

Exact attribution is enabled by default for every productive batch. After the
initial batch QEMU reports regions outside the active ELF baseline, the
orchestrator atomically creates a schema-v3 job containing the canonical input
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
schema v2 provides its fixed Starry ELF and fingerprint directly. A schema-v1
failure remains replayable, but is imported for minimization only when its old
guest log contains exactly one strict semantic difference. The importer derives
the fingerprint, pins the active Starry ELF, and the normal original-validation
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
6. reduce length, byte, pipe size, poll masks, pipe/status/fd flags, and `dup3`
   flags through fixed simple values.

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

Each strict schema-v2 minimization job owns its fixed target set, source
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
the original and minimized schema-v2 failure artifacts.

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

Saves use a temp-directory + atomic rename to prevent half-written artifacts.
Attribution instability uses the separate schema-v3 job layout described above
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
[`dup(2)`](https://man7.org/linux/man-pages/man2/dup.2.html). The execution
oracle, rather than a hard-coded kernel version, determines the exact result
and errno for the recorded host release. Stage 3.2a changes only the oracle and
its test formats; it does not claim a new Starry production-syscall change.

## Syscall impact map

| Syscall | Comparison scope |
|---|---|
| `pipe2` | Four `O_NONBLOCK`/`O_CLOEXEC` combinations, fixed unknown-bit `EINVAL`, and logical slots |
| `read` | Zero-length success, nonblocking `EAGAIN`, EOF, byte count, exact bytes |
| `write` | Zero-length success, `EPIPE`, `PIPE_BUF` atomicity, partial writes |
| `close` | Endpoint lifetime transitions, `EBADF` for invalid slots |
| `dup` | Success/error; shared description state and cleared destination `FD_CLOEXEC` |
| `dup2` | Same-fd behavior, invalid source, occupied-destination replacement, cleared destination `FD_CLOEXEC`, normalized success |
| `dup3` | Same-fd/invalid-flag `EINVAL`, replacement, optional destination `FD_CLOEXEC`, normalized success |
| `poll` | Timeout-zero return count and `revents` (slot-based writer readiness, closed-peer events) |
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

Future work may add blocking/concurrent scenarios, cross-architecture
differential coverage, or automatic CI regression detection. Those changes
require their own design evidence and must continue to keep the default test
path clean.
