# Starry x86 IRQ route read-lock re-entry experiment

## Status and scope

The controlled run completed on 2026-08-27 and satisfied the predeclared
forced-overlap comparison for both locations. The temporary probe was then
removed. See [the retained result record](starry-irq-route-reentry-experiment-results.md)
for the evidence identities and limits of the conclusion.

This document defines a temporary, opt-in experiment for KernDiff defect
`defect-0001`. It does not declare the defect root cause and is not a production
diagnostic facility. The probe must be removed after the controlled runs have
been retained.

The experiment does not add checkpoints, logs, schemas, watchdog time, scheduler
policy, filesystem behavior, or a GDB dependency. The only normal-build change
in the experiment commit is code whose compile-time target is `disabled`.

## Evidence and hypothesis

The retained ordinary runs contain three locations relevant to one mechanism:

- A8 and A9 stopped after the first serial IRQ setup entered and before it
  returned.
- D1 completed `ipi-ready` and stopped before `smp-filesystem-online`, where the
  NVMe runtime expands from one to four hardware contexts and registers the new
  MSI-X sources.
- Both locations call `somehal::irq::parent_irq_for_leaf()` while local timer
  interrupts are enabled. A timer interrupt calls `ActiveIrq::id()`, which in
  turn calls `resolve_irq_route()` on the same `IRQ_ROUTES` lock.

Git history provides a concrete semantic-change candidate. Before
`1ab948f772639a0437f3f8482fb85df219f8a1d6`, the production `IRQ_ROUTES` type
was `SpinNoIrq`; therefore every `.lock()` acquisition saved and disabled local
interrupts. The synchronization migration changed the object to `SpinLock` and
kept `lock_irqsave()` for mutation, but the two read paths retained the spelling
`.lock()`, which now disables preemption only.

The hypothesis is that a local timer interrupt can therefore re-enter an x86
route read while CPU 0 holds the same non-reentrant lock. This history and call
graph make the mechanism plausible, but they do not prove that it caused any
natural occurrence.

## Alternatives

| Option | Decision | Reason |
| --- | --- | --- |
| Continue natural family runs only | deferred | Useful for prevalence, but a rare schedule gives slow evidence about one mechanism. |
| Add more persistent checkpoints | rejected for this experiment | The current phase/checkpoint evidence already identifies the two call windows. |
| Attach GDB to every boot | rejected as the primary test | A probabilistic timing defect is likely to be perturbed substantially. |
| Widen the existing critical section once | selected | Produces a bounded, mechanism-specific overlap without changing the permanent observation surface. |
| Apply `lock_irqsave()` without a reproducing arm | rejected | A passing build alone would not distinguish repair from failure to exercise the race. |

## Probe design

The environment variable `KERNDIFF_IRQ_ROUTE_REENTRY_PROBE` is consumed by
`somehal` at compile time. Accepted values are:

- unset: disabled control build;
- `serial`: CPU 0, x86 IOAPIC GSI 4;
- `nvme-smp`: CPU 0, x86 MSI parent route whose leaf hardware ID is 2.

Any other value fails compilation. The target is a compile-time constant, so an
unset control build has no probe state lookup or clock read on the route-read
path after optimization.

The selected read site claims one `AtomicBool` and busy-waits for approximately
50 ms in the TSC domain while it still owns `IRQ_ROUTES`. Mismatched routes,
non-CPU-0 calls, and repeated matching calls do not read the clock. The probe
does not allocate, take another lock, call external code, or emit output.

The serial target is tied to the QEMU PC COM1 route. Reaching the existing
serial IRQ-setup return checkpoint proves that the matching lookup completed.
The NVMe target is tied to the current KernDiff QEMU profile, in which the NVMe
controller is the MSI-X allocation and reserves leaf 0 for admin, leaf 1 for
the bootstrap I/O queue, and leaf 2 for the first queue added by
`online_smp()`. Reaching `smp-filesystem-online` proves that registration of
that added source completed. These targets are intentionally not a general
fault-injection API.

## Arms and interpretation

Run each location as three separately built arms:

1. Current ordinary `.lock()`, probe disabled. This checks that the experiment
   base can complete, but one completion says nothing about the natural rate.
2. Current ordinary `.lock()`, matching probe enabled. A timer IRQ should enter
   during the widened section and the external watchdog should report the same
   phase window.
3. Candidate `.lock_irqsave()`, the same matching probe enabled. The pending
   timer IRQ should be delivered only after the route guard drops, and the boot
   should reach all 12 phases, guest start, and normal QMP `SHUTDOWN`.

The strongest positive result is arm 2 hanging and arm 3 completing for both
locations. That result proves the same-CPU re-entry mechanism and the candidate
exclusion rule under forced overlap. It still does not, by itself, prove that
the mechanism explains every natural defect variant. A failure of arm 2 to hang
or arm 3 to complete rejects this candidate as designed and must be retained
without reinterpretation.

## Candidate repair

The candidate changes only the two `IRQ_ROUTES` read acquisitions to
`lock_irqsave()`, matching mutation and restoring the pre-migration production
semantics. It adds no lock, changes no lock order, and does not expand the
critical section. On entry from hard-IRQ context the saved state is already
disabled and remains disabled; on task-context entry the guard restores the
previous local state on drop.

A host regression test observes the real `ax-sync` critical-section provider
from inside the route-read guard. It must fail with the pre-candidate ordinary
lock and pass only when the read guard has saved and disabled local IRQs. Pure
tests also cover probe target selection, CPU restriction, and one-shot
claiming.

## Acceptance and cleanup

Before any QEMU run:

- the `somehal` host tests pass with the bare-metal absolute symbols supplied
  only to the test link:

  ```text
  env RUSTFLAGS='-C link-arg=-Wl,--defsym=STACK_SIZE=0x40000 -C link-arg=-Wl,--defsym=PAGE_SIZE=0x1000 -C link-arg=-Wl,--defsym=__PERCPU_TEMPLATE_ALIGN_START=0x1000 -C link-arg=-Wl,--defsym=__PERCPU_TEMPLATE_ALIGN_END=0x2000' cargo test -p somehal --lib
  ```

- `cargo check -p somehal --tests` also compiles every platform test target;
- `cargo test -p ax-sync --features host-test` passes;
- warnings-as-errors clippy for `somehal`, `axruntime`, `ax-fs-ng`,
  `ax-driver`, and `starry-kernel` passes;
- `cargo fmt --all --check` and `git diff --check` pass;
- an x86_64 Starry release build succeeds for each probe value used.

QEMU is operator-run. Each arm must use a fresh session and preserve its target
ELF, guest log, target result, QMP terminal event, source commit, and exact
environment. A probe arm must not reuse an ELF built for another value.

After the controlled evidence is recorded, remove the probe module, compile-time
environment variable, and probe-only tests. Keep this design and the result
record. The candidate repair may remain only if the controlled evidence and
normal no-probe smoke acceptance both pass. The defect remains `open;
unresolved` until that evidence is reviewed.
