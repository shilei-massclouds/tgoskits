# Starry x86 IRQ route read-lock re-entry experiment results

## Outcome

The controlled experiment completed on 2026-08-27 and produced the strongest
positive result defined by the design. With the ordinary `SpinLock::lock()`
route read, the one-shot 50 ms overlap caused the external watchdog to pause
the guest at both the serial GSI 4 and first NVMe SMP MSI-X route. With the same
overlap and `SpinLock::lock_irqsave()`, both boots completed all 12 phases,
started the guest workload, produced fresh coverage, and ended with a normal
QMP `SHUTDOWN`.

This proves the same-CPU route-lock re-entry mechanism under forced overlap and
shows that restoring IRQ-save semantics excludes it. It does not prove that an
interrupt overlapped this lock in natural occurrences A8, A9, or D1, and it
does not establish one cause for every `defect-0001` variant. The defect
therefore remains `open; unresolved`.

## Fixed setup

All arms used the `tgoskits-starry` x86_64 KernDiff pipe smoke case, SMP=4,
QEMU q35, the same rootfs and firmware configuration, no validation fault, no
GDB, and `--no-early-boot-diff`. Every arm used a new KernDiff session and a
separately built ELF. The disabled control is common to the serial and NVMe
triplets because an unset compile-time target has no location-specific state.

The ordinary-lock experiment revision was
`a9ed0e41e5bb9ba2a42de2c20cb469c5cadbb8d9`. The IRQ-safe candidate revision
was `05564f51ecb42758a205bd31e4d787d6594bae5b`.

## Arm results

| Arm | Compile-time target | Result | Last boundary / QMP | ELF SHA-256 | Session |
| --- | --- | --- | --- | --- | --- |
| Ordinary lock control | unset | completed | `shell-ready`; `SHUTDOWN` at 18,021 ms | `59ea6e8593d05e7857523f55e62543696276429ccf27c65f020c3e7558177cf7` | `run-pipe-smoke-20260827T045531Z-4754ee44` |
| Ordinary lock serial | `serial` | `early-boot-hang` | `serial-first-irq-setup-entered` without return; `WATCHDOG` at 66,796 ms | `8aba304faddd415d19b4d2f24bb1c3055766d1eeb059f50b7b1652e13257480f` | `run-pipe-smoke-20260827T045759Z-8bbb2347` |
| Ordinary lock NVMe SMP | `nvme-smp` | `early-boot-hang` | `ipi-ready` without `smp-filesystem-online`; `WATCHDOG` at 67,096 ms | `db338f2d8dd02f0171edde507b5c7f63f1918e4087de195498ddf2a0e6b32388` | `run-pipe-smoke-20260827T051241Z-f4f24f4b` |
| IRQ-save serial | `serial` | completed | 12 phases; `SHUTDOWN` at 18,629 ms | `461a453aac60c2dc6f560169a05cf24ed31c4aed04dda269117249bb93a74b71` | `run-pipe-smoke-20260827T051908Z-ee3fa844` |
| IRQ-save NVMe SMP | `nvme-smp` | completed | 12 phases; `SHUTDOWN` at 18,671 ms | `e6479425db46271dcc4c039bb786c1785280a7e2e7a6b27d8d64f4fc2728d2d5` | `run-pipe-smoke-20260827T052422Z-132710b0` |
| IRQ-save normal smoke | unset | completed | 12 phases; `SHUTDOWN` at 19,154 ms | `2ff78c243bd970cfd986a1ab95d90484e7bc35f3c99df4c035c96baca73cdac0` | `run-pipe-smoke-20260827T053800Z-1a7d7422` |

The serial failure's v7 page contained
`serial_init_checkpoint_bitmap=0x3e0ff`: IRQ setup entered but did not return.
The first observed serial-window timer IRQ branch had already completed before
the later forced overlap. QMP reported `WATCHDOG` with `action=pause`.

The NVMe failure's v7 page contained
`filesystem_init_checkpoint_bitmap=0xffffc03f`, completed initial filesystem
initialization, and reached phase sequence 7 (`ipi-ready`). It did not publish
phase 8 (`smp-filesystem-online`). QMP again reported `WATCHDOG` with
`action=pause`.

## Retained evidence

The complete sessions and both compact incidents are retained without editing
their JSON under:

```text
/home/cloud/gitArceOS/KernDiff-evidence/defect-0001-irq-route-reentry-20260827T045531Z/
```

The failure incidents are:

- `incident-20260827T045800394732Z-d9a4e27c65d901f5` for serial;
- `incident-20260827T051241905480Z-d9a4e27c65d901f5` for NVMe SMP.

The archive manifest covers 262 original files and 1,754,808,906 logical bytes.
Its SHA-256 is
`5c2c9fd17d33d063ddf6e47f2f8aa03c679ab90af43d5fa75fbe96cfa09ba1f6`.
Every path, size, and digest matched before and after relocation. A strict
storage-only deduplication pass required identical content, size, mode, owner,
mtime, and extended attributes. It hard-linked 12 duplicate paths, released
442,368 physical bytes, preserved every path, and passed the complete manifest
verification again. Original evidence JSON was not edited and no managed-data
purge was run.

## Interpretation and production state

Commit `1ab948f772639a0437f3f8482fb85df219f8a1d6` changed `IRQ_ROUTES` from a
lock type whose ordinary acquisition disabled local IRQs to generic
`SpinLock`. The route mutation path retained `lock_irqsave()`, while two read
paths retained `.lock()`. The controlled comparison demonstrates that this
semantic mismatch admits the proposed re-entry and that the candidate restores
the earlier exclusion rule.

The retained production change makes both route reads use the same IRQ-save
guard as mutation. It adds no lock or lock order, allocation, log, checkpoint,
schema, scheduler change, filesystem behavior change, or watchdog change. The
temporary environment variable, one-shot widening state, clock reads, and
probe-only tests were removed after evidence capture. The regression test that
requires the real route-read guard to disable and restore local IRQs remains.

Natural causal attribution remains narrower than the intervention result. A8
and A9 stopped in the serial enclosing interval, and D1 stopped in the NVMe SMP
enclosing interval, but those pages did not capture a lock owner, interrupted
instruction, or nested stack. Continued natural sampling on the production
candidate is needed before changing the ledger's unresolved status.
