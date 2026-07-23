# Apple 10-for-2 Source Matrix

This is an execution record for the current implementation batch. Ten research/implementation lanes were reconciled through two closing gates: deterministic CI and Sergeant final proof.

| Lane | Source | Borrowed capability | Deliberately excluded |
|---|---|---|---|
| 1 | TGCHECKM8 contracts | permissions, leases, state, process supervision, evidence | direct UI-to-device control |
| 2 | `ttgtool-ramdisks` | product/iOS coverage catalogue and provider destination | unverified binary trust |
| 3 | `blackra1n-icloud-bypass-ios15.x` | evidence that its wrapper delegates build/boot to SSHRD and uses SSH over `iproxy` | activation-bypass and baseband mutation logic |
| 4 | `ipwndfu` | legacy/A6-A7 pwn provider family and CPID vocabulary | unrestricted demote/NOR operations |
| 5 | `PongoOS` | A8-A11 preboot/runtime provider option | implicit route authority |
| 6 | `checkm8-a5-` | A5/A5X Arduino/MAX3421E hardware path and cable constraints | default demotion as a service action |
| 7 | TTG Unlock repositories | checksum-verified development distribution and privacy boundaries | unrelated Android/FRP behavior |
| 8 | `0x7ff/gaster` and `usbliter8` | generation-specific pwn providers and PWND evidence | cross-generation provider reuse |
| 9 | UnlockTool catalogue and SSHRD Script | working package coverage and exact typed A8-A11 build/boot recipe | remote-catalogue execution and bundled Apple images |
| 10 | X-Ray and `TTG-progress` | read-only identity certificate, route evidence, durable handoff | operation authorization |

## Reconciled implementation

The first output is split into two independent layers:

1. `tg-gaster-provider`: fixed `pwn` and `reset`, executable hash verification, supervised execution, cleanup proof, and same-device `PWND:[checkm8]` reconnect proof.
2. `tg-ramdisk-pack`: exact device/build/provider/source/asset metadata and the typed SSHRD boot sequence.

Neither layer exposes activation bypass, identity mutation, arbitrary shell execution, free-form iBoot commands, or remote package execution.

## Two closing gates

1. Rust formatting, Clippy with warnings denied, unit/integration/adversarial tests, and workspace compatibility.
2. Sergeant repository review, verification standard, proof suite, and final proof with model routing disabled.
