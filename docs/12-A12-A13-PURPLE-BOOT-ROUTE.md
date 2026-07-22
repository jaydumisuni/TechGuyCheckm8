# Phase 5B — A12/A13 Purple Boot Route

## Purpose

Define the exact transition from a verified usbliter8 pwned-DFU session to a verified Apple Purple/Diags environment without bundling Apple internal images or exposing a free-form iBoot shell.

This phase is route contracts and simulation only. It does not send a USB packet.

## Evidence basis

Public technical documentation describes the Diags boot chain as a modified iBSS/iBEC/iBoot path that ultimately loads a Diagnostics image.

Recent public A12/A13 technician logs show the practical route:

```text
verified PWND:[usbliter8]
-> upload device-exact raw iBSS
-> send CUSTOM_BOOT
-> optional power-button hold
-> wait for recovery/iBoot
-> verify the same device
-> wait for iBoot to settle
-> upload board-exact diag.img4
-> set USB serial boot arguments
-> save environment
-> go
-> verify the same device in Purple mode
```

TGCHECKM8 records the evidence URLs in the route manifest but does not copy their binaries or claim that their closed implementations are part of TGCHECKM8.

## Route identity

A Purple route is exact, not family-generic. It binds:

- product type;
- board configuration;
- CPID;
- pwn provider;
- raw iBSS hash and size;
- Diags image hash and size;
- required operator step;
- recovery settle duration;
- output transport;
- permissions;
- proof requirements.

The first research route is:

```text
Product: iPhone11,6
Board: d331pap
CPID: 8020
Pwn provider: usbliter8
```

This records candidate coverage only. Its artifacts remain unpinned, so it cannot execute.

## Apple asset boundary

The route supports only:

```text
acquisition: user_supplied_local
redistribution_allowed: false
```

TGCHECKM8 does not:

- include raw iBSS;
- include Apple Diags images;
- download Apple internal assets;
- publish those assets in Git history or GitHub Releases;
- accept a hash without the exact expected size;
- accept an artifact size without its SHA-256 hash.

A runnable local route requires both artifacts to have valid 64-hex SHA-256 pins and nonzero sizes.

## Fixed command vocabulary

The provider exposes typed steps only:

```text
VerifyPwnedDfu
VerifyRawIbss
SendRawIbss
SendCustomBoot
HoldPowerButton(seconds)        optional, route-defined
WaitForRecovery
VerifyRecoveryIdentity
WaitForRecoverySettle(ms)       route-defined
VerifyDiagImage
SendDiagImage
SetUsbSerialBootArgs
SaveEnvironment
Go
WaitForPurple
VerifyPurpleIdentity
```

There is no arbitrary shell string, upload path, boot argument or environment variable supplied by the UI.

The implementation adapter may translate the typed steps into the reviewed transport calls, but it cannot add an unrecognized iBoot command.

## Permissions

The fixed route requires exactly:

- `device_observe`
- `usb_read`
- `usb_write`
- `filesystem_read`
- `process_spawn`
- `serial_read`

It does not receive:

- serial write for SysCfg commands;
- SysCfg read, backup or restore;
- filesystem write;
- activation-artifact access;
- firmware restore;
- arbitrary pack activation.

A broad grant containing SysCfg or another unrelated permission is rejected rather than silently ignored.

## Entry proof

The route cannot start unless:

1. the usbliter8 final proof is verified;
2. its session ID matches the Purple request;
3. CPID matches the route and locked identity;
4. product type and board configuration match exactly;
5. the host currently observes `pwned_dfu`;
6. the host PWND provider is `usbliter8`;
7. reconnect identity proves the same device;
8. authorized service and operator authorization are explicit;
9. the permission grant is exact;
10. both local assets are pinned.

## Runtime evidence

Every planned step must produce one ordered acknowledgment. Missing, duplicated or reordered steps fail final proof.

Every artifact transfer must report:

- artifact kind;
- observed SHA-256;
- observed byte size;
- transport acknowledgment.

The artifact receipt set must exactly match the plan.

## Transition proof

Two independent reconnect proofs are required:

```text
pwned DFU -> recovery/iBoot
recovery/iBoot -> PurpleDiagnostic
```

Each reconnect must match:

- CPID;
- ECID hash;
- product type;
- board configuration;
- derived device identity hash;
- expected mode.

A different device of the same model is rejected.

## Final proof

`PurpleDiagnostic` is accepted only when:

- session and route match;
- the exact fixed step sequence is acknowledged;
- artifact hashes and sizes match;
- recovery identity matches;
- Purple identity matches;
- no evidence failure exists.

The Purple boot provider then releases the device lease to a separate SysCfg serial provider. It never receives SysCfg write authority itself.

## Stable promotion gate

Stable requires:

- a hardware-tested usbliter8 pwn route;
- exact user-supplied local artifact pins;
- legal/provenance review of the route implementation;
- repeated hardware evidence for the exact product and board;
- interrupted transfer and recovery tests;
- wrong-image rejection tests;
- wrong-device reconnect rejection;
- USB serial and DCSD transport tests;
- no Apple asset redistribution;
- Sergeant final proof.

## Deliberate exclusions

This phase does not:

- execute the pwn provider;
- send raw iBSS;
- send CUSTOM_BOOT;
- upload a Diags image;
- issue iBoot commands;
- boot a real device;
- open USB serial or DCSD;
- read or write SysCfg.

The next service phase implements the Diags serial protocol as an isolated read-first provider using synthetic fixtures and the existing SysCfg safety contracts.