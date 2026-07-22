# Phase 4A — Purple/Diags Service Contracts

## Purpose

Define how TGCHECKM8 will boot Apple Purple/Diags environments and provide controlled SysCfg service operations without importing an exploit, bootchain, serial implementation, or real device-write path yet.

This phase is contract and simulation work only.

## Provider families

```text
A5/A5X
  -> Arduino/MAX3421E pwn provider
  -> legacy Purple bootchain provider
  -> DCSD transport where required

A6–A11
  -> software checkm8 pwn provider
  -> generation-specific Purple bootchain provider
  -> USB serial preferred, DCSD fallback

A12/A13
  -> usbliter8 RP2350 pwn provider
  -> modern Purple bootchain provider still required
  -> USB serial preferred, DCSD fallback
```

A pwn provider and a Purple provider are separate capabilities. Pwned DFU alone does not prove that Purple Mode can boot.

## Required boot stages

```text
Lock device identity
Enter DFU
Pwn DFU
Verify pwned DFU
Select exact bootchain
Verify bootchain integrity
Send Stage I
Send Stage II
Send Stage III
Wait for Purple Mode
Verify Purple identity
```

No stage may be skipped because an external tool returned exit code zero.

## Required transition evidence

Every provider must require:

- `device_identity_locked`
- `pwned_dfu_verified`
- `bootchain_integrity_verified`
- `purple_mode_verified`
- `purple_identity_match`

For the A12/A13 research route, pwned DFU must include the `PWND:[usbliter8]` marker and reconnect identity must match the locked CPID/ECID evidence.

## SysCfg read and backup

Read support must produce a verified snapshot containing:

- session identity;
- provider identity;
- redacted device identity hash;
- product type and board configuration;
- complete raw SysCfg blob hash;
- parsed field records;
- per-field class, checksum status and write eligibility.

A backup receipt binds the backup to the exact snapshot, device and board. A write cannot be approved without a verified rollback-ready backup.

## Controlled write policy

The current contract permits only same-device, same-board, backup-backed repair planning.

Required permissions:

- `serial_write`
- `sys_cfg_restore_same_board`
- `vault_read`
- `vault_write`

Required conditions:

1. Provider contract validates for the selected policy profile.
2. Provider explicitly declares write support.
3. Snapshot is verified.
4. Backup is verified and rollback-ready.
5. Session, provider, device identity and board all match.
6. Every field exists in the locked snapshot.
7. Expected before-hash matches the snapshot.
8. Field checksum is valid and the field is marked writable.
9. Explicit human authorization is present.
10. Post-write read-back proves the exact requested hashes.

## Blocked fields and routes

The following remain blocked in this phase:

- identity-critical fields;
- unknown field classes;
- cross-device backups;
- cross-board restores;
- writes without a full backup;
- writes without rollback readiness;
- writes without exact read-back;
- arbitrary NAND writes;
- real Purple bootchain execution;
- real serial or DCSD writes.

Stable policy permits only provider-approved diagnostic and calibration classes. Manufacturing fields require a later hardware-tested policy decision. Identity-critical writes remain blocked.

## A12/A13 `usbliter8` status

The repository currently provides the RP2350 hardware pwned-DFU primitive and raw iBoot control, not a Purple bootchain or SysCfg protocol implementation.

The provider record is therefore locked as:

```text
maturity: discovered
supports_syscfg_read: false
supports_syscfg_write: false
declared_licence: unknown
```

It cannot enter Beta or Stable until:

- licensing/provenance is resolved;
- exact RP2350 firmware and build hashes are pinned;
- a compatible Purple bootchain is identified and legally distributable;
- USB serial or DCSD transport is implemented;
- read-only SysCfg extraction passes hardware tests;
- backup/rollback proof passes interruption tests;
- selected writes pass exact read-back and recovery tests.

## Promotion order

```text
Provider contract valid
-> recorded fixture simulation
-> pwned DFU hardware proof
-> Purple boot hardware proof
-> SysCfg read proof
-> complete backup proof
-> unchanged backup restore proof
-> selected non-identity field repair proof
-> interruption and rollback proof
-> Beta
-> Stable
```

No model participates in provider selection, write approval, read-back verification, or final success.