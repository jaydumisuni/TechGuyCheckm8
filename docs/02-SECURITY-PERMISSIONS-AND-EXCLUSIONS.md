# Security, Permissions and Explicit Exclusions

## Threat model

TGCHECKM8 assumes the following may be wrong, malicious, stale or compromised:

- a downloaded engine or payload;
- a worker process and its terminal output;
- a compatibility entry not backed by exact evidence;
- a device reconnect that is not the original device;
- a USB/serial adapter reporting unexpected identity;
- an interrupted session leaving services, mounts or leases behind;
- a third-party update source;
- an operator selecting the wrong device or operation;
- files supplied by a customer;
- model-generated advice;
- closed-source binaries distributed through forums or file hosts.

## Trust boundaries

1. **Operator boundary:** human authorization is required but is not proof of compatibility.
2. **Gateway boundary:** clients request operations; the Gateway validates and authorizes them.
3. **Worker boundary:** workers are isolated executors, never final authorities.
4. **Device boundary:** every reconnect must match the locked device identity before a lease resumes.
5. **Artifact boundary:** every input is hashed, typed, source-recorded and policy-checked.
6. **Update boundary:** staged content cannot become active without verification and approval.
7. **Advisory boundary:** model or external advice is non-authoritative untrusted input.

## Permission vocabulary

Permissions are granular and deny-by-default:

```text
device.observe
device.restart
device.erase
usb.read
usb.write
serial.read
serial.write
arduino.control
ssh.connect
filesystem.read
filesystem.write
filesystem.mount.readonly
filesystem.mount.readwrite
normalmode.lockdown
normalmode.afc.read
normalmode.afc.write
normalmode.diagnostics
ramdisk.boot
firmware.download
firmware.extract
firmware.patch
firmware.restore
vault.read
vault.write
shsh.read
shsh.save
activation_artifact.read
activation_artifact.restore_same_device
syscfg.read
syscfg.backup
syscfg.restore_same_board
network.loopback
network.approved_source
process.spawn
pack.stage
pack.activate
support.export_redacted
```

A capability pack lists requested permissions. A route lists the subset it needs. A session grant is the intersection of pack request, route need, policy allowance and human authorization.

## Risk tiers

- **Tier 0 — observation:** identity, health, mode and logs.
- **Tier 1 — reversible service:** restart, read-only mount, backup, artifact export.
- **Tier 2 — controlled modification:** ramdisk boot, same-device artifact restore, same-board SysCfg restore.
- **Tier 3 — destructive:** firmware restore, erase, writable system modifications.
- **Tier 4 — prohibited in Stable:** cross-device identity or activation material, Lost Mode defeat, arbitrary identity substitution.

Tier 2 and above require explicit authorization events. Tier 3 also requires a validated recovery plan and preservation checkpoint when technically possible.

## Stable exclusions

Stable builds must block:

- activation records or FairPlay material from another device;
- arbitrary serial, ECID, UDID, Wi-Fi or Bluetooth identity changes;
- operations intended to defeat Lost Mode, account ownership or anti-theft controls;
- unknown CPIDs, boards, firmware builds or route combinations;
- unverified closed-source executables;
- payload hash mismatch;
- a different device reconnecting into an active session;
- direct shell commands supplied by manifests or UI input;
- network endpoints not pinned by an approved source record;
- AI/model output being used as a compatibility or success signal.

## Same-device and same-board restoration

Activation-artifact restoration is permitted only when provenance shows the artifact was captured from the same authorized device and all bound identity fields match.

SysCfg restoration is permitted only from a verified backup of the same board. The system must show a field-level diff, preserve the current state, write the minimum approved fields, read back and verify, and retain rollback evidence.

## Path and process containment

Workers receive an isolated session directory. All paths are resolved and rejected on absolute escape, traversal, symlink escape or NUL data. Executables and arguments come from verified manifests, not user-provided command strings. Environment secrets are scoped to the worker and excluded from logs.

## Network policy

Offline is the default execution posture. Network access is granted only to named operations such as firmware download or an explicitly approved legacy normal-mode route. Approved sources require HTTPS where the target supports it, certificate/pin policy, expected content hash and bounded redirects. Legacy HTTP requirements must be isolated, visibly warned and disabled by default in Stable.

## Data protection

Raw logs may contain device identifiers. Shareable support packages replace serial, ECID, UDID, account identifiers, tokens and known credential shapes with redacted placeholders. Artifact contents are never embedded in ordinary logs.

## Failure posture

Unknown means blocked, not probably safe. Missing evidence produces `UNVERIFIED`, not success. Cleanup failure keeps the session in `RECOVERY_REQUIRED` until the device, host services and leases are reconciled.
