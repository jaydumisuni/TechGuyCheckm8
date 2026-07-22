# Phase 4B — Read-only Apple Observation and Identity Continuity

## Purpose

Build the evidence layer required before TGCHECKM8 may execute a DFU, Purple, ramdisk, jailbreak, restore, or SysCfg provider.

This phase classifies host-provided USB observations, parses Apple DFU identity markers, redacts sensitive identifiers, locks a device identity, and proves that the same device returned after a mode transition.

It does not open a USB device or send a control transfer.

## Observation boundary

```text
host adapter
  -> raw observation in memory
  -> deterministic parser
  -> immediate identifier hashing
  -> redacted observation
  -> identity lock
  -> reconnect comparison
```

Raw serial numbers and ECIDs must not be written to journals, support bundles, fixtures, logs, or UI state. Public fixtures use explicitly synthetic identifiers.

The durable observation contains only:

- matched rule ID;
- classified device mode;
- CPID;
- SHA-256 ECID hash;
- SHA-256 serial hash;
- pwn-provider marker, when present;
- product type and board configuration when independently available;
- derived redacted identity hash;
- observation source;
- completeness verdict.

## Mode classification

Mode classification is manifest-driven and fail-closed:

- zero matching rules produces `unknown`;
- one matching rule produces the declared mode;
- multiple matching rules produce an error;
- Apple DFU with a valid `PWND:[provider]` marker is classified as `pwned_dfu`;
- a process exit code never changes the observed mode.

The initial Apple DFU rule uses VID/PID `05AC:1227` and requires a `CPID:` marker.

## Identity lock

A lock requires:

- CPID;
- ECID hash;
- derived device identity hash.

Product type and board configuration are included when available. Once present in the lock, they must remain consistent after reconnect.

The raw ECID is never stored in the lock.

## Reconnect proof

A transition such as:

```text
DFU -> PWND DFU -> Purple
```

is accepted only when:

1. the observed mode is expected for the current stage;
2. CPID matches;
3. ECID hash matches;
4. product type matches when locked;
5. board configuration matches when locked;
6. the derived identity hash matches;
7. reconnect evidence is complete.

Any mismatch blocks the transition. The controller must not continue with another connected device merely because it has the same product model.

## usbliter8 evidence

For the A12/A13 research route, the observer recognizes a DFU serial marker such as:

```text
PWND:[usbliter8]
```

That marker proves only the pwned-DFU observation. It does not prove that Purple Mode booted, that a bootchain was accepted, or that SysCfg is readable.

Purple readiness requires a later independent Purple-mode observation from an approved rule and the same locked device identity.

## Current sources

The source vocabulary includes:

- Windows USB;
- macOS IOKit;
- Linux usbfs;
- recorded synthetic fixtures.

This phase implements the deterministic core and fixtures only. OS-specific USB adapters remain a later read-only phase.

## Deliberate exclusions

No code in this phase may:

- claim a USB interface;
- send USB control or bulk transfers;
- reset or restart a device;
- invoke iRecovery, usbmuxd, Lockdown, serial, DCSD, Arduino, RP2350, or SSH tooling;
- enter DFU or pwn a device;
- boot Purple/Diags;
- read or write SysCfg;
- store raw serial numbers or ECIDs.

## Promotion gate

Before a real Purple provider can use this observer, TGCHECKM8 must pass recorded fixtures for every supported host, reconnect interruption tests, ambiguous-rule tests, missing-identity tests, and hardware evidence showing that the same device is tracked through each actual USB transition.
