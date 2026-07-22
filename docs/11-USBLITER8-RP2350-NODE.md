# Phase 5A — usbliter8 RP2350 Hardware Node

## Purpose

Define the first A12/A13 hardware-pwn provider behind the TGCHECKM8 controller without bundling or executing exploit firmware.

The upstream `usbliter8` source provides a low-level bootrom exploit for Apple A12, A13 and S4/S5 families using an RP2350-class USB host. TGCHECKM8 treats that implementation as an isolated hardware node, not as application code or a direct GUI action.

This phase contains contracts, parsers, synthetic evidence and policy only.

## Upstream source facts used by the contract

The pinned research source commit is:

```text
prdgmshift/usbliter8
afe8b5c8998fce63e76c0b2a88c606c61e2950c7
```

The source routes these CPIDs:

```text
8006
8020
8030
```

The source warns that T8030/A13 is not supported reliably on RP2040. TGCHECKM8 therefore forbids marking T8030 hardware-verified on RP2040 and requires RP2350 for Stable node policy.

The upstream firmware identifies the Apple DFU device before exploitation, runs the CPID-specific route, resets the USB bus, identifies the device again, confirms the PWND marker, and only then emits `exploit SUCCESS!`.

## Separation of coverage and verification

```text
supported_cpids
  = code paths visible in the pinned upstream source

hardware_verified_cpids
  = exact board + exact UF2 + exact cable + real device evidence accepted by TGCHECKM8
```

The research manifest lists upstream source coverage but has an empty hardware-verified set.

It also has:

```text
maturity: discovered
uf2_sha256: null
declared_licence: null
```

Therefore it is visible to research and routing tools but cannot produce an executable pwn plan.

## Fixed operation

This node supports only:

```text
pwn_dfu
```

It does not expose:

- raw iBoot boot;
- production demotion;
- Purple bootchain delivery;
- ramdisk boot;
- arbitrary USB transfers;
- arbitrary serial commands;
- firmware flashing.

Those require separate provider contracts and permissions.

## Permissions

The fixed pwn profile requires exactly:

- `device_observe`
- `usb_read`
- `usb_write`
- `serial_read`

A manifest with more or fewer permissions fails validation. A session missing any permission is blocked before the physical handoff begins.

## Physical handoff

The device cannot remain attached to the normal host USB stack while the RP2350 performs the low-level transfer.

The operator must explicitly acknowledge:

1. host DFU was observed and identity-locked;
2. the device was disconnected from the host;
3. the device was connected to the approved board;
4. a direct short Lightning-to-USB-A data path is used;
5. the board was power-cycled for the session.

After board execution, a second acknowledgement records:

1. the device was disconnected from the board;
2. the device was reconnected to the host.

Incomplete handoff evidence blocks the stage.

## Board evidence

The board log parser is bounded to 1 MiB and stores only its SHA-256 hash and structured fields.

It separates:

```text
initial DFU identity
post-exploit identity
```

This distinction is mandatory. A genuine successful run is expected to show a second device identity containing the PWND state. That second state must not be mistaken for a device that was already pwned at intake.

Structured board evidence includes:

- initial CPID;
- post-exploit CPID;
- whether the initial device was already pwned;
- whether the post-exploit PWND state was observed;
- success and failure markers;
- rediscovery failure;
- unsupported CPID marker;
- elapsed time;
- board self-verification verdict;
- SHA-256 of the raw log.

Raw board logs and ECIDs are not stored in final proof.

## Final proof

A board success marker is necessary but insufficient.

TGCHECKM8 accepts the pwned-DFU stage only when all of the following pass:

1. the node manifest is valid for the policy profile;
2. the exact UF2 SHA-256 is pinned;
3. the requested CPID matches the locked host identity;
4. the CPID is supported by the node;
5. Stable routes are hardware-verified for the exact CPID;
6. device servicing and operator authorization are explicit;
7. the physical handoff is complete;
8. board intake CPID matches;
9. board post-exploit CPID matches;
10. the initial device was not already pwned;
11. the board observed the post-exploit PWND state;
12. no failure or rediscovery error exists;
13. the device returned to the host;
14. the host independently observes `pwned_dfu`;
15. the host PWND provider is `usbliter8`;
16. CPID, ECID hash, product, board and derived identity still match the locked device.

Only then may the Purple bootchain provider receive the device lease.

## Stable promotion gate

Stable requires:

- RP2350 hardware;
- exact source commit;
- exact reproducible UF2 SHA-256;
- declared and reviewed licensing;
- every advertised CPID hardware-verified;
- tested approved board profile;
- tested cable/topology profile;
- repeated success-rate evidence;
- failure, timeout and power-loss recovery evidence;
- board serial evidence;
- independent host reconnect proof;
- no raw identifier leakage;
- Sergeant final proof.

## Deliberate exclusions

This phase does not:

- compile or distribute the upstream firmware;
- flash an RP2350;
- open a serial port;
- control `picotool`;
- send exploit USB traffic;
- operate on a real device;
- boot Purple/Diags;
- read or write SysCfg.

The next hardware step is a reproducible firmware build-and-pin pack, followed by a read-only serial-node adapter and owner hardware testing.