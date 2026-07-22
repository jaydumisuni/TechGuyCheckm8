# Serial-link Doctor doctrine

## Purpose

The Serial Doctor identifies and leases the serial transport for an already verified Purple/Diags session. It exists between Purple boot proof and the SysCfg serial provider.

This phase is read-only. It must not send a newline, prompt, probe command, `syscfg list`, `syscfg print`, or any other byte to the selected port.

## Required flow

```text
verified same-session Purple proof
→ enumerate host serial candidates
→ normalize USB and descriptive metadata
→ match only bounded manifest rules
→ reject equal-authority candidates
→ derive a stable hardware fingerprint
→ open with exact settings and exclusive ownership
→ prove zero bytes were written
→ acquire serial and USB leases
→ preserve reconnect continuity across COM/TTY renumbering
```

## Privacy boundary

Raw COM names, TTY paths, adapter serial numbers, and physical USB topology strings are operational values only. They are not serializable and are redacted from `Debug` output.

Durable reports contain:

- SHA-256 port-name hash;
- SHA-256 hardware fingerprint;
- optional SHA-256 physical-location hash;
- normalized VID/PID when present;
- hashes of manufacturer and product strings;
- selected rule, link type, settings, and proof outcome.

## Matching policy

A rule must be bounded by at least one of:

- an exact VID/PID pair;
- a non-empty manufacturer pattern;
- a non-empty product pattern.

A rule with only one half of a USB identity is invalid. A rule with no bounding metadata is invalid. Equal-authority matches fail closed.

No production adapter rule is included in Phase 5D. Production rules require a recorded hardware snapshot from the exact adapter and host family. Generic internet descriptions are not hardware proof.

## Open policy

The probe receives only the selected raw port path and fixed serial settings. A ready verdict requires:

- the port opened;
- exclusive access was proved;
- exact settings were applied;
- zero bytes were written.

A probe may read zero bytes. This phase does not treat a prompt or banner as required evidence because obtaining one may require transmitting data.

## Lease policy

A ready report acquires:

- `Serial:<hardware-fingerprint>`; and
- `Usb:<physical-location-hash>` when a location is available.

A second owner cannot acquire either resource until the first lease is released or expires.

## Reconnect policy

A changed COM or TTY name does not imply a changed adapter. Reconnect continuity is accepted only when:

1. the complete hardware fingerprint is unchanged; or
2. VID/PID and the hashed physical USB location are unchanged.

A changed physical location without an exact fingerprint is blocked.

## Promotion requirements

A production discovery backend or adapter rule requires:

1. source and licence review;
2. Windows, macOS, and Linux inventory fixtures where supported;
3. raw identifier redaction proof;
4. exact port-setting proof;
5. exclusive-open proof;
6. disconnect and reconnect proof;
7. COM/TTY renumbering proof;
8. ambiguity and duplicate-interface tests;
9. zero-byte-write evidence;
10. Sergeant final proof.

## Deliberate exclusions

Phase 5D includes no OS serial library adapter, DCSD pin control, serial write implementation, Purple boot operation, SysCfg command, unrestricted terminal, activation operation, identity-field operation, or Apple diagnostic asset.
