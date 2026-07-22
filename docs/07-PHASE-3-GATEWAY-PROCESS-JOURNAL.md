# Phase 3 — Local Gateway, Process Boundary and Audit Journal

## Scope delivered

- Loopback-only TCP Gateway binding
- Rejection of non-loopback bind and peer addresses
- Length-prefixed JSON framing with strict maximum frame size
- Mandatory protocol handshake before requests
- Request/response ID correlation
- Fixed-executable process supervision without a shell
- Approved executable and working-directory roots
- Cleared child environment with explicit injection only
- Bounded concurrent stdout/stderr capture
- Process deadlines, forced termination and wait proof
- Simulated worker executable for success, failure, timeout, flood and environment fixtures
- Hash-chained append-only per-session journals
- One-writer journal ownership
- Session, sequence, previous-hash and record-hash validation
- Symlink, path escape and oversized-record rejection
- Read-only CLI for status, journal verification and engine inspection
- Gateway-to-journal integration proof

## Gateway laws

- The Gateway binds only to IPv4 or IPv6 loopback addresses.
- Remote/LAN binds are rejected before a socket is opened.
- Every frame is length-prefixed and bounded before allocation.
- The first frame must be a valid protocol connect frame.
- Exactly one request is served by the current test boundary.
- A response must preserve the initiating request ID.
- Gateway acceptance does not imply device success.

## Process laws

```text
reviewed absolute executable
+ executable inside approved root
+ working directory inside approved root
+ no shell
+ cleared environment
+ fixed arguments
+ bounded output
+ deadline
+ forced termination when required
+ child wait and pipe joins
= supervised worker outcome
```

A zero exit code is process evidence only. It is not transition or final device evidence.

## Journal laws

- One active writer owns a session journal.
- Entries are append-only JSON records.
- Every entry includes session identity, sequence, previous hash and its own SHA-256 hash.
- A different session cannot be injected into the chain.
- Sequence gaps, duplicates, tampering and previous-hash drift fail verification.
- Symlinked journal files are rejected.
- Journal lines are bounded to 1 MiB.
- Writer locks are removed on orderly close; stale-lock recovery remains a future explicit operation.

## Read-only CLI

The CLI currently exposes only:

```text
tgcheckm8 status
tgcheckm8 verify-journal <events.jsonl>
tgcheckm8 inspect-engine <engine.json> [stable|beta|development]
```

There is no jailbreak, restore, ramdisk, diagnostic write or device-service command in this phase.

## Deliberate exclusions

This phase still contains no:

- Apple USB discovery or transport;
- usbmuxd/Lockdown/AFC implementation;
- iRecovery, DFU, serial, DCSD, Arduino or SSH implementation;
- exploit, jailbreak or ramdisk worker;
- firmware download, patch or restore;
- activation-artifact or SysCfg access;
- network exposure beyond loopback;
- remote node pairing;
- graphical interface.

## Next phase

Phase 4 adds a read-only Apple observation layer behind the same contracts:

- host and dependency Doctor;
- USB topology inventory;
- normal/recovery/DFU observation adapters;
- stable device identity derivation and redaction;
- reconnect identity matching;
- recorded fixture playback for Windows, macOS and Linux;
- no USB writes.

A device-changing engine remains blocked until read-only observation and reconnect evidence pass adversarial testing.

## Locked handoff to Purple/Diags work

Purple Mode is not added to this phase. After Phase 4 observation passes, the next reviewed service phase will introduce only:

- typed Purple/Diags bootchain-provider contracts;
- generation-specific provider selection for A5/A5X, A6–A11 and A12/A13;
- SysCfg read, parse, validate and backup models;
- simulated transport, disconnect, checksum and rollback fixtures;
- write-policy gates requiring same-device identity, full backup, field diff, explicit authorization and read-back proof.

Real SysCfg writes, identity-field changes, NAND writes and unverified cross-board restores remain blocked until their own hardware-tested release gate passes.