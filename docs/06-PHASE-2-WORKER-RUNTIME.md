# Phase 2 — Worker Runtime Foundation

## Scope delivered

- Typed local wire protocol with mandatory connect handshake
- Explicit peer roles, requests, responses and events
- Idempotency requirements for every side-effecting method
- Exact worker identity, engine version, capability, permission, host and provenance validation
- Atomic multi-resource leases using logical deadlines
- Session-scoped idempotent run registration
- Worker- and session-owned cancellation
- Cancellation acknowledgement before terminal cancellation
- Terminal run-state enforcement
- Deterministic scenarios for success, timeout, disconnect, identity mismatch, cleanup failure and honored cancellation
- Cross-crate simulated lifecycle proof
- CI artifacts containing exact rustfmt and Clippy diagnostics when those gates fail

## Runtime sequence

```text
Worker process appears
→ protocol connect is validated
→ worker hello matches selected manifest and staged executable digest
→ side-effecting request carries an idempotency key
→ run is registered or deduplicated within the session
→ all required resources are leased atomically
→ run becomes active
→ simulator/worker emits structured events and evidence
→ evidence judge evaluates mandatory proof
→ cancellation or completion reaches a terminal run state
→ cleanup is verified
→ leases are released
```

## Resource laws

- A resource belongs to at most one active lease.
- A multi-resource request is all-or-nothing.
- A lease is bound to session, worker and run identity.
- Another session or worker cannot renew or release it.
- Expiry releases every resource owned by the lease.
- Completion without cleanup proof does not produce verified success.

## Protocol laws

- The first frame is always `connect`.
- A connection cannot handshake twice.
- Protocol version and peer identity are mandatory.
- `health` and `collect_evidence` are read-only.
- `prepare`, `execute_stage`, `cancel`, `recover` and `cleanup` require idempotency keys.
- Wire success is not device success; final proof remains separate.

## Worker laws

A worker is accepted only when its reported:

- protocol version;
- worker identity;
- engine ID and version;
- capabilities;
- permission ceiling;
- host platform and architecture;
- provenance digest

match the selected, reviewed manifest exactly.

## Deliberate exclusions

This phase still contains no:

- socket or WebSocket server;
- real process spawning;
- filesystem sandbox;
- USB, serial, Arduino, SSH or Lockdown implementation;
- device discovery;
- exploit or ramdisk engine;
- firmware or artifact write;
- persistent session database;
- graphical interface.

The simulator is deterministic test code. It cannot access a host device.

## Next phase

Phase 3 adds a local-only Gateway service, JSON framing, an isolated simulated worker process, bounded stdout/stderr handling, process deadlines, kill-and-cleanup behavior, persistent append-only session logs and a read-only CLI. A real Apple transport remains excluded until the process boundary passes adversarial tests.
