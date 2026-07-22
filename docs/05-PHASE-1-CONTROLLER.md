# Phase 1 — Deterministic Controller Foundation

## Scope delivered by this phase

- Legal session-state transition graph
- Terminal-state enforcement
- Recovery checkpoint transitions
- Exact-match compatibility routing
- Ambiguous and unknown route blocking
- Stable maturity and hardware-proof gate
- Permission intersection across engine, route, policy and human approval
- Offline network denial
- Destructive-operation authorization and recovery readiness
- Independent evidence source requirements
- Contradiction blocking
- Thin controller planning façade

## Still deliberately absent

- USB implementation
- Process spawning
- Worker protocol transport
- Device discovery
- Exploit execution
- Ramdisk boot
- Firmware modification
- Artifact collection
- Persistent vault storage
- GUI

No crate in this phase can modify a device.

## Integration order

```text
Session intake
→ lock identity
→ exact route selection
→ human/policy permission gate
→ preparing state
→ future worker allocation
```

A session cannot reach `Preparing` unless route and permission gates both approve. A session cannot reach `CompletedVerified` directly from execution; it must pass stage and final verification.

## Next phase

Phase 2 adds the typed local protocol, worker capability handshake, resource leases, cancellation and a simulated worker. The simulator must prove timeout, disconnect, identity mismatch and cleanup behavior before any owned exploit engine is imported.
