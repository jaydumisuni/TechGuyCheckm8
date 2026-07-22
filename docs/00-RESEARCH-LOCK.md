# TGCHECKM8 Research Lock

Status: **Architecture review candidate**  
Scope: deterministic Apple device lifecycle platform  
Authority: THETECHGUY DIGITAL SOLUTIONS owner approval remains final

## Product definition

TGCHECKM8 is a local-first Apple device lifecycle, preservation, jailbreak, diagnostic, firmware and recovery platform. It is not a single exploit, a loose script collection, or a model-driven agent.

The platform unifies independently versioned capability workers beneath one typed controller, one compatibility solver, one permission system, one evidence ledger and one recovery policy.

## Architectural sources studied

The design intentionally combines lessons from:

- **Sergeant (SRG):** evidence before claims, specialist separation, deny-by-default policy, audit trails, review gates and final proof.
- **Rust:** typed states, explicit errors, ownership of device resources and narrow unsafe boundaries.
- **OpenClaw:** one control plane, typed clients/nodes, capability discovery, queues, idempotency, staged packs and operator approval.
- **Legacy iOS Kit:** complete Apple firmware lifecycle, device-mode handling, SHSH preservation, ramdisk services, restore planning, IPSW workflows and legacy compatibility knowledge.
- **TechGuyCheckm8 / checkm8-a5 / ipwndfu / existing ramdisk work:** currently owned exploit, routing and ramdisk foundations.
- **hacktiv8:** normal-mode USBMux/Lockdown/AFC/Diagnostics transport patterns and deterministic reconnect verification.
- **purpleSLIVER, BigBroActivator and pyAR2SISV concepts:** diagnostic-mode, technician workflow and structured artifact-preservation ideas. Closed or unverified implementations are not imported.

## Constitutional rules

1. No UI directly controls a device.
2. No worker acts without an explicit capability grant.
3. No unknown device, firmware, route, payload or permission is treated as safe.
4. No model participates in authoritative routing, permission, execution, recovery or success decisions.
5. No success exists without independent device evidence.
6. One device transport has one active lease and one authoritative session at a time.
7. Destructive operations require a verified recovery path and an explicit human authorization event.
8. Engine updates are staged, verified and approved before activation; active known-good versions remain rollback targets.
9. Every redistributed dependency, payload and patch requires provenance, licence and checksum records.
10. Public Stable builds exclude cross-device activation artifacts, arbitrary identity substitution, Lost Mode defeat and unverified closed binaries.

## Authority hierarchy

```text
Owner authorization
        ↓
TGCHECKM8 policy gate
        ↓
Compatibility and route solver
        ↓
Typed session state machine
        ↓
Device lease and command queue
        ↓
Approved capability worker
        ↓
Independent evidence judge
        ↓
Session final proof
```

Models may explain logs or documentation only. They cannot override any deterministic block.

## Operation families

The core contracts support these families even when an early release leaves some disabled:

- Diagnose device and host
- Jailbreak
- Boot SSH ramdisk
- Preserve device identity and recoverable artifacts
- Save SHSH/APTicket/Cryptex material where technically supported
- Build and verify firmware artifacts
- Signed, SHSH-backed and tethered restore planning
- Tethered Just Boot
- Enter approved diagnostic mode
- Read and back up SysCfg
- Restore the same board's verified SysCfg backup for repair
- Preserve and restore the same authorized device's activation artifacts
- Export a redacted support package

## Explicit non-goals for Stable

- Cross-device activation-record injection
- Arbitrary serial, ECID, Wi-Fi or Bluetooth identity substitution
- Defeating Lost Mode, ownership controls or account locks
- Running unverified binaries obtained from download forums
- Selecting routes based on AI/model output
- Blindly executing shell output as proof
- Publishing a route as Stable without exact hardware evidence

## Release maturity

```text
Discovered → Imported → Contract Valid → Simulation Tested
→ Hardware Tested → Beta → Stable → Deprecated/Blocked
```

A route reaches Stable only after deterministic compatibility proof, payload integrity proof, successful hardware evidence, interruption/recovery testing, negative tests, clean-host packaging proof, licence review and rollback proof.

## Immediate implementation boundary

The first branch creates only:

- architecture and policy documents;
- machine-readable contracts;
- a Rust workspace skeleton for deterministic types;
- schema validation and contract tests.

Existing exploit payloads and device-changing scripts remain untouched until the foundation passes Sergeant review and owner approval.
