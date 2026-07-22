# TGCHECKM8 System Architecture

## 1. System shape

```text
Desktop UI / CLI
        ↓ typed local protocol
TGCHECKM8 Gateway
        ↓
Policy and Authorization Gate
        ↓
Session State Machine
        ↓
Compatibility and Route Solver
        ↓
Resource Lease + Lane Queue
        ↓
Capability Worker Host
        ↓
Exploit / Ramdisk / Normal-mode / Firmware / Diagnostic Workers
        ↓
Evidence Judge
        ↓
Final Proof + Recovery Ledger
```

The Gateway is the only control plane. The UI cannot launch tools or write to a device directly. Workers cannot select their own route, expand their own permissions or declare the final result.

## 2. Rust core workspace

```text
crates/
├── tg-contracts       shared types and schemas
├── tg-protocol        request/response/event protocol
├── tg-session         typed lifecycle state machine
├── tg-device          device identity and mode evidence
├── tg-router          compatibility and route selection
├── tg-policy          authorization and deny-by-default rules
├── tg-leases          USB, serial, SSH and worker resource ownership
├── tg-worker-host     isolated process supervision
├── tg-evidence        evidence normalization and proof evaluation
├── tg-recovery        retry, rollback and cleanup planning
├── tg-vault           preservation metadata and artifact inventory
├── tg-updater         staged packs, signatures and rollback pointers
├── tg-doctor          host, driver, dependency and topology checks
├── tg-gateway         local control plane
└── tg-cli             deterministic operator interface
```

Unsafe device operations remain behind worker boundaries. The core consumes structured events, never arbitrary terminal text as authoritative proof.

## 3. Device modes

The canonical mode model is:

```text
Disconnected
Normal
Recovery
DFU
PwnedDFU
PwnedIBSS
PwnedIBEC
KDFU
PurpleDiagnostic
RamdiskBooting
RamdiskSSH
TetheredOS
Unknown
```

Every transition has three parts:

1. prior observed mode;
2. requested transition and authorized worker;
3. independent evidence of the resulting mode.

An exploit process exit code is execution evidence, not device-state evidence.

## 4. Session states

```text
Idle
Detected
IntakeLocked
RouteProposed
AwaitingAuthorization
Preparing
WaitingForDeviceMode
ExecutingStage
StageVerification
RecoveryRequired
Rebooting
FinalVerification
CompletedVerified
CompletedUnverified
Failed
Cancelled
```

A session is append-only in the audit ledger. Corrections add new events rather than rewriting old ones.

## 5. Resource ownership

Resource lanes serialize unsafe collisions:

```text
session:<session-id>       concurrency 1
device:<stable-id>         concurrency 1
usb:<port-path>            concurrency 1
serial:<adapter-id>        concurrency 1
arduino:<board-id>         concurrency 1
ssh:<device-session>       concurrency 1
vault:<ecid>               concurrency 1 for writes
pack:<engine-id>           concurrency 1 for activation
```

A worker receives a time-bound lease. Lease loss, timeout, process death or device identity mismatch forces the session into recovery or unverified failure.

## 6. Worker boundary

Each worker implements:

```text
hello / capability handshake
health
prepare
execute_stage
cancel
recover
collect_evidence
cleanup
```

The handshake declares version, capabilities, host support, requested permissions, executable provenance and expected evidence types. The core rejects unknown fields when policy requires strict mode and rejects missing mandatory fields always.

Workers run with:

- fixed executable and arguments;
- restricted environment;
- isolated working directory;
- explicit network policy;
- explicit filesystem roots;
- one or more granted resource leases;
- deadline and cancellation channel;
- structured stdout protocol;
- bounded captured stderr for diagnostics.

## 7. Capability packs

```text
packs/
├── bundled/
├── managed/
├── owner-approved/
├── staged/
└── retired/
```

Each pack contains:

```text
engine.toml
compatibility.json
permissions.json
recovery.json
proof-requirements.json
checksums.sha256
provenance.json
LICENSE
THIRD_PARTY_NOTICES.md
```

Precedence is owner-approved override, managed verified pack, bundled stable pack. Staged and retired packs are never selected by Stable routing.

## 8. Compatibility solver

Routing is a constraint solution, not a chip-name lookup. Inputs include:

- product type and board configuration;
- chip/CPID and architecture;
- current iOS/iPadOS version and build;
- requested operation;
- current device mode;
- host OS/architecture;
- transport and hardware availability;
- SHSH/APTicket/Cryptex inventory;
- SEP and baseband constraints;
- tethered/untethered requirements;
- data-preservation preference;
- route maturity and exact hardware evidence;
- known quirks and blocked combinations.

The solver returns an approved route, a set of unmet requirements, or a deterministic block. It never returns “try anyway” in Stable.

## 9. Evidence judge

Every stage declares required proof before execution. Proof is evaluated independently of the worker that performed the stage where technically possible.

Examples:

- DFU: USB identity and mode query
- Pwned DFU: recognized pwn marker plus matching device identity
- Ramdisk ready: expected USB transition, SSH handshake and ramdisk build identity
- Mount ready: explicit mount table and read test
- Artifact preserved: hash, size, schema validation and vault commit
- Post-jailbreak: provider-specific state plus common post-boot device evidence

Final success requires all mandatory evidence and no unresolved blocker.

## 10. Preservation Vault

```text
vault/devices/<stable-device-id>/
├── identity/
├── firmware-history/
├── shsh/
├── aptickets/
├── cryptex/
├── activation-records/
├── syscfg/
├── baseband/
├── backups/
├── recovery-packages/
└── manifests/
```

Shareable reports redact ECID, serial, UDID, account identifiers and secrets. Raw artifacts never enter normal logs.

## 11. Model independence

The authoritative path must pass with no internet, API key, local model, Hunter, OpenAI, Ollama or hosted service. Optional advisory integrations can explain a log or retrieve documentation, but their output is untrusted input and cannot change route, policy, permission, recovery or proof verdicts.

## 12. Initial implementation sequence

1. Contracts, schemas and validation tests.
2. Read-only device discovery and mode observation.
3. Session ledger, leases and cancellation.
4. Compatibility solver with no device-changing route enabled.
5. Worker simulator and failure fixtures.
6. Evidence and final-proof engine.
7. Doctor and support-package export.
8. First owned checkm8 route behind Beta policy.
9. Existing ramdisk route behind Beta policy.
10. Preservation services, then firmware lifecycle and modern providers.
