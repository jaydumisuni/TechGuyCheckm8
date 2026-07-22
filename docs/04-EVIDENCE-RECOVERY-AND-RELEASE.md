# Evidence, Recovery and Release Doctrine

## Evidence classes

- **Observation:** a directly measured device, host or artifact fact.
- **Execution:** a worker started, exited, timed out or emitted a structured event.
- **Transition:** the device moved from one verified mode/state to another.
- **Integrity:** a file, payload, pack or artifact matches an expected hash/schema.
- **Authorization:** a human approved a named operation and risk tier.
- **Recovery:** cleanup, retry or rollback completed and was independently checked.
- **Final proof:** all mandatory evidence for the operation is satisfied.

Execution evidence alone never proves a device transition or successful operation.

## Stage result vocabulary

```text
SUCCESS_VERIFIED
SUCCESS_PARTIAL
UNVERIFIED
RETRYABLE_FAILURE
USER_ACTION_REQUIRED
UNSUPPORTED
BLOCKED_BY_POLICY
DEVICE_DISCONNECTED
IDENTITY_MISMATCH
RECOVERY_REQUIRED
CANCELLED
FAILED
```

## Evidence record

Each record includes:

- evidence identifier and schema version;
- session and stage identifiers;
- timestamp and monotonic sequence;
- evidence class and source;
- stable device identity reference;
- observed values;
- artifact hashes where applicable;
- collector identity/version;
- validation outcome;
- redaction classification;
- links to superseding or contradicting evidence.

Contradictions are retained and resolved by explicit rules. They are not deleted.

## Stage proof examples

### Pwned DFU

Mandatory:

- device was previously verified in DFU;
- executing worker and payload hashes match the selected route;
- observed pwn marker is from the same device identity;
- independent transport query confirms expected post-exploit state.

### SSH ramdisk ready

Mandatory:

- expected USB transition occurred;
- ramdisk build/device identifiers match the route;
- SSH handshake completes on the allocated tunnel;
- a read-only identity query matches the locked device;
- required services report healthy.

### Artifact preservation

Mandatory:

- source path/capability authorized;
- artifact read completed;
- hash and size recorded;
- parser/schema validation completed where supported;
- device binding recorded;
- vault write committed and read back;
- raw content excluded from normal logs.

### Final jailbreak state

Mandatory:

- provider-specific proof requirements pass;
- device returned to the expected boot state;
- common post-boot verification passes;
- no unresolved recovery or cleanup blocker remains.

## Recovery plan

Every device-changing stage declares:

```json
{
  "safe_to_retry": false,
  "maximum_attempts": 1,
  "expected_failure_modes": [],
  "expected_device_state_after_failure": "Unknown",
  "cleanup_actions": [],
  "rollback_actions": [],
  "manual_actions": [],
  "restore_required_conditions": [],
  "recovery_proof_requirements": []
}
```

The controller, not the worker, decides whether a retry is allowed.

## Recovery checkpoints

1. Intake and identity locked
2. Route and artifacts verified
3. Required preservation completed
4. Target mode verified
5. Exploit/boot stage verified
6. Service environment verified
7. Modification committed
8. Reboot/exit completed
9. Final state verified
10. Host services and leases cleaned

A session can resume only from a checkpoint whose evidence remains valid for the same device, route and active pack versions.

## Cleanup requirements

Cleanup covers:

- worker process termination;
- tunnel and proxy termination;
- mount reconciliation;
- USB/serial/Arduino lease release;
- temporary directory deletion or quarantine;
- restoration of host services such as usbmuxd;
- sensitive environment and token removal;
- final device rediscovery.

Cleanup failure produces `RECOVERY_REQUIRED`, even when the main operation appears complete.

## Session final proof

```text
Route approval
+ mandatory stage evidence
+ independent final device verification
+ cleanup proof
+ no unresolved blocker
= SUCCESS_VERIFIED
```

Any missing mandatory input produces `UNVERIFIED` or failure, never a fabricated success.

## Release channels

- **Development:** contract-valid experiments; owner/developer use only.
- **Beta:** hardware-tested routes with known limitations and telemetry-free evidence export.
- **Stable:** exact supported combinations with successful proof, recovery tests and packaged rollback.

## Stable release gate

A Stable release requires:

1. Repository and architecture review passes.
2. Contract/schema tests pass.
3. Compatibility manifests validate and contain no ambiguous overlaps.
4. All bundled artifacts match checksums and provenance records.
5. Clean-host installation/package tests pass on supported hosts.
6. Positive hardware fixtures pass for each claimed route family.
7. Negative and identity-mismatch fixtures block correctly.
8. Interruption, timeout, disconnect and cancellation recovery tests pass.
9. Licence and third-party notices are complete.
10. Previous stable engine/app versions remain available for rollback.
11. Sergeant Final Proof passes.
12. Owner approves publication.

## Update workshop

```text
Upstream/source change detected
→ stage only
→ verify provenance/hash/licence
→ contract and compatibility validation
→ simulation and negative fixtures
→ Sergeant review
→ owner approval
→ Beta activation
→ hardware evidence
→ Stable promotion
```

No automatic upstream update may directly replace an active Stable pack.
