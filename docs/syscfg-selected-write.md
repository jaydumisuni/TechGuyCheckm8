# Selected SysCfg Write Doctrine

## Scope

This phase completes the generic transaction mechanism for one approved non-identity SysCfg field. It does not promote a production field or perform a physical device operation in CI.

## Required chain

```text
verified rollback-ready Phase 5G backup
→ reopen and authenticate encrypted vault object
→ decrypt and parse the exact full SysCfg dump
→ bind snapshot, device, board, provider, endpoint and lease
→ select exactly one catalogued Diagnostic or Calibration field
→ verify the current field value still matches the backup hash
→ issue exactly one typed syscfg add command
→ immediately print and hash the field
→ accept only an exact requested hash match
→ otherwise restore the original value from the verified backup
→ print and verify the restored value
→ RecoveryRequired when rollback cannot be proved
```

## Permanent blocks

The following remain blocked:

- identity-critical fields;
- unknown fields;
- manufacturing fields in the selected-repair path;
- multiple fields in one transaction;
- unchanged values;
- free-form Diags commands;
- writes without explicit authorization;
- writes without a current serial lease;
- writes without successful encrypted-backup decrypt-readback;
- writes when the device, board, provider, session or adapter scope differs;
- success based only on a command acknowledgment.

## Verdict meanings

- `VerifiedCommitted`: exact after-value read-back proved the requested change.
- `FailedNoWrite`: the transaction stopped before a write was accepted.
- `RolledBackVerified`: a post-write failure occurred and the original backup value was restored and proved.
- `RecoveryRequired`: a write may have occurred and rollback could not be independently proved.

## Production field promotion

A field can be enabled only in a separate reviewed provider manifest after:

1. its meaning and class are independently established;
2. its safe value domain is documented;
3. same-device read, backup, write and read-back are recorded;
4. power-loss and disconnect recovery are tested;
5. rollback is demonstrated from the encrypted vault object;
6. identity and ownership protections remain unaffected;
7. Rust, Sergeant and hardware evidence gates all pass.

## Progress handoff

After merge, the live state must be recorded in `jaydumisuni/TTG-progress` under `projects/tgcheckm8/` using `CURRENT.md`, `DONE.md`, `NEXT.md`, and `BLOCKERS.md`. That record must distinguish the completed simulation-tested mechanism from the still-blocked production field and physical-device promotion work.
