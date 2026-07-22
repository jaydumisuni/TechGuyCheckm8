# SysCfg serial provider doctrine

## Scope

The SysCfg serial provider is a typed transaction boundary for an already verified Purple/Diags session. It is not a general serial terminal and it does not enter Purple mode by itself.

The only protocol forms accepted by the provider are:

```text
syscfg list
syscfg print <catalogued-key>
syscfg add <catalogued-writable-key> <validated-value>
```

Callers cannot provide arbitrary command text.

## Source evidence

The initial protocol vocabulary was observed in the open `MagicCFG-Windows` source at commit `2923e2f3d4b478938856ddc03c8be7ac2a458c99`:

- individual reads use `syscfg print <key>`;
- complete backup capture uses `syscfg list`;
- individual updates use `syscfg add <key> <value>`.

The source path does not demonstrate a separate `syscfg save` operation. TGCHECKM8 therefore does not invent or emit one. A completed serial exchange is not accepted as proof of persistence; the provider immediately issues `syscfg print` and compares the exact value hash.

## Privacy boundary

A full `syscfg list` can include serial numbers, hardware addresses and manufacturing identifiers. Raw list bytes and field values:

- are not serializable provider evidence;
- are redacted from `Debug` output;
- remain in memory only until encrypted vault storage succeeds;
- are represented durably by SHA-256 hashes and a scoped vault receipt.

The public research manifest marks all discovered fields read-only. No real field is promoted to writable merely because an upstream editor exposes it.

## Read flow

1. Verify the same-session Purple final proof.
2. Require the exact read permission set.
3. Emit only `syscfg list`.
4. Enforce the provider response-size limit.
5. Parse a deterministic key/value map.
6. Classify known fields and mark unknown fields non-writable.
7. Require mandatory backup keys.
8. Produce a hash-only `SysCfgSnapshot`.
9. Store the raw dump in the encrypted vault.
10. Bind the vault receipt to session, device, board, source hash and byte count.

## Selected repair write flow

A write plan is built only when all of the following are true:

- the serial provider is explicitly write-capable;
- the Purple provider policy approves the request;
- the full snapshot and rollback-ready backup are verified;
- session, provider, device identity and board identity all match;
- the permission set is exact, not merely a superset;
- every selected field is catalogued and marked writable;
- only Diagnostic or Calibration classes are eligible;
- the raw before-value hashes to the declared precondition;
- the requested raw value hashes to the declared after-state;
- the value contains no line breaks, controls or command delimiters.

For each selected field the provider performs:

```text
syscfg print <key>        # verify the backed-up before value is still current
syscfg add <key> <value>  # provisional write
syscfg print <key>        # exact read-back authority
```

The transaction is committed only after every selected field matches its requested hash and the shared Purple write verification succeeds.

## Rollback

Any transport error, device error marker, parse failure, changed precondition or read-back mismatch stops forward progress.

Every field that may have been written is restored in reverse order with the backed-up raw value and independently read back. The resulting status is one of:

- `verified_committed` — all requested values read back exactly;
- `failed_no_write` — failure occurred before any possible write;
- `rolled_back_verified` — forward work failed, but every previous value was restored and proved;
- `recovery_required` — one or more previous values could not be independently restored.

A `recovery_required` result must block normal session completion and preserve the encrypted backup and evidence package.

## Field promotion criteria

A real field remains read-only until a separate promotion record proves all of the following on the exact product and board route:

1. the field has a documented repair purpose that does not replace device identity or ownership data;
2. at least two independent read captures produce a stable parser result;
3. the complete pre-write `syscfg list` is encrypted and rollback-ready;
4. a controlled write changes only the selected field;
5. immediate read-back matches the requested value exactly;
6. restore of the previous value succeeds and reads back exactly;
7. a power-cycle or normal reboot does not reveal collateral configuration changes;
8. the hardware evidence package identifies the Diags image, serial link, device route and provider versions;
9. Sergeant and the Rust proof suite pass with the promoted manifest;
10. the stable policy explicitly allows the field class.

Source-code support, a successful upstream screenshot, or a writable text box is not hardware proof. Identity-critical and unknown fields cannot be promoted through this process.

## Deliberate exclusions

This phase contains no real serial-port implementation, driver selection, DCSD pin control, Purple boot execution, Apple asset, unrestricted terminal, activation operation, serial-number rewrite, MAC-address rewrite or other identity-field write.
