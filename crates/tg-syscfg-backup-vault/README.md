# tg-syscfg-backup-vault

This crate converts an already completed and verified `syscfg list` capture into a rollback-ready encrypted backup.

## Pipeline

```text
verified read receipt + complete raw response
→ receipt/session/device/lease validation
→ deterministic SysCfg parser
→ required-key completeness check
→ hash-only SysCfg snapshot
→ XChaCha20-Poly1305 encryption
→ create-new local vault object
→ flush and durable file sync
→ reopen stored object
→ authenticate and decrypt
→ exact byte-for-byte and SHA-256 comparison
→ verified rollback-ready receipt
```

## Security boundary

The crate performs no device or serial operation. It cannot encode or send `syscfg add`, and it exposes no free-form terminal.

Raw SysCfg bytes exist only in process memory and inside the authenticated encrypted vault object. Durable JSON evidence contains hashes, counts, device scope, snapshot identity, key identifier, and verification results—never raw field values.

The filesystem vault requires an existing non-symlink directory. On Unix, group or world accessible roots are rejected and new vault objects are created with mode `0600`.

## Write promotion rule

A selected non-identity write remains blocked until all of these are true:

- the complete list contains every required backup key;
- the snapshot is verified and bound to the same session, device, provider, and board;
- the encrypted package has been reopened and authenticated;
- decrypted bytes exactly match the captured response and source hash;
- the issued `SysCfgBackupReceipt` is verified and rollback-ready;
- a later write provider independently proves field policy, before-value, read-back, and rollback behavior.
