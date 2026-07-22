# Phase 5G — SysCfg encrypted backup vault

## Purpose

Phase 5G closes the gap between a successful `syscfg list` exchange and a repair operation that can be safely rolled back.

The phase consumes the raw response and hash-only receipt already produced by the fixed read transport. It does not reopen the serial port or send another command.

## Authority

Exact backup permissions:

```text
device_observe
serial_read
serial_write
sys_cfg_read
sys_cfg_backup
vault_write
```

`serial_write` reflects the authority exercised by the earlier fixed read transport when it sent `syscfg list`; this vault layer itself performs no serial I/O.

The logical SysCfg parsing context remains restricted to the existing exact read permission set.

## Receipt chain

A rollback-ready receipt requires all of the following bindings:

- read receipt session equals the SysCfg context and held endpoint session;
- read receipt lease equals the endpoint lease;
- adapter hardware fingerprint equals the endpoint candidate;
- device identity hash equals the endpoint and logical context;
- lease is still active when the backup is promoted;
- operation is exactly `List` with no field key;
- prompt is present as a standalone line;
- byte count and SHA-256 match the captured response;
- every provider-required backup key is present;
- snapshot source hash equals the raw response hash;
- encrypted object metadata binds snapshot, session, provider, device, board, key identifier, byte count, and field count;
- stored object is reopened, authenticated, decrypted, and compared byte-for-byte with the source;
- stored package hash is recorded in the final `SysCfgBackupReceipt`.

## Envelope

The local envelope contains:

```text
magic
format version
24-byte random nonce
bounded JSON metadata length
ciphertext length
hash-only JSON metadata
XChaCha20-Poly1305 ciphertext and authentication tag
```

The serialized metadata is authenticated as additional data. Any change to metadata, ciphertext, nonce, or tag prevents successful read-back.

## Privacy

Never serialize or journal:

- raw `syscfg list` bytes;
- field values;
- decrypted backup contents;
- the 256-bit encryption key;
- the absolute vault path.

Durable evidence may contain SHA-256 hashes, UUIDs, key identifiers, counts, provider and board scope, and verification booleans.

## Failure behavior

No rollback-ready receipt is issued after:

- an incomplete dump;
- a response/receipt mismatch;
- an expired or mismatched lease;
- an insecure vault root;
- an existing object collision;
- a short or failed write;
- package authentication failure;
- decrypt-readback mismatch;
- package or receipt hash mismatch.

A failed initial persistence attempt removes the incomplete object where possible.

## Write boundary

Phase 5G does not enable a write provider. The first selected non-identity write belongs to a later phase and must consume this verified backup receipt, re-read the before-value, execute one catalogued field mutation, verify exact read-back, and prove rollback on mismatch.
