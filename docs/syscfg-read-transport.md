# SysCfg read transport doctrine

## Scope

`tg-syscfg-read-transport` is the first bounded Diags serial data path. It follows:

```text
verified Purple mode
→ Serial Doctor ready report
→ held serial lease
→ fixed read operation
→ bounded prompt-framed response
→ existing SysCfg parser
→ hash-only receipt
```

The operation type can represent only:

```text
syscfg list
syscfg print <catalogued-key>
```

It cannot represent `syscfg add`, arbitrary strings, shell commands, terminal input, activation operations, or identity writes.

## Transport permission

A logical SysCfg read still transmits command bytes. The transport therefore requires the exact set:

- `device_observe`
- `serial_read`
- `serial_write`
- `sys_cfg_read`

`serial_write` authorizes only the already encoded fixed read command. It does not grant a caller access to raw serial bytes or the mutating SysCfg command type.

The logical `SysCfgSerialContext` remains separately validated under its read contract. Both layers must agree on session and device identity.

## Endpoint binding

A read endpoint is non-serializable and binds:

- the raw host port path;
- the redacted candidate receipt;
- fixed serial settings;
- the active lease;
- session ID;
- device identity hash.

Binding fails when:

- the Serial Doctor verdict is not ready;
- candidate and Doctor receipts differ;
- the lease owner belongs to another session;
- the serial resource is absent from the lease;
- the lease is expired;
- the device identity differs;
- control-line side effects were not acknowledged;
- the exact transport permissions are not granted.

## Framing

Each exchange:

1. opens the selected leased port with fixed settings;
2. transmits exactly one encoded read command;
3. flushes that command;
4. reads bounded chunks;
5. rejects a response over both the transport and provider limits;
6. requires a standalone `>` prompt line;
7. stops after a bounded number of consecutive timeouts;
8. verifies the exact command-byte count;
9. passes the response to the existing deterministic parser.

No response is accepted merely because bytes arrived.

## Privacy

Raw response bytes, full SysCfg dumps, and individual values are not serializable transport evidence.

Durable receipts contain only:

- schema version;
- session and lease IDs;
- hardware fingerprint;
- operation type and catalogued key;
- command action;
- bytes written and read;
- response SHA-256;
- prompt verification.

## Deliberate exclusions

This phase contains no production adapter rule, physical Purple boot, unrestricted terminal, `syscfg add`, backup-vault writer, activation operation, serial-number rewrite, MAC-address rewrite, or any other identity-field mutation.

Physical promotion requires an authorized device, recorded serial transcript with values redacted, exact command/response proof, timeout and disconnect recovery, and Sergeant final proof.
