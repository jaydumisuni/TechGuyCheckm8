# tg-syscfg-write-transport

This crate completes the guarded selected-field SysCfg transaction path.

It accepts exactly one catalogued field and requires all of the following before the serial port is opened:

- verified same-session Purple mode;
- exact device, board, provider, endpoint and lease identity;
- exact write permission grant and explicit authorization;
- an encrypted Phase 5G backup receipt marked verified and rollback-ready;
- successful vault reopen, authentication and decrypt-readback;
- a field catalogued as writable by both the serial and Purple provider policies;
- a field class of `Diagnostic` or `Calibration` only;
- a requested value that differs from the locked backup value.

The existing transaction engine then performs:

1. `syscfg print <key>` and exact before-hash verification;
2. one typed `syscfg add <key> <value>`;
3. immediate `syscfg print <key>` read-back;
4. verified commit only on exact after-hash match;
5. automatic rollback to the encrypted backup value on any post-write failure;
6. rollback read-back verification;
7. `RecoveryRequired` when rollback cannot be proved.

The real serial adapter accepts only fixed `syscfg print` and `syscfg add` command shapes. It exposes no free-form terminal.

No production field is promoted by this crate. A real field remains non-writable until a separate provider manifest is backed by same-device hardware evidence, a verified field meaning, a safe value domain, successful write/read-back proof, interrupted-write recovery proof, and Sergeant final proof. Identity-critical and unknown fields remain blocked.
