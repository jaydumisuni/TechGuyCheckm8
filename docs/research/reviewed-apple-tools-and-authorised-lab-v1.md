# Reviewed Apple Tools and Authorised A11 Lab v1

## Reviewed executable receipts

### macOS arm64

- Gaster SHA-256: `ddcea40bcb4b22187089a338df46cbb5a9722ffb845c1e0016edd45b7588ab10`
- Gaster bytes: `71864`
- iRecovery SHA-256: `6ecacc0500baa569dc11eda53af7d28dc0da07583dc1f057f6696de8373d3497`
- iRecovery bytes: `116504`

### macOS x86_64

- Gaster SHA-256: `64985592a47023c49ee54f56ea25e9d6f84c8d29a5e4c651c52d7ba54d27f6b1`
- Gaster bytes: `34248`
- iRecovery SHA-256: `3b2aa6d85b61528af43791084a0813bce45666c08c15cd955ff73be09ac1702d`
- iRecovery bytes: `90904`

Both receipts bind the exact Gaster, libirecovery, libimobiledevice-glue and libplist source commits. The binaries remain Actions artifacts; only hashes and build evidence are tracked.

## First exact hardware target

- Product type: `iPhone10,6`
- Board: `d221ap`
- CPID: `8015`
- iOS: `16.7.10`
- Build: `20H350`
- Final environment: SSH ramdisk

## Implemented pipeline

```text
reviewed architecture-matched Gaster/iRecovery artifact
→ exact connected-device verification with redacted identity
→ pinned SSHRD source and submodules
→ exact primary IPSW source
→ BuildManifest build/product/board verification
→ generated iBSS/iBEC/logo/ramdisk/DeviceTree/trustcache/kernelcache
→ non-executing package inventory
→ catalogue and Rust runtime provider manifests
→ fixed authorised Gaster/iRecovery hardware sequence
→ same-device PWND and patched-iBoot evidence
→ ramdisk SSH evidence
→ normal-boot recovery proof by default
```

The hardware stage is manual, protected and self-hosted. It requires the `apple-lab` environment, a macOS runner labelled `ttg-apple-lab`, an authorisation ticket and the exact authorised device. It cannot promote a route to Stable.

## Review evidence

The dual-architecture builds, Apple lab contract suite, pinned SSHRD patch check, generated Rust manifest validation, workspace formatting/Clippy/tests and Sergeant deterministic proof have passed. Physical asset generation and hardware/recovery evidence remain pending until the authorised target is connected to the protected runner.
