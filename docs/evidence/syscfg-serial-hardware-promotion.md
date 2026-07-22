# SysCfg serial hardware promotion checklist

A provider or field remains `discovered` or `simulation_tested` until every applicable item below is attached to a hardware evidence package.

## Session identity

- [ ] Product type, board configuration and CPID match the declared route.
- [ ] The Purple final proof is verified for the same session.
- [ ] The redacted device identity remains stable through every reconnect.
- [ ] The serial link type and adapter identity are recorded.

## Read and backup

- [ ] `syscfg list` completes within the declared response limit.
- [ ] Two independent list captures parse to the same field set.
- [ ] Mandatory backup keys are present.
- [ ] The raw dump is stored only in the encrypted vault.
- [ ] Snapshot, plaintext and vault-package hashes are recorded.
- [ ] The vault receipt is durable and rollback-ready.

## Field-specific write proof

- [ ] The field has a documented non-identity repair purpose.
- [ ] Its class is Diagnostic or Calibration.
- [ ] The before-value is re-read and matches the backup hash.
- [ ] Only the fixed `syscfg add <key> <value>` form is emitted.
- [ ] Immediate `syscfg print <key>` read-back matches exactly.
- [ ] A second full `syscfg list` shows no unexpected field changes.
- [ ] The previous value can be restored and read back exactly.
- [ ] The result survives the required power-cycle or reboot check.

## Failure proof

- [ ] Transport interruption before write produces `failed_no_write`.
- [ ] Read-back mismatch triggers reverse-order rollback.
- [ ] Verified rollback produces `rolled_back_verified`.
- [ ] A forced rollback failure produces `recovery_required`.
- [ ] Recovery-required sessions retain the vault backup and block normal completion.

## Promotion decision

- [ ] Raw logs are redacted before support export.
- [ ] Artifact hashes and provider versions are immutable in the record.
- [ ] Rust formatting, Clippy and all workspace tests pass.
- [ ] Sergeant verification, proof suite and final proof pass.
- [ ] The reviewed manifest changes only the exact proven field and route.

Identity-critical, unknown, ownership, activation, serial-number and hardware-address fields are not eligible for promotion through this checklist.
