# Authorised Apple Lab

This directory converts reviewed host tools and a pinned SSHRD recipe into one exact A8-A11 hardware-verification lane.

## First target

- Product: `iPhone10,6`
- Board: `d221ap`
- CPID: `8015`
- iOS: `16.7.10`
- Build: `20H350`

The target manifest pins the restoration source, expected SHA-256, source commits, expected assets and final environment.

## Preparation

`prepare_exact_sshrd.sh`:

1. requires an explicit authorisation flag and protected ticket;
2. verifies the reviewed Gaster and iRecovery hashes;
3. verifies the connected device against product, board and CPID;
4. clones the pinned SSHRD source and submodules;
5. replaces its host Gaster/iRecovery binaries with the reviewed builds;
6. replaces dynamic IPSW selection with the exact approved URL;
7. preserves and validates the exact BuildManifest build/product/board evidence;
8. generates the SSHRD assets;
9. packages and inventories the assets without executing them;
10. creates catalogue/runtime provider manifests and generation receipts.

The preparation operation uses authorised pwned DFU for SSHRD key handling but does not boot the ramdisk.

## Hardware execution

`execute_exact_sequence.sh` verifies all tools/assets again, locks device continuity, runs fixed Gaster pwn/reset, sends the typed SSHRD sequence, proves ramdisk SSH, requests normal reboot by default and produces redacted hardware and recovery proof records.

The scripts never authorize Stable promotion. The protected `Authorised Apple Lab` workflow requires a self-hosted macOS runner labelled `ttg-apple-lab`, an approved `apple-lab` environment and the `TTG_AUTHORIZATION_TICKET` secret.

No activation bypass, baseband mutation, identity write or free-form terminal is included.
