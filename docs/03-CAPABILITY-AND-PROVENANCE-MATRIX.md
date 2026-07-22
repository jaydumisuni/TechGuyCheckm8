# Capability and Provenance Matrix

This matrix records what each researched project contributes, how it may be integrated, and what must not be assumed.

| Source | Reusable capability | Integration strategy | Current confidence | Licence/provenance rule |
|---|---|---|---|---|
| TechGuyCheckm8 | CPID routing, payload/script bundles, cross-platform packaging concepts | Refactor owned work into capability workers | Owned but requires validation | Preserve source history and hashes |
| checkm8-a5- | Arduino/MAX3421E A5/A5X work, constants and USB Host Shield adaptations | Merge validated complete state machine into an A5 hardware worker | Partial/incomplete scaffold observed | Preserve upstream attribution and exact local changes |
| ipwndfu | Pwned DFU and bootrom research functions | Pin approved source commit or isolate forked worker | Mature upstream foundation; route-specific proof still required | Include upstream licence, source commit and patch set |
| existing ramdisk/BlackRa1n work | Ramdisk preparation, boot, SSH and service flow | Extract lawful service primitives into ramdisk workers | Existing implementation requires cleanup and exact device validation | Separate activation-bypass history from general ramdisk services |
| Sergeant | Evidence doctrine, review gates, audit and final proof | Use as independent repository/release reviewer | High | No runtime dependency required |
| Rust | Typed state, ownership, errors and isolated unsafe boundaries | Native deterministic core | High | Standard Rust ecosystem provenance controls |
| OpenClaw | Gateway/node architecture, typed protocol, queues, idempotency, staged skills/packs | Clean reimplementation for device capability workers | High as architecture reference | Do not import model authority into execution path |
| Legacy iOS Kit | Firmware lifecycle, SHSH, IPSW, restore, ramdisk, device modes, legacy compatibility | Clean-room manifests and isolated compatible workers | High operational value; route facts require exact validation | GPL code requires deliberate compatible handling; never casual copy |
| hacktiv8 | USBMux/Lockdown/AFC/Diagnostics, reconnect loop, normal-mode compatibility gate | MIT-attributed normal-mode worker primitives | Source inspected; legacy exploit route narrow | Record MIT notice and source commit |
| purpleSLIVER concept | Purple diagnostic mode, serial/DCSD and SysCfg workflow | Clean implementation from public protocols/research only | Source not verified | No binary redistribution; concept only until provenance is verified |
| BigBroActivator concept | Technician workflow, staged ramdisk/SSH operations and checkpoints | Reimplement job orchestration and mount graph | Source not verified | No binary reuse; workflow concept only |
| pyAR2SISV concept | Structured activation-artifact parsing and validation | Clean Rust parser for same-device preservation/restoration | Exact source not located | No code reuse until source/licence is verified |
| modern jailbreak providers | A12/A13 and later firmware-specific routes | Optional provider packs behind exact manifests | Provider/version dependent | Pin official source/release, licence, hash and supported matrix |

## Capability families

### Detection and transport

- USB topology and stable device identity
- USBMux and Lockdown
- AFC read/write
- Diagnostics and MobileGestalt queries
- iRecovery/DFU transport
- SSH and port forwarding
- Serial/DCSD transport
- Arduino/MAX3421E control

### Exploit and boot

- Legacy bootrom routes
- A5/A5X hardware checkm8
- A6 software route
- A7–A11 checkm8 providers
- Pwned iBSS/iBEC and kDFU
- SSH ramdisk boot
- Tethered OS boot
- Modern firmware-specific jailbreak providers

### Preservation

- Identity snapshot and firmware history
- SHSH/APTicket/Cryptex inventory
- Activation-artifact backup and same-device validation
- SysCfg read and same-board backup
- Baseband information and supported backups
- Filesystem and app-data backup where authorized
- Recovery package creation

### Firmware lifecycle

- IPSW metadata and download
- Integrity verification
- Component extraction
- Firmware key and patch-set lookup
- Custom IPSW construction
- SEP/baseband/Cryptex constraint solving
- Signed, SHSH-backed and tethered restore planning
- Just Boot

### Technician and diagnostics

- Device/host Doctor
- Driver and usbmuxd repair
- Known USB/cable/hub quirks
- Mount graph and read/write policy
- Battery and device information export
- Serial/verbose boot capture
- Redacted support package
- Job checkpoints and resume/recovery

## Provenance record requirements

Every active pack must record:

```json
{
  "source_repository": "owner/repo",
  "source_commit": "full-sha",
  "source_release": "optional-tag",
  "licence": "SPDX-expression",
  "local_patch_hash": "sha256",
  "build_recipe_hash": "sha256",
  "artifact_hashes": {},
  "maintainer": "TGCHECKM8",
  "review_status": "discovered|imported|contract_valid|simulation_tested|hardware_tested|beta|stable|deprecated|blocked"
}
```

A source name or popular reputation is not enough. Stable requires reproducible provenance and exact artifact hashes.
