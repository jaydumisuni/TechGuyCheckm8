# UnlockTool Static Ramdisk Observations

Status: **research-only, non-executable evidence**

Observation date: 2026-07-31

Source: local installation rooted at `C:\UnlockTool`

Method: static file, metadata, hash, driver-INF, and sanitized log inspection only

## Safety and provenance boundary

This note records behavior observed in a locally installed proprietary tool. It does
not establish source provenance, licence, implementation correctness, or authority
to redistribute any component.

The inspection did not:

- launch UnlockTool or any bundled executable;
- connect to, interrogate, modify, or reboot a device;
- extract, decrypt, or reverse the proprietary containers;
- copy tool binaries, Apple images, drivers, raw logs, or account artifacts;
- retain ECIDs, serial numbers, activation records, FairPlay files, certificates,
  account databases, or other device/account identifiers.

`Backups` and `Temp` were excluded from all saved evidence because they contain
activation/account material and private certificate files. Raw logs were not copied.
Only workflow facts that could be sanitized were transcribed.

## Installation shape

The installation contained 283 files totalling 2,701,521,484 bytes under:

```text
Backups
Binaries
DA
DataFiles
Drivers
FAQ
Logs
Temp
```

It is a multi-vendor service-tool installation. This note is intentionally limited
to Apple ramdisk observations. Huawei, Exynos, MediaTek, and other data found beside
the Apple files are outside this evidence scope.

The Apple-facing host utilities include several generations of `irecovery`,
`iproxy`, `idevicerestore`, other libimobiledevice utilities, custom `.utl`
containers, a USBLITER8 helper, a pwned-DFU driver set, Apple USB drivers, and a USB
serial driver.

## Proprietary container fingerprint

Every inspected `.rd`, legacy extensionless generic ramdisk, `.drv`, and selected
`.utl` file starts with:

```text
61 5C 04 05 14 41
```

7-Zip 26.01 did not recognize representative `.rd` or `.drv` files as archives.
The common header therefore identifies an UnlockTool-specific wrapper or container,
but its format, compression, encryption, contents, and signatures remain unknown.
No attempt was made to unpack it.

Representative container receipts:

| Relative path | Bytes | SHA-256 |
|---|---:|---|
| `Drivers\pwndfu.drv` | 5,429,479 | `83159e127f8d56305f3b08a6b18db56aafe564457f8abfbd6a42892d77b5de47` |
| `Drivers\ramdisk.drv` | 7,482,961 | `5a6c5535e014af12ee11a31d7d4d60b6fc6a5adb947867d7153ea398e247b76f` |
| `Binaries\libiboot.utl` | 625,061 | `6eae2fadc06f7078874a773d002d128ee1163db8dd0e9ea0e96076b13f9c584e` |
| `Binaries\libirecovery.utl` | 5,095,117 | `a745fc1e6852b00ebd84fcf5eb9df5778ae5fea07d8ab4ab2602baf93ebbb876` |
| `Binaries\liberecovery.utl` | 12,385,658 | `296ce58b954c8df0965b08608dae4532a8d0fb9233ca98935b1f51d5cc7a263d` |

These hashes describe the observed local files only. They are not approved
TGCHECKM8 provider pins.

## Installed ramdisk profile receipts

### Modern named profiles

| Local profile | Bytes | SHA-256 |
|---|---:|---|
| `iPhone 11_N104AP_15.0.rd` | 130,565,401 | `6b4d719f49201cb0c1385262e727e497e2ff7d50af5fad33e126ff6f5532fbba` |
| `iPhone 11_N104AP_18.5.rd` | 191,166,309 | `49082a426b5542baee618a70e7a009202e5083438d37aad8b3524a42eed385de` |
| `iPhone 11_N104AP_18.6.1.rd` | 191,342,303 | `6c0319c33179cb5ba4dd330754f842f19bb5ee39ec34505011b25b1c96dc9f26` |
| `iPhone 11_N104AP_26.3.1.rd` | 230,003,400 | `d304eaf3b3caf8a9e4ac1d74afd3262b4a3399973a568c2ce87ede8a333ee58e` |
| `iPhone XR_N841AP_13.0.rd` | 113,041,843 | `98bd4e777180a43d706c73dc21b3e35037fd029337b14c9c4cdcc3a259d0ec32` |
| `iPhone XR_N841AP_14.0.rd` | 113,093,621 | `8d5254e13bd034304bdfd7f67d6b9114312ebdf62d6a6ff6726d26d8d2479671` |
| `iPhone XR_N841AP_15.0.rd` | 128,444,609 | `5006b1690fe98979ab98b49d354d537adc33cec95757b5564b5eac69754a1c28` |
| `iPhone XR_N841AP_18.5.rd` | 189,117,258 | `8d1b9b7ea863c402f8573cdca7eea2290e89827ef78cdbf90723906fad0cbfda` |
| `iPhone XR_N841AP_18.6.1.rd` | 189,201,239 | `6f95e966f22049240b35469258f95da9e475ebcd18478024f07edb848386a16e` |

The labels above are local filenames. In particular, `26.3.1` is not treated here
as a verified public Apple version or build identifier.

### Legacy generic profiles

| Local profile | Bytes | SHA-256 |
|---|---:|---|
| `iPhone8,1-n71ap` | 107,151,947 | `e2279d940fc54531d83e9ac2d18204aba7c7744114e65a1963c96d4559b31ec9` |
| `iPhone8,1-n71map` | 107,151,344 | `a0c320cca13f739b26fecd89eee92cf0d519a444231ae71e56d4c30d5f3314c0` |
| `iPhone8,2-n66ap` | 107,148,233 | `26a8f59328c48d728ec290b1dd537a849ac3f478aeacacfa32e11ccbd07ee4fe` |
| `iPhone8,2-n66map` | 107,144,568 | `38da9ebf6a2a5ddd77bba7a8f5039e39e5b68d49283a0d7c0299310f87334837` |
| `iPhone8,4-n69ap` | 106,932,035 | `6adcbd72da373e93dc0f3a30b10b4ee7631bf8d7f1fff315703f3cbbe7f174b5` |
| `iPhone8,4-n69uap` | 106,936,506 | `42d1ca77291973a7b5b7ac3028f25fa0f125597d76adbf7a6843c9f720f22575` |
| `iPhone9,1-d10ap` | 103,622,360 | `9a21aa2429e42012b6a62d2a33d09fe0d926c9ef332a1b28fe0b98ceb3198734` |
| `iPhone9,2-d11ap` | 103,622,929 | `46a9794ea89df5d337b111d5c30be60605238ed638ed9d651346c816fd803c84` |
| `iPhone9,3-d101ap` | 103,622,101 | `669892f05df325a62a44077481ff35dca452aa58807ea5de17fcebc1d549a9a0` |
| `iPhone9,4-d111ap` | 103,622,868 | `5b30e27c45d9ed4656401f0e1177b5dd29ea40b7116cd13fe7eb3d63a8884555` |

## Host executable receipts

The selected executables are ordinary Windows PE files. Windows found no embedded
product/version metadata and reported all five as not Authenticode-signed.

| Relative path | Bytes | SHA-256 |
|---|---:|---|
| `Binaries\iRecovery3\usbliter8_boot.exe` | 275,168 | `66bbaba3e3e31d2ed1b72c3acf353ebafbd2a95f26da3b6d674c52223887c47b` |
| `Binaries\iRecovery3\irecovery.exe` | 18,432 | `8c68c5cd991cd349d98a29c451a305f7cf16da52a920bcc9037c1bdf30bfcb6e` |
| `Binaries\irecovery.exe` | 17,920 | `99cfa81cfd9013e4f3ac85751cbd48ec5507186bbd2a99c6b3327d10d10c2a05` |
| `Binaries\iproxy.exe` | 17,408 | `720dddea7054e92dd8c40942ea0180550feb9c7d17740b6876688f6b9409937e` |
| `Binaries\idevicerestore.exe` | 185,856 | `7d1c6c0c0b5697d83f6a44d9dca2b544ee0bdc32577f4ea85cb88d90af89ccd5` |

No source commit, build recipe, licence receipt, or reproducible build proof was
present beside these local files. They cannot be promoted into a TGCHECKM8 provider
from hashes alone.

## Driver observations

The pwned-DFU INF declares:

```text
Provider: libusbK
Class: libusbk devices
Driver version: 3.1.0.0, dated 2022-03-03
Primary DFU hardware ID: USB\VID_05AC&PID_1227
Service binary: libusbK.sys
```

The ramdisk driver bundle contains:

```text
Apple Mobile Device USB Driver 6.0.9999.69, dated 2017-05-19
Apple recovery/iBoot and DFU USB hardware IDs
Microsoft USB serial driver 10.0.19041.1202
```

This supports the log evidence that driver state is part of the route, not merely
host setup performed before a route starts.

## Sanitized A8-A11 observation

Two successful `BOOT RAMDISK` logs described the same iPhone 6s route:

```text
Product: iPhone8,1
Board: n71map
iBoot label: IBOOT-2234.0.0.2.22
Entry mode: DFU
Pwn provider label: GASTER
```

Observed sequence:

```text
check device
-> run Gaster pwn stage
-> send ibss.img4
-> send ibec.img4
-> execute loader
-> attempt first unnamed img4 transfer
-> observe "No response from device!"
-> install/switch 64-bit driver
-> retry and complete the transfer
-> send a second unnamed img4
-> send ramdisk.img4
-> send rdtrust.img4
-> send kernel.img4
-> boot ramdisk
```

The logs show a reproducible driver-transition retry after the first failed transfer.
The current A8-A11 TGCHECKM8 recipe broadly matches the iBSS, iBEC, loader, ramdisk,
trust-cache, kernel, and boot ordering. It does not yet model this driver transition
and retry as separately evidenced state.

The two unnamed assets cannot safely be assigned to logo, DeviceTree, or another
role from these logs alone. The tool's mount-fix hint is also not proof of the
underlying filesystem command or repair behavior.

## Sanitized A12/A13 observation

Two successful `BOOT RAMDISK` logs described the same iPhone 11 route:

```text
Product label: iPhone 11
Board: N104AP
Selected local profile: iPhone 11_N104AP_26.3.1
Pwn provider label: USBLITER8
```

Observed sequence:

```text
identify device
-> check DFU
-> lock redacted device identity
-> select the board/build-labelled profile
-> verify pwn status
-> observe PWND: USBLITER8
-> switch drivers
-> perform an unnamed boot stage
-> send boot
-> wait for recovery
-> perform an unnamed firmware stage
-> send logo
-> send pmpf
-> send wchf
-> send anef
-> send aopf
-> send avef
-> send gfxf
-> send ispf
-> send siof
-> send an unnamed asset
-> send ramdisk
-> send an unnamed asset
-> send SEP
-> send kernel
-> boot ramdisk
-> wait for SSH
-> mount filesystems
```

This is materially different from both the current A8-A11 SSH ramdisk contract and
the current A12/A13 Purple/Diags research contract. It is evidence for a distinct
A12/A13 user-supplied ramdisk route family, not evidence that the Purple route can
be reused.

The log labels `pmpf`, `wchf`, `anef`, `aopf`, `avef`, `gfxf`, `ispf`, and `siof`
are preserved exactly as observations. Their exact Apple manifest roles, transfer
commands, required order across other builds, and whether every role is mandatory
remain unverified.

## TGCHECKM8 contract implications

Before implementation, define a separate research-only A12/A13 ramdisk route with
at least these typed stages:

```text
VerifyPwnedDfu
SwitchDriver
VerifyDriverState
SendBoot
WaitForRecovery
VerifyRecoveryIdentity
SendFirmwareAsset(role)
SendRamdisk
SendSep
SendKernel
BootRamdisk
WaitForSsh
VerifySshIdentity
MountFilesystems
VerifyMount
```

The route should additionally require:

- exact product, board, CPID, firmware build, and local profile binding;
- verified USBLITER8 pwn evidence from the same session;
- same-device proof after every reconnect;
- per-asset size, SHA-256, role, and transfer acknowledgment;
- an explicit driver-transition checkpoint;
- SSH readiness and mount proofs that are independent of process exit status;
- user-supplied-local acquisition and no redistribution for Apple/tool assets;
- no arbitrary command strings from a UI or route manifest.

For A8-A11, add an evidenced driver transition and bounded transfer retry to the
route model. A retry must preserve the same session/device identity and must record
the initial failure, driver state change, and successful re-acknowledgment.

## Evidence that remains unverified

This inspection did not establish:

- the proprietary container format or any contained asset list;
- source code, source commits, licences, or reproducible builds for closed helpers;
- actual ramdisk or firmware-component hashes after container extraction;
- CPID, full Apple build identity, signing state, or cryptographic validation for
  the observed iPhone 11 profile;
- the exact commands hidden behind generic `boot`, `firmware`, send, mount, or
  retry labels;
- the semantic roles of unnamed assets;
- whether the A12/A13 sequence applies beyond N104AP and the observed local profile;
- whether USBLITER8 hardware/firmware matches TGCHECKM8's reviewed provider;
- interruption recovery, wrong-image rejection, wrong-device rejection, or normal
  boot recovery;
- any physical-device result independently reproduced by TGCHECKM8.

This note is therefore an evidence lead and contract-design input only. It must not
be used to authorize execution or to mark a route hardware-tested, Beta, or Stable.
