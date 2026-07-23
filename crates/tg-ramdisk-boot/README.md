# tg-ramdisk-boot

A fixed iRecovery worker that executes the ordered instructions produced by a device/build-exact `tg-ramdisk-pack`.

## Accepted process forms

```text
irecovery -f <verified asset inside approved root>
irecovery -c <fixed command from typed enum>
```

The command enum is limited to `go`, `setpicture 0x1`, `ramdisk`, `devicetree`, `firmware`, and `bootx`. No caller-supplied iBoot command or shell string is accepted.

## Source pin

- repository: `https://github.com/libimobiledevice/libirecovery`
- commit: `04d04f7cbaa4696504e91c1478ddd56160ed6776`
- licence: LGPL-2.1-or-later

The locally built or packaged executable still requires its own SHA-256 and build receipt.

## Start gate

The runtime requires:

- a validated provider pack;
- a hash-pinned iRecovery executable from the approved libirecovery source pin;
- a verified same-device Gaster final proof in pwned DFU;
- exact product, board, CPID, and firmware scope;
- explicit operator authorization;
- the exact permission grant;
- an active USB lease.

## Stage gate

Before every asset transfer, the worker resolves the relative path inside the approved asset root and recomputes its SHA-256. Changed or escaped assets are blocked before process spawn.

Wait instructions are acknowledged separately and cannot advance early. Checkpoint instructions require same-device evidence and an environment-specific marker. A successful child process never substitutes for a device checkpoint.

## Recovery boundary

A failed or unclean iRecovery process marks the runtime failed and stops all later instructions. Retrying or recovering requires the TGCHECKM8 controller to evaluate the observed device mode and issue a new supervised action. Final success requires completion of every typed step and proof of the requested ramdisk or Purple environment.
