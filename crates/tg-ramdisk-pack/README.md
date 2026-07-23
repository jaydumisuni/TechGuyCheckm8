# tg-ramdisk-pack

A device/build-exact provider-pack contract derived from documented working SSHRD recipes.

## What a pack contains

- exact product type, board configuration, CPID, and firmware build;
- generation-correct pwn provider;
- pinned source repositories, commits, and licences;
- local relative asset paths, sizes, and SHA-256 values;
- a typed boot plan generated from the approved recipe;
- optional hardware transcript and recovery-proof hashes.

The pack stores metadata only. It does not bundle Apple images or accept free-form iBoot commands.

## A8-A11 SSHRD boot recipe

```text
require pwned DFU
→ send iBSS
→ wait 2 seconds
→ send iBEC
→ send `go` only for CPID 8010/8011/8012/8015
→ wait 2 seconds
→ optionally send logo and `setpicture 0x1`
→ send ramdisk and command `ramdisk`
→ send DeviceTree and command `devicetree`
→ optionally send trust cache and command `firmware`
→ send kernel cache and command `bootx`
→ prove the requested final environment
```

Changing the order, introducing an unknown command, using an unsafe path, omitting a required asset, or changing the exact device/build binding blocks the pack.

## Source pins

- Gaster: `0x7ff/gaster` at `7fffffff38a1bed1cdc1c5bae0df70f14395129b`, Apache-2.0
- SSHRD Script: `verygenericname/SSHRD_Script` at `d99ec4a19172b87d80fd9dea25eabf39291425a0`, BSD-3-Clause

A valid pack can become ready for hardware verification but never authorizes execution by itself.
