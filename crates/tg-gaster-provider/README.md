# tg-gaster-provider

A supervised, hash-pinned Gaster worker for documented A8-A11 checkm8 routes.

## Fixed command surface

The provider can express only:

```text
gaster pwn
gaster reset
```

It accepts no free-form argument or shell string. The executable must be inside an approved process root and must match the SHA-256 recorded in the provider manifest before spawning.

## Final proof

A successful process exit is insufficient. The provider requires:

1. a locked same-device DFU identity before execution;
2. successful supervised `pwn` and `reset` child processes;
3. verified process cleanup and bounded output capture;
4. a same-device host reconnect in pwned DFU;
5. the serial marker `PWND:[checkm8]`.

The crate does not choose or send ramdisk assets. That responsibility belongs to the separate typed ramdisk pack and boot worker.

## Source pin

- repository: `https://github.com/0x7ff/gaster`
- commit: `7fffffff38a1bed1cdc1c5bae0df70f14395129b`
- licence: Apache-2.0

Stable execution remains blocked until an exact built executable hash and per-CPID hardware proof are recorded.
