# Purple Boot Environment Rollback Obligation

## Why this exists

The researched A12/A13 Purple route includes an iBoot environment update followed by `saveenv`. TGCHECKM8 must therefore treat the route as potentially persistent even when the intent is only to enable USB serial for the current diagnostic session.

A successful Purple boot is a service checkpoint, not the end of the device session.

## Precondition

Before the route may start, the controller requires a boot-environment backup receipt containing:

- the same session ID;
- the same route ID;
- the same locked device identity hash;
- a valid SHA-256 snapshot hash;
- `rollback_ready: true`.

A backup from another device, route, or session is rejected. An unhashed or non-restorable snapshot is rejected.

## Plan behavior

A runnable Purple plan adds:

```text
VerifyEnvironmentBackup
```

before any boot asset is transferred.

The plan records:

```text
environment_backup_sha256
cleanup_required: true
```

The Purple final proof preserves both fields.

## Lifecycle

```text
verified pwned DFU
-> verified environment backup
-> Purple boot
-> SysCfg read/repair session
-> exit Purple
-> restore environment snapshot
-> reboot
-> verify expected normal/recovery state
-> close cleanup obligation
```

The future cleanup provider must receive the same device lease and the exact backup receipt. It may not restore another device’s environment.

## Failure behavior

If Purple boot succeeds but cleanup cannot be completed, the session result is:

```text
PURPLE READY — CLEANUP REQUIRED
```

It is not reported as a completed device operation.

The support bundle must retain:

- route and session identity;
- environment snapshot hash;
- current device mode;
- cleanup blocker;
- deterministic recovery instructions.

## Separation from SysCfg

The boot-environment snapshot is not a SysCfg backup and cannot satisfy the SysCfg rollback requirement.

A service session that performs a selected SysCfg repair therefore carries two independent rollback obligations:

1. boot-environment cleanup;
2. SysCfg same-device backup/restore readiness.

Neither can substitute for the other.