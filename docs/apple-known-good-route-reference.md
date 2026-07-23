# Known-Good Apple Route Integration

## Purpose

Documented working Apple recipes strengthen TGCHECKM8; they do not replace its controller, proof, recovery, or authorization architecture.

The route-reference layer converts a working external recipe into a device-exact contract containing:

- exact product type and board configuration;
- exact firmware build;
- the correct generation-specific pwn provider;
- pinned provider source and licence;
- local-only SHA-256-pinned boot, ramdisk, or Diags assets;
- fixed expected mode transitions;
- a signed read-only TTG Device X-Ray identity and route certificate.

## Generation providers

```text
A5/A5X  -> Arduino/MAX3421E
A6/A7   -> ipwndfu provider family
A8-A11  -> Gaster documented route family
A12/A13 -> usbliter8 RP2350 provider family
```

A route cannot inherit another generation's provider. In particular, A12/A13 cannot be routed through the A8-A11 Gaster reference.

## X-Ray boundary

X-Ray may certify:

- device identity;
- exact product, board, CPID and firmware build;
- whether the device matches a documented route-reference family;
- the expected transitions and required asset roles;
- the hash and signature of its sealed evidence bundle.

X-Ray cannot grant operational permission. A certificate with `write_allowed=true` is rejected. The route-reference evaluator always returns `execution_authorized=false`.

## Reference catalogues

Working ramdisk and Diags catalogues are evidence sources, not executable trust anchors. Their presence never substitutes for local artifact proof.

Before hardware verification, every required local artifact must have:

- a declared role;
- a nonzero size;
- a valid SHA-256;
- an exact product, board and firmware binding;
- a redistribution policy that keeps Apple or third-party images outside the repository when required.

## Promotion

```text
documented route family
-> X-Ray candidate certificate
-> exact device/build route manifest
-> local artifact hashes
-> ready for hardware verification
-> reproduce known working sequence
-> hardware transcript
-> recovery evidence
-> separate engine authorization
```

The reference layer deliberately stops before execution. Engines execute only through the existing TGCHECKM8 controller, permissions, leases, state machine, evidence judge, recovery controller and final-proof gate.
