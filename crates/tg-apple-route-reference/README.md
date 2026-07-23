# tg-apple-route-reference

This crate converts documented working Apple routes into deterministic, device-exact verification contracts.

It binds:

- a pinned pwn-provider source and licence;
- a read-only TTG Device X-Ray certificate;
- exact product type, board configuration, CPID family, and firmware build;
- local-only SHA-256-pinned boot, ramdisk, or Diags assets;
- the ordered device-mode transitions expected from the known working recipe.

The result may become `ready_for_hardware_verification`, but `execution_authorized` is always `false` in this crate. A separate reviewed engine, explicit permissions, and hardware evidence are still required before any device operation.

## Current baseline

The first reference family is A8-A11 using Gaster, with working ramdisk and Diags catalogues treated as reference sources. Reference catalogues do not count as local asset proof and no Apple image is bundled or redistributed.

A12/A13 remains a separate `usbliter8_rp2350` provider family and cannot inherit the Gaster route.

## Authority handoff

A signed X-Ray bundle may prove identity, route-family match, freshness, and evidence integrity. It cannot activate an engine, grant a permission, approve a local asset, or declare an operation successful. TGCHECKM8 retains those decisions through its controller, policy gate, leases, worker manifests, evidence judge, recovery controller, and final-proof gate.
