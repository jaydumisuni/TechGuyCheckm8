# tg-apple-route-reference

This crate converts documented working Apple routes into deterministic, device-exact verification contracts.

It binds:

- a pinned pwn-provider source and licence;
- a read-only TTG Device X-Ray certificate;
- exact product type and board configuration;
- local-only SHA-256-pinned boot, ramdisk, or Diags assets;
- the ordered device-mode transitions expected from the known working recipe.

The result may become `ready_for_hardware_verification`, but `execution_authorized` is always `false` in this crate. A separate reviewed engine, explicit permissions, and hardware evidence are still required before any device operation.

## Current baseline

The first reference family is A8-A11 using Gaster, with working ramdisk and Diags catalogues treated as reference sources. Reference catalogues do not count as local asset proof and no Apple image is bundled or redistributed.

A12/A13 remains a separate `usbliter8_rp2350` provider family and cannot inherit the Gaster route.
