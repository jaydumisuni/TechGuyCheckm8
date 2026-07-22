# SysCfg serial providers

This directory contains provider metadata only. It contains no Apple diagnostic image, serial-port driver, DCSD firmware, raw SysCfg backup, device identifier or unrestricted terminal command.

## `magiccfg-research.json`

The initial manifest records protocol and field vocabulary observed in the open MagicCFG Windows source at commit `2923e2f3d4b478938856ddc03c8be7ac2a458c99`.

Its status is intentionally limited:

- maturity is `discovered`;
- write capability is disabled;
- every real field is marked non-writable;
- identity and hardware-address fields are classified `identity_critical`;
- calibration-looking fields remain read-only until exact hardware promotion evidence exists;
- the manifest cannot pass stable-provider validation.

The manifest proves only that the command vocabulary and candidate fields were discovered. It does not prove that a command is safe on a particular product, board, Diags image, serial adapter or firmware revision.

## Promotion

A promoted provider must be added as a separate reviewed manifest. It must narrow coverage to the exact proven product and board route, declare the exact serial link, identify the source revision and licence, and enable only the individually proven non-identity fields.

Promotion must follow `docs/evidence/syscfg-serial-hardware-promotion.md`. Editing the research manifest in place to enable writes is not an accepted promotion path.
