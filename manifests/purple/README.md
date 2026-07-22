# Purple Provider Manifests

Provider records in this directory are deterministic routing and provenance inputs.

A listed product type means the provider is a candidate for that device family. It does not mean Purple Mode, SysCfg read, or SysCfg write has been hardware-verified.

The authoritative capability fields are:

- `maturity`
- `supports_syscfg_read`
- `supports_syscfg_write`
- `allowed_write_classes`
- `proof_requirements`
- `declared_licence`

A `discovered` provider with read/write set to `false` cannot be selected for a real service operation. It exists only so research, provenance, required hardware, and missing evidence are tracked without being mistaken for working support.

Promotion requires recorded fixtures, exact source/build hashes, declared licensing, hardware proof, reconnect identity proof, Purple-mode proof, SysCfg read proof, backup proof, interruption recovery, and exact read-back after any selected write.
