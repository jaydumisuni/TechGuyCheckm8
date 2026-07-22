# tg-syscfg-read-transport

Lease-bound, fixed-command Diags serial transport for `syscfg list` and catalogued `syscfg print` operations.

The crate includes a pinned `serialport` implementation and a channel trait for deterministic simulation. It cannot express `syscfg add` or free-form serial input, and durable receipts contain hashes rather than device values.
