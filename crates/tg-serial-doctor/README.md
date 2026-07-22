# tg-serial-doctor

Deterministic, read-only serial-link discovery and Doctor contracts for TGCHECKM8.

This crate selects one bounded serial candidate, produces a redacted report, verifies an exclusive zero-write open, acquires serial/USB leases, and checks reconnect continuity. It does not implement an OS inventory backend and cannot send serial data.
