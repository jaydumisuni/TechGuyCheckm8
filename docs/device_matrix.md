# Device Matrix (CPIDs & Arduino rules)

- **A4** (S5L8930): `0x8930` → software-only (no Arduino)
- **A5/A5X** (S5L8940/42/45): `0x8940`, `0x8942`, `0x8945` → **Arduino required**
- **A6/A6X** (S5L8950/55): `0x8950`, `0x8955` → software-only
- **A7–A11**: software-only checkm8 (no Arduino)

> Your app auto-detects CPID via `irecovery -q`, then routes accordingly.
