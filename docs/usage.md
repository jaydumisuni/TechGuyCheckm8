# Usage

The orchestration host should:
1. Ensure the device is in **DFU mode**.
2. Call `irecovery -q`, parse **CPID**.
3. Route:
   - A5/A5X → compile/upload Arduino sketch (or upload prebuilt HEX) then run optional post-scripts.
   - A4/A6/A7–A11 → software-only scripts for the host OS.
4. Scripts call `tools/<os>/irecovery` to send payloads in order.
5. Display progress and final status ("Done" on success).

## Integrity
Always verify files against `checksums.txt` before running.
