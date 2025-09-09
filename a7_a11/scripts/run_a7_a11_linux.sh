#!/usr/bin/env bash
set -euo pipefail

CACHE="${HOME}/.techguy/assets"

IREC="${CACHE}/tools/linux/irecovery"
P1="${CACHE}/a7_a11/payloads/a7_stage1.bin"
P2="${CACHE}/a7_a11/payloads/a7_stage2.bin"

[ -x "$IREC" ] || { echo "Missing irecovery at $IREC"; exit 2; }
[ -f "$P1" ]   || { echo "Missing stage1 payload at $P1"; exit 2; }
[ -f "$P2" ]   || { echo "Missing stage2 payload at $P2"; exit 2; }

echo "Sending stage1..."
"$IREC" -f "$P1"

echo "Sending stage2..."
"$IREC" -f "$P2"

echo "Done."
