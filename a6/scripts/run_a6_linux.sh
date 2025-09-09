#!/usr/bin/env bash
set -euo pipefail

CACHE="${HOME}/.techguy/assets"

IREC="${CACHE}/tools/linux/irecovery"
P1="${CACHE}/a6/payloads/a6_stage1.bin"
P2="${CACHE}/a6/payloads/a6_stage2.bin"

[ -x "$IREC" ] || { echo "Missing irecovery"; exit 2; }
[ -f "$P1" ]   || { echo "Missing stage1"; exit 2; }
[ -f "$P2" ]   || { echo "Missing stage2"; exit 2; }

echo "Sending stage1..."
"$IREC" -f "$P1"

echo "Sending stage2..."
"$IREC" -f "$P2"

echo "Done."
