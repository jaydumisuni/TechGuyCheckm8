#!/usr/bin/env bash
set -euo pipefail

CACHE="${HOME}/.techguy/assets"

IREC="${CACHE}/tools/linux/irecovery"
P1="${CACHE}/a4/payloads/a4_stage1.bin"

[ -x "$IREC" ] || { echo "Missing irecovery at $IREC"; exit 2; }
[ -f "$P1" ]   || { echo "Missing stage1 payload at $P1"; exit 2; }

echo "Sending stage1..."
"$IREC" -f "$P1"

echo "Done."
