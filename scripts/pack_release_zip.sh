#!/usr/bin/env bash
set -euo pipefail
VER="${1:-1.0.0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python3 scripts/make_checksums.py
ZIP="TechGuyCheckm8-v$VER.zip"
rm -f "$ZIP"
zip -r9 "$ZIP" . -x ".git/*" "scripts/pack_release_zip.sh" "scripts/pack_release_zip.ps1"
echo "Packed $ZIP"
