#!/usr/bin/env python3
"""Patch the pinned SSHRD script for an exact pre-approved IPSW URL and evidence copy."""

from __future__ import annotations

import argparse
from pathlib import Path

IPSW_SELECTION = (
    'ipswurl=$(curl -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" '
    '| "$oscheck"/jq \'.firmwares | .[] | select(.version=="\'$1\'")\' '
    '| "$oscheck"/jq -s \'.[0] | .url\' --raw-output)'
)
EXACT_IPSW_SELECTION = 'ipswurl="${TTG_IPSW_URL:?TTG_IPSW_URL is required}"'
CLEANUP = 'echo "[*] Cleaning up work directory"\nrm -rf work 12rd'
EVIDENCE_CLEANUP = (
    'if [ -n "${TTG_BUILD_MANIFEST_OUT:-}" ] && [ -f work/BuildManifest.plist ]; then\n'
    '    cp work/BuildManifest.plist "$TTG_BUILD_MANIFEST_OUT"\n'
    'fi\n'
    'echo "[*] Cleaning up work directory"\n'
    'rm -rf work 12rd'
)


def patch(source: str) -> str:
    if source.count(IPSW_SELECTION) != 1:
        raise ValueError("pinned SSHRD IPSW selection line was not found exactly once")
    if source.count(CLEANUP) != 1:
        raise ValueError("pinned SSHRD cleanup line was not found exactly once")
    patched = source.replace(IPSW_SELECTION, EXACT_IPSW_SELECTION)
    patched = patched.replace(CLEANUP, EVIDENCE_CLEANUP)
    if "api.ipsw.me/v4/device/$deviceid" in patched:
        raise ValueError("dynamic primary IPSW selection remains after patch")
    return patched


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    text = args.input.read_text(encoding="utf-8")
    args.output.write_text(patch(text), encoding="utf-8")
    args.output.chmod(0o755)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
