#!/usr/bin/env python3
"""Patch the pinned SSHRD script for an exact pre-approved IPSW URL and evidence copy."""

from __future__ import annotations

import argparse
from pathlib import Path

IPSW_PREFIX = 'ipswurl=$(curl -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw"'
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
    lines = source.splitlines(keepends=True)
    indexes = [index for index, line in enumerate(lines) if line.startswith(IPSW_PREFIX)]
    if len(indexes) != 1:
        raise ValueError("pinned SSHRD primary IPSW selection line was not found exactly once")
    index = indexes[0]
    newline = "\n" if lines[index].endswith("\n") else ""
    lines[index] = EXACT_IPSW_SELECTION + newline
    patched = "".join(lines)
    if patched.count(CLEANUP) != 1:
        raise ValueError("pinned SSHRD cleanup line was not found exactly once")
    patched = patched.replace(CLEANUP, EVIDENCE_CLEANUP)
    if any(line.startswith(IPSW_PREFIX) for line in patched.splitlines()):
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
