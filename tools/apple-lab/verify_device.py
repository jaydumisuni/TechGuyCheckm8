#!/usr/bin/env python3
"""Verify exact irecovery identity without persisting raw ECID."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def fields(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().upper()
        if key in {"CPID", "ECID", "PRODUCT", "MODEL", "MODE", "PWND", "NAME"}:
            result[key] = value.strip()
    return result


def normalize_cpid(value: str) -> str:
    value = value.strip().lower().removeprefix("0x").upper()
    if len(value) != 4 or any(ch not in "0123456789ABCDEF" for ch in value):
        raise ValueError(f"invalid CPID: {value}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--query", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-pwnd", action="store_true")
    args = parser.parse_args()

    target = json.loads(args.target.read_text(encoding="utf-8"))
    raw = args.query.read_text(encoding="utf-8", errors="replace")
    parsed = fields(raw)
    required = {"CPID", "ECID", "PRODUCT", "MODEL", "MODE"}
    missing = required - parsed.keys()
    if missing:
        raise ValueError(f"irecovery query is missing fields: {sorted(missing)}")
    cpid = normalize_cpid(parsed["CPID"])
    mismatches = []
    if cpid != target["cpid"].upper():
        mismatches.append("CPID")
    if parsed["PRODUCT"] != target["product_type"]:
        mismatches.append("PRODUCT")
    if parsed["MODEL"].lower() != target["board_config"].lower():
        mismatches.append("MODEL")
    if args.require_pwnd and parsed.get("PWND", "").lower() != "checkm8":
        mismatches.append("PWND")
    if mismatches:
        raise ValueError(f"connected device does not match target: {mismatches}")

    identity_material = "|".join(
        [cpid, parsed["ECID"].upper(), parsed["PRODUCT"], parsed["MODEL"].lower()]
    )
    output = {
        "schema_version": "tgcheckm8.apple-lab-device-proof.v1",
        "target_id": target["target_id"],
        "cpid": cpid,
        "product_type": parsed["PRODUCT"],
        "board_config": parsed["MODEL"].lower(),
        "mode": parsed["MODE"],
        "pwn_provider": parsed.get("PWND") or None,
        "device_identity_sha256": hashlib.sha256(identity_material.encode()).hexdigest(),
        "query_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "evidence_complete": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
