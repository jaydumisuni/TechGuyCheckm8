#!/usr/bin/env python3
"""Persist a reviewed build receipt only when its reproducible evidence changes."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def fingerprint(receipt: dict[str, Any]) -> dict[str, Any]:
    host = receipt["host"]
    return {
        "schema_version": receipt["schema_version"],
        "host": {
            "system": host["system"],
            "release": host["release"],
            "machine": host["machine"],
            "compiler": host["compiler"],
            "python": host["python"],
            "pkg_config": host["pkg_config"],
        },
        "source_pins": receipt["source_pins"],
        "outputs": [
            {
                "role": item["role"],
                "filename": item["filename"],
                "relative_path": item["relative_path"],
                "byte_len": item["byte_len"],
                "sha256": item["sha256"],
                "smoke_status_code": item["smoke_status_code"],
                "smoke_output_sha256": item["smoke_output_sha256"],
            }
            for item in receipt["outputs"]
        ],
        "review_checks": receipt["review_checks"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--new-receipt", type=Path, required=True)
    parser.add_argument("--new-sums", type=Path, required=True)
    parser.add_argument("--destination-receipt", type=Path, required=True)
    parser.add_argument("--destination-sums", type=Path, required=True)
    args = parser.parse_args()

    new_receipt = load(args.new_receipt)
    if args.destination_receipt.is_file():
        current = load(args.destination_receipt)
        sums_match = (
            args.destination_sums.is_file()
            and args.destination_sums.read_bytes() == args.new_sums.read_bytes()
        )
        if fingerprint(current) == fingerprint(new_receipt) and sums_match:
            print("Reviewed receipt evidence is unchanged.")
            return 0

    args.destination_receipt.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.new_receipt, args.destination_receipt)
    shutil.copyfile(args.new_sums, args.destination_sums)
    print("Reviewed receipt evidence changed and was persisted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
