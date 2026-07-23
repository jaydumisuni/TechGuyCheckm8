#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LAB = ROOT / "tools" / "apple-lab"
TARGET = LAB / "targets" / "iphone10,6-d221ap-16.7.10-20h350.json"


def main() -> int:
    output = Path(sys.argv[1]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    receipt = output / "receipt.json"
    inventory = output / "inventory.json"
    receipt.write_text(
        json.dumps(
            {
                "schema_version": "tgcheckm8.apple-tool-build-receipt.v1",
                "outputs": [
                    {
                        "role": "gaster_executable",
                        "filename": "gaster",
                        "byte_len": 100,
                        "sha256": "a" * 64,
                    },
                    {
                        "role": "irecovery_executable",
                        "filename": "irecovery",
                        "byte_len": 200,
                        "sha256": "b" * 64,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    roles = [
        "ibss",
        "ibec",
        "logo",
        "ramdisk",
        "devicetree",
        "trustcache",
        "kernelcache",
    ]
    inventory.write_text(
        json.dumps(
            {
                "schema_version": "tgcheckm8.package-inventory.v1",
                "classified_assets": [
                    {
                        "role": role,
                        "relative_path": f"assets/{role}.img4",
                        "sha256": f"{index + 1:x}" * 64,
                        "byte_len": 1000 + index,
                        "redistribution_allowed": False,
                    }
                    for index, role in enumerate(roles)
                ],
            }
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [
            sys.executable,
            str(LAB / "make_provider_manifest.py"),
            "--target",
            str(TARGET),
            "--build-receipt",
            str(receipt),
            "--inventory",
            str(inventory),
            "--output-dir",
            str(output / "provider"),
        ],
        check=True,
    )
    print(output / "provider" / "provider-pack.runtime.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
