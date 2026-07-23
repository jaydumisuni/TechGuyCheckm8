#!/usr/bin/env python3
"""Generate exact catalogue and runtime ramdisk manifests from verified inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

CATALOG_SCHEMA = "tgcheckm8.ramdisk-pack.v1"
RUNTIME_SCHEMA = "tgcheckm8.ramdisk-pack.v1"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def tool_asset(receipt: dict[str, Any], role: str) -> dict[str, Any]:
    record = next((item for item in receipt["outputs"] if item["role"] == role), None)
    if not record:
        raise ValueError(f"build receipt is missing {role}")
    return {
        "role": role,
        "relative_path": f"tools/{record['filename']}",
        "sha256": record["sha256"],
        "byte_len": record["byte_len"],
        "redistribution_allowed": False,
    }


def boot_steps(cpid: str, roles: set[str]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = [
        {"kind": "require_checkpoint", "value": "pwned_dfu_verified"},
        {"kind": "send_asset", "value": "ibss"},
        {"kind": "wait_millis", "value": 2000},
        {"kind": "send_asset", "value": "ibec"},
    ]
    if cpid.upper() in {"8010", "8011", "8012", "8015"}:
        steps.append({"kind": "recovery_command", "value": "go"})
    steps.extend(
        [
            {"kind": "wait_millis", "value": 2000},
            {"kind": "prove_checkpoint", "value": "patched_iboot_ready"},
        ]
    )
    if "logo" in roles:
        steps.extend(
            [
                {"kind": "send_asset", "value": "logo"},
                {"kind": "recovery_command", "value": "setpicture_0x1"},
            ]
        )
    steps.extend(
        [
            {"kind": "send_asset", "value": "ramdisk"},
            {"kind": "recovery_command", "value": "ramdisk"},
            {"kind": "send_asset", "value": "devicetree"},
            {"kind": "recovery_command", "value": "devicetree"},
        ]
    )
    if "trustcache" in roles:
        steps.extend(
            [
                {"kind": "send_asset", "value": "trustcache"},
                {"kind": "recovery_command", "value": "firmware"},
            ]
        )
    steps.extend(
        [
            {"kind": "send_asset", "value": "kernelcache"},
            {"kind": "recovery_command", "value": "bootx"},
            {"kind": "prove_checkpoint", "value": "ramdisk_ready"},
        ]
    )
    return steps


def runtime_step(step: dict[str, Any]) -> dict[str, Any]:
    kind = step["kind"]
    value = step["value"]
    key_map = {
        "require_checkpoint": "require_checkpoint",
        "send_asset": "send_asset",
        "recovery_command": "recovery_command",
        "wait_millis": "wait_millis",
        "prove_checkpoint": "prove_checkpoint",
    }
    command_map = {"setpicture_0x1": "set_picture_one"}
    return {key_map[kind]: command_map.get(value, value)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    target = load_json(args.target)
    receipt = load_json(args.build_receipt)
    inventory = load_json(args.inventory)
    if target["schema_version"] != "tgcheckm8.apple-lab-target.v1":
        raise ValueError("unsupported target schema")
    if receipt["schema_version"] != "tgcheckm8.apple-tool-build-receipt.v1":
        raise ValueError("unsupported build receipt schema")
    if inventory["schema_version"] != "tgcheckm8.package-inventory.v1":
        raise ValueError("unsupported package inventory schema")

    assets = list(inventory["classified_assets"])
    assets.extend(
        [
            tool_asset(receipt, "gaster_executable"),
            tool_asset(receipt, "irecovery_executable"),
        ]
    )
    roles = {item["role"] for item in assets}
    missing = set(target["expected_assets"]) - roles
    if missing:
        raise ValueError(f"package is missing expected roles: {sorted(missing)}")
    if len(roles) != len(assets):
        raise ValueError("provider inputs contain duplicate asset roles")

    steps = boot_steps(target["cpid"], roles)
    pack_id = target["target_id"].replace("ios", "sshrd-ios")
    sources = [
        {
            "source_id": "gaster",
            "repository": "https://github.com/0x7ff/gaster",
            "commit": target["source_pins"]["gaster"],
            "licence": "Apache-2.0",
            "role": "pwned_dfu_provider",
        },
        {
            "source_id": "irecovery",
            "repository": "https://github.com/libimobiledevice/libirecovery",
            "commit": target["source_pins"]["irecovery"],
            "licence": "LGPL-2.1-or-later",
            "role": "fixed_usb_boot_transport",
        },
        {
            "source_id": "sshrd-script",
            "repository": "https://github.com/verygenericname/SSHRD_Script",
            "commit": target["source_pins"]["sshrd"],
            "licence": "BSD-3-Clause",
            "role": "known_working_build_recipe",
        },
    ]
    catalogue = {
        "schema_version": CATALOG_SCHEMA,
        "pack_id": pack_id,
        "route_reference_profile_id": "apple:a8-a11:gaster-reference",
        "product_type": target["product_type"],
        "board_config": target["board_config"],
        "cpid": target["cpid"],
        "firmware_build": target["firmware_build"],
        "environment": target["final_environment"],
        "pwn_provider": "gaster",
        "sources": sources,
        "assets": sorted(assets, key=lambda item: item["role"]),
        "boot_recipe": {
            "recipe_id": target["boot_recipe"],
            "source_commit": target["source_pins"]["sshrd"],
            "steps": steps,
        },
        "maturity": "contract_valid",
        "execution_enabled": False,
        "hardware_transcript_sha256": None,
        "recovery_proof_sha256": None,
    }
    runtime_assets = {
        item["role"]: {
            "role": item["role"],
            "relative_path": item["relative_path"],
            "sha256": item["sha256"],
            "byte_len": item["byte_len"],
            "redistribution_allowed": False,
        }
        for item in assets
    }
    runtime = {
        "schema_version": RUNTIME_SCHEMA,
        "pack_id": pack_id,
        "route_reference_profile_id": "apple:a8-a11:gaster-reference",
        "product_type": target["product_type"],
        "board_config": target["board_config"],
        "cpid": target["cpid"],
        "firmware_build": target["firmware_build"],
        "environment": target["final_environment"],
        "pwn_provider": "gaster",
        "source_references": sources,
        "assets": runtime_assets,
        "boot_steps": [runtime_step(step) for step in steps],
        "maturity": "contract_valid",
        "hardware_transcript_sha256": None,
        "recovery_proof_sha256": None,
    }

    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    catalogue_path = output / "provider-pack.catalogue.json"
    runtime_path = output / "provider-pack.runtime.json"
    catalogue_path.write_text(json.dumps(catalogue, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    runtime_path.write_text(json.dumps(runtime, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    generation = {
        "schema_version": "tgcheckm8.provider-generation-receipt.v1",
        "target_sha256": sha256_file(args.target),
        "build_receipt_sha256": sha256_file(args.build_receipt),
        "inventory_sha256": sha256_file(args.inventory),
        "catalogue_manifest_sha256": sha256_file(catalogue_path),
        "runtime_manifest_sha256": sha256_file(runtime_path),
        "execution_authorized": False,
    }
    (output / "provider-generation-receipt.json").write_text(
        json.dumps(generation, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
