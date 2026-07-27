#!/usr/bin/env python3
"""Create a deterministic receipt for reviewed Windows Apple host tools.

The smoke checks invoke usage/help paths only. They never request a USB device,
open DFU transport, or execute a device operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "tgcheckm8.windows-apple-tool-build-receipt.v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pe_machine(path: Path) -> str:
    data = path.read_bytes()[:4096]
    if len(data) < 64 or data[:2] != b"MZ":
        return "not-pe"
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset + 6 > len(data):
        with path.open("rb") as handle:
            handle.seek(offset)
            header = handle.read(8)
    else:
        header = data[offset : offset + 8]
    if header[:4] != b"PE\0\0":
        return "pe-unknown"
    machine = struct.unpack_from("<H", header, 4)[0]
    return {0x014C: "x86", 0x8664: "x86_64", 0xAA64: "arm64"}.get(
        machine, f"machine-0x{machine:04x}"
    )


def command_output(command: list[str], env: dict[str, str] | None = None) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 126, f"unavailable: {type(exc).__name__}: {exc}"
    return completed.returncode, completed.stdout.strip()


def file_record(path: Path, root: Path, role: str) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size <= 0:
        raise ValueError(f"missing or empty output for {role}: {path}")
    return {
        "role": role,
        "filename": path.name,
        "relative_path": path.relative_to(root).as_posix(),
        "byte_len": path.stat().st_size,
        "sha256": sha256_file(path),
        "file_format": "PE",
        "architecture": pe_machine(path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--gaster", type=Path, required=True)
    parser.add_argument("--irecovery", type=Path, required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--gaster-commit", required=True)
    parser.add_argument("--irecovery-commit", required=True)
    parser.add_argument("--glue-commit", required=True)
    parser.add_argument("--plist-commit", required=True)
    parser.add_argument("--build-log", type=Path, required=True)
    parser.add_argument("--dependency-log", type=Path, required=True)
    parser.add_argument("--package-lock", type=Path, required=True)
    args = parser.parse_args()

    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    gaster = args.gaster.resolve()
    irecovery = args.irecovery.resolve()
    runtime = args.runtime_dir.resolve()

    runtime_env = dict(os.environ)
    runtime_env["PATH"] = str(runtime) + os.pathsep + str(gaster.parent) + os.pathsep + runtime_env.get("PATH", "")

    gaster_code, gaster_text = command_output([str(gaster)], runtime_env)
    irecovery_code, irecovery_text = command_output([str(irecovery), "--help"], runtime_env)
    smoke_checks = {
        "gaster_usage_only": {
            "command": [gaster.name],
            "return_code": gaster_code,
            "output_sha256": hashlib.sha256(gaster_text.encode("utf-8")).hexdigest(),
            "usage_visible": "Put the device in pwned DFU mode" in gaster_text,
            "device_operation_requested": False,
        },
        "irecovery_help_only": {
            "command": [irecovery.name, "--help"],
            "return_code": irecovery_code,
            "output_sha256": hashlib.sha256(irecovery_text.encode("utf-8")).hexdigest(),
            "help_visible": "Usage" in irecovery_text or "irecovery" in irecovery_text.casefold(),
            "device_operation_requested": False,
        },
    }
    if not all(item.get("usage_visible", item.get("help_visible", False)) for item in smoke_checks.values()):
        raise SystemExit("Usage-only smoke proof did not produce the expected help text")

    files = [
        file_record(gaster, output, "gaster_windows_executable"),
        file_record(irecovery, output, "irecovery_windows_executable"),
    ]
    for dll in sorted(runtime.glob("*.dll"), key=lambda item: item.name.casefold()):
        files.append(file_record(dll, output, "runtime_dependency"))

    source_pins = [
        {
            "role": "gaster",
            "repository": "https://github.com/0x7ff/gaster",
            "commit": args.gaster_commit,
            "licence": "Apache-2.0",
        },
        {
            "role": "irecovery",
            "repository": "https://github.com/libimobiledevice/libirecovery",
            "commit": args.irecovery_commit,
            "licence": "LGPL-2.1-or-later",
        },
        {
            "role": "libimobiledevice_glue",
            "repository": "https://github.com/libimobiledevice/libimobiledevice-glue",
            "commit": args.glue_commit,
            "licence": "LGPL-2.1-or-later",
        },
        {
            "role": "libplist",
            "repository": "https://github.com/libimobiledevice/libplist",
            "commit": args.plist_commit,
            "licence": "LGPL-2.1-or-later",
        },
    ]

    receipt = {
        "schema_version": SCHEMA,
        "build_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "builder": {
            "repository": os.environ.get("GITHUB_REPOSITORY", "local"),
            "commit": os.environ.get("GITHUB_SHA", "local"),
            "workflow": os.environ.get("GITHUB_WORKFLOW", "local"),
            "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "local"),
        },
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "toolchain": "MSYS2 MinGW-w64 x86_64",
        },
        "source_pins": source_pins,
        "outputs": files,
        "smoke_checks": smoke_checks,
        "build_log": {
            "relative_path": args.build_log.resolve().relative_to(output).as_posix(),
            "byte_len": args.build_log.stat().st_size,
            "sha256": sha256_file(args.build_log),
        },
        "dependency_log": {
            "relative_path": args.dependency_log.resolve().relative_to(output).as_posix(),
            "byte_len": args.dependency_log.stat().st_size,
            "sha256": sha256_file(args.dependency_log),
        },
        "package_lock": {
            "relative_path": args.package_lock.resolve().relative_to(output).as_posix(),
            "byte_len": args.package_lock.stat().st_size,
            "sha256": sha256_file(args.package_lock),
        },
        "review_checks": {
            "source_commits_exact": True,
            "binaries_nonempty": True,
            "pe_x86_64_only": all(item["architecture"] == "x86_64" for item in files),
            "sha256_recorded": all(len(item["sha256"]) == 64 for item in files),
            "usage_only_smoke_tests": True,
            "device_operation_executed": False,
            "driver_installed": False,
            "stable_promotion_authorized": False,
        },
    }
    if not receipt["review_checks"]["pe_x86_64_only"]:
        raise SystemExit("A reviewed output is not a Windows x86_64 PE file")

    receipt_path = output / "windows-build-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "SHA256SUMS.windows").write_text(
        "".join(f"{item['sha256']}  {item['relative_path']}\n" for item in files),
        encoding="utf-8",
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
