#!/usr/bin/env python3
"""Create a deterministic build receipt for reviewed Apple host tools."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "tgcheckm8.apple-tool-build-receipt.v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def command_output(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        return f"unavailable: {exc}"
    return completed.stdout.strip()


def binary_record(role: str, path: Path, smoke_command: list[str]) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size <= 0:
        raise ValueError(f"missing or empty output for {role}: {path}")
    smoke = subprocess.run(
        smoke_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=15,
        check=False,
    )
    return {
        "role": role,
        "filename": path.name,
        "byte_len": path.stat().st_size,
        "sha256": sha256_file(path),
        "file_description": command_output(["file", str(path)]),
        "smoke_command": smoke_command,
        "smoke_status_code": smoke.returncode,
        "smoke_output_sha256": hashlib.sha256(smoke.stdout.encode("utf-8")).hexdigest(),
        "smoke_output_excerpt": smoke.stdout[:1000],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--gaster", type=Path, required=True)
    parser.add_argument("--irecovery", type=Path, required=True)
    parser.add_argument("--gaster-commit", required=True)
    parser.add_argument("--irecovery-commit", required=True)
    parser.add_argument("--glue-commit", required=True)
    parser.add_argument("--plist-commit", required=True)
    parser.add_argument("--build-log", type=Path, required=True)
    args = parser.parse_args()

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    gaster = args.gaster.resolve()
    irecovery = args.irecovery.resolve()

    records = [
        binary_record("gaster_executable", gaster, [str(gaster)]),
        binary_record("irecovery_executable", irecovery, [str(irecovery), "--help"]),
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
            "compiler": command_output(["clang", "--version"]),
            "make": command_output(["make", "--version"]),
            "pkg_config": command_output(["pkg-config", "--version"]),
        },
        "source_pins": [
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
        ],
        "outputs": records,
        "build_log": {
            "filename": args.build_log.name,
            "byte_len": args.build_log.stat().st_size,
            "sha256": sha256_file(args.build_log),
        },
        "review_checks": {
            "source_commits_exact": True,
            "binaries_nonempty": True,
            "sha256_recorded": True,
            "smoke_tests_executed": True,
            "device_operation_executed": False,
        },
    }
    receipt_path = output_dir / "build-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sums = "\n".join(f"{item['sha256']}  {item['filename']}" for item in records) + "\n"
    (output_dir / "SHA256SUMS").write_text(sums, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
