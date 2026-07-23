from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LAB = ROOT / "tools" / "apple-lab"
TARGET = LAB / "targets" / "iphone10,6-d221ap-16.7.10-20h350.json"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PATCH = load_module("patch_sshrd", LAB / "patch_sshrd.py")


class AppleLabPipelineTests(unittest.TestCase):
    def test_pinned_sshrd_patch_is_exact_and_preserves_manifest(self) -> None:
        selector = f"{PATCH.IPSW_PREFIX} | pinned-test-jq)"
        source = f"header\n{selector}\n{PATCH.CLEANUP}\nfooter\n"
        patched = PATCH.patch(source)
        self.assertIn(PATCH.EXACT_IPSW_SELECTION, patched)
        self.assertIn("TTG_BUILD_MANIFEST_OUT", patched)
        self.assertNotIn("api.ipsw.me/v4/device/$deviceid", patched)
        with self.assertRaises(ValueError):
            PATCH.patch("different upstream script")

    def test_device_proof_is_redacted_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            query = root / "query.txt"
            output = root / "proof.json"
            raw_ecid = "0x123456789ABCDEF"
            query.write_text(
                "\n".join(
                    [
                        "CPID: 0x8015",
                        f"ECID: {raw_ecid}",
                        "PRODUCT: iPhone10,6",
                        "MODEL: d221ap",
                        "MODE: DFU",
                        "PWND: checkm8",
                    ]
                ),
                encoding="utf-8",
            )
            subprocess.run(
                [
                    sys.executable,
                    str(LAB / "verify_device.py"),
                    "--target",
                    str(TARGET),
                    "--query",
                    str(query),
                    "--output",
                    str(output),
                    "--require-pwnd",
                ],
                check=True,
            )
            proof = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(proof["evidence_complete"])
            self.assertEqual(proof["cpid"], "8015")
            self.assertNotIn(raw_ecid, output.read_text(encoding="utf-8"))
            self.assertEqual(len(proof["device_identity_sha256"]), 64)

    def test_generator_emits_catalogue_and_rust_runtime_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "receipt.json"
            inventory = root / "inventory.json"
            output = root / "out"
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
            asset_roles = [
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
                            for index, role in enumerate(asset_roles)
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
                    str(output),
                ],
                check=True,
            )
            catalogue = json.loads(
                (output / "provider-pack.catalogue.json").read_text(encoding="utf-8")
            )
            runtime = json.loads(
                (output / "provider-pack.runtime.json").read_text(encoding="utf-8")
            )
            self.assertIn("ibss", {item["role"] for item in catalogue["assets"]})
            self.assertIn("i_bss", runtime["assets"])
            self.assertIn("i_bec", runtime["assets"])
            self.assertIn("i_recovery_executable", runtime["assets"])
            self.assertIn("device_tree", runtime["assets"])
            self.assertIn("trust_cache", runtime["assets"])
            self.assertIn("kernel_cache", runtime["assets"])
            self.assertIn(
                {"recovery_command": "set_picture_one"}, runtime["boot_steps"]
            )
            self.assertIn({"recovery_command": "boot_x"}, runtime["boot_steps"])
            self.assertFalse(catalogue["execution_enabled"])


if __name__ == "__main__":
    unittest.main()
