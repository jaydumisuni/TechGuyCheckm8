#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This exact SSHRD preparation lane requires macOS." >&2
  exit 2
fi
if [[ "${TTG_AUTHORIZED_DEVICE:-}" != "YES" || -z "${TTG_AUTHORIZATION_TICKET:-}" ]]; then
  echo "Set TTG_AUTHORIZED_DEVICE=YES and TTG_AUTHORIZATION_TICKET for the authorised lab device." >&2
  exit 2
fi
if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <target.json> <reviewed-tools-dir> <output-dir>" >&2
  exit 2
fi

TARGET="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
TOOLS="$(cd "$2" && pwd)"
OUTPUT="$(mkdir -p "$3" && cd "$3" && pwd)"
SCRIPT_ROOT="$(cd "$(dirname "$0")" && pwd)"
WORK="$OUTPUT/work"
EVIDENCE="$OUTPUT/evidence"
PACKAGE="$OUTPUT/package"
mkdir -p "$WORK" "$EVIDENCE" "$PACKAGE"

read_json() {
  python3 - "$TARGET" "$1" <<'PY'
import json, sys
value=json.load(open(sys.argv[1], encoding='utf-8'))
for part in sys.argv[2].split('.'):
    value=value[part]
print(value)
PY
}

TARGET_ID="$(read_json target_id)"
PRODUCT="$(read_json product_type)"
BOARD="$(read_json board_config)"
CPID="$(read_json cpid)"
IOS_VERSION="$(read_json ios_version)"
FIRMWARE_BUILD="$(read_json firmware_build)"
IPSW_FILENAME="$(read_json ipsw.filename)"
IPSW_URL="$(read_json ipsw.url)"
IPSW_SHA256="$(read_json ipsw.sha256)"
GASTER_COMMIT="$(read_json source_pins.gaster)"
IRECOVERY_COMMIT="$(read_json source_pins.irecovery)"
SSHRD_COMMIT="$(read_json source_pins.sshrd)"
CATALOG_COMMIT="$(read_json source_pins.ramdisk_catalog)"

RECEIPT="$TOOLS/build-receipt.json"
GASTER="$TOOLS/bin/gaster"
IRECOVERY="$TOOLS/bin/irecovery"
for file in "$RECEIPT" "$GASTER" "$IRECOVERY"; do
  [[ -f "$file" ]] || { echo "Missing reviewed tool input: $file" >&2; exit 3; }
done

python3 - "$TARGET" "$RECEIPT" "$GASTER" "$IRECOVERY" <<'PY'
import hashlib, json, pathlib, sys

target=json.load(open(sys.argv[1], encoding='utf-8'))
receipt=json.load(open(sys.argv[2], encoding='utf-8'))
source_pins={item['role']: item['commit'] for item in receipt.get('source_pins', [])}
expected={
    'gaster': target['source_pins']['gaster'],
    'irecovery': target['source_pins']['irecovery'],
}
for role, commit in expected.items():
    if source_pins.get(role) != commit:
        raise SystemExit(f'reviewed receipt source pin mismatch for {role}')
for role, path in [
    ('gaster_executable', pathlib.Path(sys.argv[3])),
    ('irecovery_executable', pathlib.Path(sys.argv[4])),
]:
    record=next((x for x in receipt['outputs'] if x['role']==role), None)
    if not record:
        raise SystemExit(f'missing {role} in receipt')
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != record['sha256']:
        raise SystemExit(f'{role} hash mismatch')
print('Reviewed source pins and tool hashes verified.')
PY

IPSW_FILE="$WORK/$IPSW_FILENAME"
echo "Downloading and hashing exact IPSW before device work: $IPSW_FILENAME"
curl --fail --location --retry 3 --retry-all-errors --continue-at - --output "$IPSW_FILE" "$IPSW_URL"
python3 - "$IPSW_FILE" "$IPSW_SHA256" "$IPSW_URL" "$EVIDENCE/ipsw-proof.json" <<'PY'
import hashlib, json, pathlib, sys
path=pathlib.Path(sys.argv[1])
digest=hashlib.sha256()
with path.open('rb') as handle:
    for block in iter(lambda: handle.read(1024*1024), b''):
        digest.update(block)
actual=digest.hexdigest()
expected=sys.argv[2].lower()
if actual != expected:
    raise SystemExit(f'IPSW SHA-256 mismatch: expected {expected}, observed {actual}')
proof={
    'schema_version':'tgcheckm8.ipsw-proof.v1',
    'filename':path.name,
    'url':sys.argv[3],
    'byte_len':path.stat().st_size,
    'expected_sha256':expected,
    'observed_sha256':actual,
    'verified':True,
}
pathlib.Path(sys.argv[4]).write_text(json.dumps(proof, indent=2, sort_keys=True)+'\n', encoding='utf-8')
print(f'Exact IPSW SHA-256 verified: {actual}')
PY

chmod 0755 "$GASTER" "$IRECOVERY"
"$IRECOVERY" -q > "$WORK/device-before.raw.txt"
python3 "$SCRIPT_ROOT/verify_device.py" \
  --target "$TARGET" \
  --query "$WORK/device-before.raw.txt" \
  --output "$EVIDENCE/device-before.json"
rm -f "$WORK/device-before.raw.txt"

rm -rf "$WORK/SSHRD_Script" "$WORK/ttgtool-ramdisks"
git clone --recursive https://github.com/verygenericname/SSHRD_Script.git "$WORK/SSHRD_Script"
git -C "$WORK/SSHRD_Script" checkout --detach "$SSHRD_COMMIT"
git -C "$WORK/SSHRD_Script" submodule update --init --recursive
test "$(git -C "$WORK/SSHRD_Script" rev-parse HEAD)" = "$SSHRD_COMMIT"

cp "$GASTER" "$WORK/SSHRD_Script/Darwin/gaster"
cp "$IRECOVERY" "$WORK/SSHRD_Script/Darwin/irecovery"
chmod 0755 "$WORK/SSHRD_Script/Darwin/gaster" "$WORK/SSHRD_Script/Darwin/irecovery"
python3 "$SCRIPT_ROOT/patch_sshrd.py" \
  "$WORK/SSHRD_Script/sshrd.sh" \
  "$WORK/SSHRD_Script/ttg-build-exact.sh"

python3 - "$WORK/SSHRD_Script/Darwin" "$EVIDENCE/sshrd-darwin-tool-inventory.json" <<'PY'
import hashlib, json, pathlib, sys
root=pathlib.Path(sys.argv[1])
records=[]
for path in sorted(root.iterdir()):
    if path.is_file():
        records.append({'filename': path.name, 'byte_len': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
pathlib.Path(sys.argv[2]).write_text(json.dumps({'schema_version':'tgcheckm8.sshrd-tool-inventory.v1','files':records}, indent=2, sort_keys=True)+'\n')
PY

export TTG_IPSW_URL="$IPSW_URL"
export TTG_BUILD_MANIFEST_OUT="$EVIDENCE/BuildManifest.plist"
export USB_TIMEOUT="${USB_TIMEOUT:-5}"
(
  cd "$WORK/SSHRD_Script"
  ./ttg-build-exact.sh "$IOS_VERSION"
) 2>&1 | tee "$EVIDENCE/sshrd-build.log"
rm -f "$IPSW_FILE"

[[ -s "$EVIDENCE/BuildManifest.plist" ]] || {
  echo "Pinned SSHRD build did not preserve BuildManifest evidence" >&2
  exit 4
}
python3 - "$TARGET" "$EVIDENCE/BuildManifest.plist" <<'PY'
import json, plistlib, sys

target=json.load(open(sys.argv[1], encoding='utf-8'))
with open(sys.argv[2], 'rb') as handle:
    manifest=plistlib.load(handle)
if manifest.get('ProductBuildVersion') != target['firmware_build']:
    raise SystemExit(f"BuildManifest build mismatch: {manifest.get('ProductBuildVersion')}")
strings=[]
def visit(value):
    if isinstance(value, dict):
        for item in value.values(): visit(item)
    elif isinstance(value, list):
        for item in value: visit(item)
    elif isinstance(value, str):
        strings.append(value)
visit(manifest)
if target['product_type'] not in strings:
    raise SystemExit('BuildManifest does not contain the target product type')
if target['board_config'].lower() not in {value.lower() for value in strings}:
    raise SystemExit('BuildManifest does not contain the target board configuration')
print('Exact ProductBuildVersion, product type and board verified in BuildManifest.')
PY

for required in iBSS.img4 iBEC.img4 logo.img4 ramdisk.img4 devicetree.img4 trustcache.img4 kernelcache.img4 version.txt; do
  [[ -s "$WORK/SSHRD_Script/sshramdisk/$required" ]] || {
    echo "Generated package is missing $required" >&2
    exit 4
  }
done
[[ "$(cat "$WORK/SSHRD_Script/sshramdisk/version.txt")" = "$IOS_VERSION" ]] || {
  echo "Generated ramdisk version marker does not match the target" >&2
  exit 4
}

rm -rf "$PACKAGE/assets"
mkdir -p "$PACKAGE/assets"
cp "$WORK/SSHRD_Script/sshramdisk/iBSS.img4" "$PACKAGE/assets/iBSS.img4"
cp "$WORK/SSHRD_Script/sshramdisk/iBEC.img4" "$PACKAGE/assets/iBEC.img4"
cp "$WORK/SSHRD_Script/sshramdisk/logo.img4" "$PACKAGE/assets/logo.img4"
cp "$WORK/SSHRD_Script/sshramdisk/ramdisk.img4" "$PACKAGE/assets/ramdisk.img4"
cp "$WORK/SSHRD_Script/sshramdisk/devicetree.img4" "$PACKAGE/assets/devicetree.img4"
cp "$WORK/SSHRD_Script/sshramdisk/trustcache.img4" "$PACKAGE/assets/trustcache.img4"
cp "$WORK/SSHRD_Script/sshramdisk/kernelcache.img4" "$PACKAGE/assets/kernelcache.img4"
cp "$TARGET" "$PACKAGE/target.json"
cp "$RECEIPT" "$PACKAGE/tool-build-receipt.json"
cp "$EVIDENCE/BuildManifest.plist" "$PACKAGE/BuildManifest.plist"
cp "$EVIDENCE/ipsw-proof.json" "$PACKAGE/ipsw-proof.json"

rm -f "$OUTPUT/${TARGET_ID}.zip"
(
  cd "$PACKAGE"
  /usr/bin/zip -X -r "$OUTPUT/${TARGET_ID}.zip" assets target.json tool-build-receipt.json BuildManifest.plist ipsw-proof.json
)

git clone https://github.com/jaydumisuni/ttgtool-ramdisks.git "$WORK/ttgtool-ramdisks"
git -C "$WORK/ttgtool-ramdisks" checkout --detach "$CATALOG_COMMIT"
test "$(git -C "$WORK/ttgtool-ramdisks" rev-parse HEAD)" = "$CATALOG_COMMIT"
python3 "$WORK/ttgtool-ramdisks/scripts/inventory_package.py" \
  "$OUTPUT/${TARGET_ID}.zip" \
  --output "$OUTPUT/package-inventory.json"

python3 "$SCRIPT_ROOT/make_provider_manifest.py" \
  --target "$TARGET" \
  --build-receipt "$RECEIPT" \
  --inventory "$OUTPUT/package-inventory.json" \
  --output-dir "$OUTPUT/provider"

python3 - "$TARGET" "$OUTPUT" "$EVIDENCE" <<'PY'
import hashlib, json, os, pathlib, sys

def h(path):
    d=hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(1024*1024), b''):
            d.update(block)
    return d.hexdigest()

target=json.load(open(sys.argv[1], encoding='utf-8'))
out=pathlib.Path(sys.argv[2])
evidence=pathlib.Path(sys.argv[3])
ipsw_proof=json.load(open(evidence/'ipsw-proof.json', encoding='utf-8'))
receipt={
  'schema_version':'tgcheckm8.sshrd-build-receipt.v1',
  'target_id':target['target_id'],
  'product_type':target['product_type'],
  'board_config':target['board_config'],
  'cpid':target['cpid'],
  'ios_version':target['ios_version'],
  'firmware_build':target['firmware_build'],
  'ipsw_url':target['ipsw']['url'],
  'ipsw_expected_sha256':ipsw_proof['expected_sha256'],
  'ipsw_observed_sha256':ipsw_proof['observed_sha256'],
  'ipsw_byte_len':ipsw_proof['byte_len'],
  'ipsw_proof_sha256':h(evidence/'ipsw-proof.json'),
  'build_manifest_sha256':h(evidence/'BuildManifest.plist'),
  'package_zip_sha256':h(out/(target['target_id']+'.zip')),
  'package_inventory_sha256':h(out/'package-inventory.json'),
  'device_proof_sha256':h(evidence/'device-before.json'),
  'sshrd_build_log_sha256':h(evidence/'sshrd-build.log'),
  'authorization_ticket_sha256':hashlib.sha256(os.environ['TTG_AUTHORIZATION_TICKET'].encode()).hexdigest(),
  'asset_generation_complete':True,
  'pwned_dfu_used_for_build':True,
  'device_boot_executed':False,
  'execution_authorized':False,
}
(out/'sshrd-build-receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True)+'\n')
PY

printf 'Exact SSHRD package prepared for %s / %s / %s.\n' "$PRODUCT" "$BOARD" "$FIRMWARE_BUILD"
printf 'Package: %s\n' "$OUTPUT/${TARGET_ID}.zip"
printf 'Runtime manifest: %s\n' "$OUTPUT/provider/provider-pack.runtime.json"
printf 'The full IPSW hash and BuildManifest were verified; authorised pwned DFU was used for key handling; no ramdisk boot was executed.\n'
