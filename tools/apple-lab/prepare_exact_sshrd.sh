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
IPSW_URL="$(read_json ipsw.url)"
IPSW_SHA256="$(read_json ipsw.sha256)"
SSHRD_COMMIT="$(read_json source_pins.sshrd)"
CATALOG_COMMIT="$(read_json source_pins.ramdisk_catalog)"

RECEIPT="$TOOLS/build-receipt.json"
GASTER="$TOOLS/bin/gaster"
IRECOVERY="$TOOLS/bin/irecovery"
for file in "$RECEIPT" "$GASTER" "$IRECOVERY"; do
  [[ -f "$file" ]] || { echo "Missing reviewed tool input: $file" >&2; exit 3; }
done

python3 - "$RECEIPT" "$GASTER" "$IRECOVERY" <<'PY'
import hashlib, json, pathlib, sys
receipt=json.load(open(sys.argv[1], encoding='utf-8'))
for role, path in [('gaster_executable', pathlib.Path(sys.argv[2])), ('irecovery_executable', pathlib.Path(sys.argv[3]))]:
    record=next((x for x in receipt['outputs'] if x['role']==role), None)
    if not record:
        raise SystemExit(f'missing {role} in receipt')
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != record['sha256']:
        raise SystemExit(f'{role} hash mismatch')
print('Reviewed tool hashes verified.')
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

python3 - "$WORK/SSHRD_Script/sshrd.sh" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1])
text=path.read_text(encoding='utf-8')
needle='ipswurl=$(curl -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "$oscheck"/jq \'.firmwares | .[] | select(.version=="\'$1\'")\' | "$oscheck"/jq -s \'.[0] | .url\' --raw-output)'
replacement='ipswurl="${TTG_IPSW_URL:?TTG_IPSW_URL is required}"'
if text.count(needle) != 1:
    raise SystemExit('Could not locate the exact SSHRD IPSW selection line')
text=text.replace(needle, replacement)
out=path.with_name('ttg-build-exact.sh')
out.write_text(text, encoding='utf-8')
out.chmod(0o755)
PY

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
export USB_TIMEOUT="${USB_TIMEOUT:-5}"
(
  cd "$WORK/SSHRD_Script"
  ./ttg-build-exact.sh "$IOS_VERSION"
) 2>&1 | tee "$EVIDENCE/sshrd-build.log"

for required in iBSS.img4 iBEC.img4 logo.img4 ramdisk.img4 devicetree.img4 trustcache.img4 kernelcache.img4 version.txt; do
  [[ -s "$WORK/SSHRD_Script/sshramdisk/$required" ]] || {
    echo "Generated package is missing $required" >&2
    exit 4
  }
done

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

rm -f "$OUTPUT/${TARGET_ID}.zip"
(
  cd "$PACKAGE"
  /usr/bin/zip -X -r "$OUTPUT/${TARGET_ID}.zip" assets target.json tool-build-receipt.json
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

python3 - "$TARGET" "$OUTPUT" "$EVIDENCE" "$IPSW_SHA256" <<'PY'
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
receipt={
  'schema_version':'tgcheckm8.sshrd-build-receipt.v1',
  'target_id':target['target_id'],
  'product_type':target['product_type'],
  'board_config':target['board_config'],
  'cpid':target['cpid'],
  'ios_version':target['ios_version'],
  'firmware_build':target['firmware_build'],
  'ipsw_url':target['ipsw']['url'],
  'ipsw_expected_sha256':sys.argv[4],
  'package_zip_sha256':h(out/(target['target_id']+'.zip')),
  'package_inventory_sha256':h(out/'package-inventory.json'),
  'device_proof_sha256':h(evidence/'device-before.json'),
  'sshrd_build_log_sha256':h(evidence/'sshrd-build.log'),
  'authorization_ticket_sha256':hashlib.sha256(os.environ['TTG_AUTHORIZATION_TICKET'].encode()).hexdigest(),
  'asset_generation_complete':True,
  'device_boot_executed':False,
  'execution_authorized':False,
}
(out/'sshrd-build-receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True)+'\n')
PY

printf 'Exact SSHRD package prepared for %s / %s / %s.\n' "$PRODUCT" "$BOARD" "$FIRMWARE_BUILD"
printf 'Package: %s\n' "$OUTPUT/${TARGET_ID}.zip"
printf 'Runtime manifest: %s\n' "$OUTPUT/provider/provider-pack.runtime.json"
printf 'No boot was executed by this preparation step.\n'
