#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "The reviewed A8-A11 hardware lane currently requires macOS." >&2
  exit 2
fi
if [[ "${TTG_AUTHORIZED_DEVICE:-}" != "YES" || -z "${TTG_AUTHORIZATION_TICKET:-}" ]]; then
  echo "Set TTG_AUTHORIZED_DEVICE=YES and TTG_AUTHORIZATION_TICKET." >&2
  exit 2
fi
if [[ $# -ne 4 ]]; then
  echo "Usage: $0 <target.json> <reviewed-tools-dir> <prepared-output-dir> <evidence-output-dir>" >&2
  exit 2
fi

TARGET="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
TOOLS="$(cd "$2" && pwd)"
PREP="$(cd "$3" && pwd)"
OUT="$(mkdir -p "$4" && cd "$4" && pwd)"
SCRIPT_ROOT="$(cd "$(dirname "$0")" && pwd)"
ASSETS="$PREP/package/assets"
MANIFEST="$PREP/provider/provider-pack.runtime.json"
RECEIPT="$TOOLS/build-receipt.json"
GASTER="$TOOLS/bin/gaster"
IRECOVERY="$TOOLS/bin/irecovery"
IPROXY="$PREP/work/SSHRD_Script/Darwin/iproxy"
SSHPASS="$PREP/work/SSHRD_Script/Darwin/sshpass"

for file in "$TARGET" "$MANIFEST" "$RECEIPT" "$GASTER" "$IRECOVERY" "$IPROXY" "$SSHPASS"; do
  [[ -f "$file" ]] || { echo "Missing execution input: $file" >&2; exit 3; }
done
chmod 0755 "$GASTER" "$IRECOVERY" "$IPROXY" "$SSHPASS"

python3 - "$TARGET" "$MANIFEST" "$RECEIPT" "$GASTER" "$IRECOVERY" "$ASSETS" <<'PY'
import hashlib, json, pathlib, sys

def digest(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1024*1024), b''):
            h.update(b)
    return h.hexdigest()

target=json.load(open(sys.argv[1], encoding='utf-8'))
manifest=json.load(open(sys.argv[2], encoding='utf-8'))
receipt=json.load(open(sys.argv[3], encoding='utf-8'))
if manifest['product_type'] != target['product_type'] or manifest['board_config'].lower() != target['board_config'].lower() or manifest['cpid'].upper() != target['cpid'].upper() or manifest['firmware_build'] != target['firmware_build']:
    raise SystemExit('runtime manifest does not match target')
for role, path in [('gaster_executable', pathlib.Path(sys.argv[4])), ('irecovery_executable', pathlib.Path(sys.argv[5]))]:
    record=next(x for x in receipt['outputs'] if x['role']==role)
    if digest(path) != record['sha256']:
        raise SystemExit(f'{role} hash mismatch')
asset_root=pathlib.Path(sys.argv[6]).resolve()
for role, record in manifest['assets'].items():
    if role in {'gaster_executable','i_recovery_executable'}:
        continue
    path=(asset_root.parent / record['relative_path']).resolve()
    if not path.is_file() or asset_root not in path.parents:
        raise SystemExit(f'unsafe or missing asset for {role}: {path}')
    if digest(path) != record['sha256'] or path.stat().st_size != record['byte_len']:
        raise SystemExit(f'asset proof mismatch for {role}')
print('Runtime target, tools and assets verified.')
PY

SESSION_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
SESSION="$OUT/session-$SESSION_ID"
mkdir -p "$SESSION"
LOG="$SESSION/hardware-transcript.log"
exec > >(tee -a "$LOG") 2>&1

cleanup() {
  if [[ -n "${IPROXY_PID:-}" ]]; then
    kill "$IPROXY_PID" 2>/dev/null || true
    wait "$IPROXY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

query_and_verify() {
  local name="$1"
  shift
  "$IRECOVERY" -q > "$SESSION/$name.raw.txt"
  python3 "$SCRIPT_ROOT/verify_device.py" \
    --target "$TARGET" \
    --query "$SESSION/$name.raw.txt" \
    --output "$SESSION/$name.json" "$@"
  rm -f "$SESSION/$name.raw.txt"
}

same_identity() {
  python3 - "$SESSION/$1.json" "$SESSION/$2.json" <<'PY'
import json,sys
a=json.load(open(sys.argv[1])); b=json.load(open(sys.argv[2]))
if a['device_identity_sha256'] != b['device_identity_sha256']:
    raise SystemExit('device identity changed across reconnect')
PY
}

send_asset() {
  local filename="$1"
  "$IRECOVERY" -f "$ASSETS/$filename"
}

query_and_verify device-dfu-before
printf 'Starting fixed Gaster pwn/reset for session %s\n' "$SESSION_ID"
"$GASTER" pwn
"$GASTER" reset
query_and_verify device-pwnd --require-pwnd
same_identity device-dfu-before device-pwnd

send_asset iBSS.img4
sleep 2
send_asset iBEC.img4
"$IRECOVERY" -c go
sleep 2
query_and_verify device-patched-iboot
same_identity device-dfu-before device-patched-iboot

send_asset logo.img4
"$IRECOVERY" -c "setpicture 0x1"
send_asset ramdisk.img4
"$IRECOVERY" -c ramdisk
send_asset devicetree.img4
"$IRECOVERY" -c devicetree
send_asset trustcache.img4
"$IRECOVERY" -c firmware
send_asset kernelcache.img4
"$IRECOVERY" -c bootx

"$IPROXY" 2222 22 > "$SESSION/iproxy.log" 2>&1 &
IPROXY_PID=$!
SSH_READY=0
for _ in $(seq 1 60); do
  if nc -z 127.0.0.1 2222 >/dev/null 2>&1; then
    SSH_READY=1
    break
  fi
  sleep 1
done
[[ "$SSH_READY" -eq 1 ]] || { echo "Ramdisk SSH port did not become ready" >&2; exit 5; }

"$SSHPASS" -p alpine ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=10 \
  -p 2222 root@127.0.0.1 \
  'printf "TTG_SSHRD_READY\n"; sw_vers 2>/dev/null || true; uname -a' \
  > "$SESSION/ramdisk-ssh-proof.txt"
grep -q '^TTG_SSHRD_READY$' "$SESSION/ramdisk-ssh-proof.txt"

RECOVERY_VERIFIED=false
if [[ "${TTG_LEAVE_RAMDISK:-NO}" != "YES" ]]; then
  "$SSHPASS" -p alpine ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 \
    -p 2222 root@127.0.0.1 '/sbin/reboot' || true
  kill "$IPROXY_PID" 2>/dev/null || true
  wait "$IPROXY_PID" 2>/dev/null || true
  unset IPROXY_PID

  NORMAL_USB=0
  for _ in $(seq 1 60); do
    system_profiler SPUSBDataType SPUSBHostDataType > "$SESSION/post-reboot-usb.raw.txt" 2>&1 || true
    if python3 - "$SESSION/post-reboot-usb.raw.txt" <<'PY'
import sys
text=open(sys.argv[1], encoding='utf-8', errors='replace').read().lower()
has_mobile='iphone' in text or 'apple mobile device' in text
unexpected='dfu mode' in text or 'recovery mode' in text
raise SystemExit(0 if has_mobile and not unexpected else 1)
PY
    then
      NORMAL_USB=1
      break
    fi
    sleep 1
  done
  [[ "$NORMAL_USB" -eq 1 ]] || { echo "Normal-mode USB recovery proof was not observed" >&2; exit 6; }

  set +e
  "$IRECOVERY" -q > "$SESSION/post-reboot-irecovery.txt" 2>&1
  IRECOVERY_NORMAL_STATUS=$?
  set -e
  [[ "$IRECOVERY_NORMAL_STATUS" -ne 0 ]] || {
    echo "Device still responds to iRecovery after requested normal reboot" >&2
    exit 6
  }

  python3 - "$SESSION/post-reboot-usb.raw.txt" "$SESSION/post-reboot-irecovery.txt" "$SESSION/recovery-proof.json" <<'PY'
import hashlib, json, pathlib, sys
usb=pathlib.Path(sys.argv[1]).read_bytes()
irecovery=pathlib.Path(sys.argv[2]).read_bytes()
proof={
  'schema_version':'tgcheckm8.apple-recovery-proof.v1',
  'normal_mode_usb_observed':True,
  'dfu_or_recovery_marker_absent':True,
  'irecovery_no_longer_attached':True,
  'usb_snapshot_sha256':hashlib.sha256(usb).hexdigest(),
  'irecovery_exit_snapshot_sha256':hashlib.sha256(irecovery).hexdigest(),
  'verified':True,
}
pathlib.Path(sys.argv[3]).write_text(json.dumps(proof, indent=2, sort_keys=True)+'\n')
PY
  rm -f "$SESSION/post-reboot-usb.raw.txt" "$SESSION/post-reboot-irecovery.txt"
  RECOVERY_VERIFIED=true
fi
export RECOVERY_VERIFIED

python3 - "$TARGET" "$MANIFEST" "$RECEIPT" "$SESSION" "$LOG" <<'PY'
import hashlib, json, os, pathlib, sys

def h(path):
    d=hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(1024*1024), b''):
            d.update(block)
    return d.hexdigest()

target=json.load(open(sys.argv[1], encoding='utf-8'))
session=pathlib.Path(sys.argv[4])
initial=json.load(open(session/'device-dfu-before.json'))
pwnd=json.load(open(session/'device-pwnd.json'))
patched=json.load(open(session/'device-patched-iboot.json'))
recovery_path=session/'recovery-proof.json'
recovery_verified=os.environ.get('RECOVERY_VERIFIED')=='true'
proof={
  'schema_version':'tgcheckm8.apple-hardware-proof.v1',
  'session_id':session.name.removeprefix('session-'),
  'target_id':target['target_id'],
  'device_identity_sha256':initial['device_identity_sha256'],
  'same_device_pwnd':initial['device_identity_sha256']==pwnd['device_identity_sha256'],
  'same_device_patched_iboot':initial['device_identity_sha256']==patched['device_identity_sha256'],
  'pwn_provider':pwnd.get('pwn_provider'),
  'ramdisk_ssh_verified':True,
  'ramdisk_ssh_proof_sha256':h(session/'ramdisk-ssh-proof.txt'),
  'hardware_transcript_sha256':h(sys.argv[5]),
  'runtime_manifest_sha256':h(sys.argv[2]),
  'tool_build_receipt_sha256':h(sys.argv[3]),
  'authorization_ticket_sha256':hashlib.sha256(os.environ['TTG_AUTHORIZATION_TICKET'].encode()).hexdigest(),
  'normal_reboot_requested':os.environ.get('TTG_LEAVE_RAMDISK','NO')!='YES',
  'recovery_verified':recovery_verified,
  'recovery_proof_sha256':h(recovery_path) if recovery_path.is_file() else None,
  'stable_promotion_authorized':False,
}
(session/'hardware-proof.json').write_text(json.dumps(proof, indent=2, sort_keys=True)+'\n')
PY

printf 'Hardware sequence complete. Evidence: %s\n' "$SESSION"
printf 'Recovery verified: %s\n' "$RECOVERY_VERIFIED"
printf 'Stable promotion remains disabled pending transcript review and independent adjudication.\n'
