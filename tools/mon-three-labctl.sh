#!/usr/bin/env bash
# Existing MON 3-PC lab runtime control. No reinstall, rekey, firewall mutation or code upgrade.
set -Eeuo pipefail
umask 077

ROLE="$(id -un)"
COMMAND="${1:-status}"
ROOT="$HOME/mon-three"
TOKEN_FILE="$ROOT/identity/operator.jwt"
GATEWAY_IP="10.77.0.1"
VICTIM_IP="10.77.0.50"
ATTACKER_IP="10.77.0.70"
POSTGRES="mon-three-postgres"

say() { printf '[MON %s] %s\n' "$ROLE" "$*"; }
pass() { say "PASS: $*"; }
warn() { say "CHECK: $*" >&2; }
stop() { say "STOP: $*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
Usage: bash mon-labctl.sh status|start|enable|backup|renew-token|start-all|status-all
  status      Read-only health gate for this PC (default)
  start       Start only existing, expected local services; then verify
  enable      Explicitly enable existing local services at VM boot
  backup      PC-2 only: private, verified PostgreSQL logical backup
  renew-token PC-2 only: sign an 8h operator JWT using EXISTING key (opt-in)
  start-all   PC-2 only: local start, then PC-5 and PC-7 over WireGuard SSH
  status-all  PC-2 only: local status, then PC-5 and PC-7 over WireGuard SSH
No operation installs, rekeys, flushes firewall, changes IPs, or launches attacks.
USAGE
}

case "$ROLE" in
  pc-2|pc-5|pc-7) ;;
  *) stop "Expected pc-2, pc-5 or pc-7 account; got $ROLE" ;;
esac

# A failing check must remain a failing check, even if other components are healthy.
ERRORS=0
check() {
  local description="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$description"; else warn "$description FAILED"; ERRORS=$((ERRORS+1)); fi
}
check_http() {
  local label="$1" url="$2" expected="${3:-200}" cookie="${4:-}" code
  local args=(--noproxy '*' --silent --show-error --max-time 8 --output /dev/null --write-out '%{http_code}')
  if [[ -n "$cookie" ]]; then args+=(-H "Cookie: mon_session=$cookie"); fi
  code="$(curl "${args[@]}" "$url" 2>/dev/null)" || code="000"
  if [[ "$code" == "$expected" ]]; then pass "$label HTTP $code"; else warn "$label HTTP $code (expected $expected)"; ERRORS=$((ERRORS+1)); fi
}
check_portal_capture() {
  local payload
  payload="$(curl --noproxy '*' -fsS --max-time 8 http://127.0.0.1:5174/portal/health 2>/dev/null)" || return 1
  printf '%s' "$payload" | python3 -c 'import json,sys
try:
    data=json.load(sys.stdin)
    assert data.get("state")=="READY" and data.get("capture")=="CAPTURING"
except (ValueError, AttributeError, AssertionError):
    sys.exit(1)'
}
check_victim_version() {
  local payload
  payload="$(curl --noproxy '*' -fsS --max-time 8 "http://$VICTIM_IP:8085/health" 2>/dev/null)" || return 1
  printf '%s' "$payload" | python3 -c 'import json,sys
try:
    data=json.load(sys.stdin)
    assert data.get("status")=="READY" and data.get("training") is True and data.get("version")==4
except (ValueError, AttributeError, AssertionError):
    sys.exit(1)'
}
check_tunnel() {
  local expected="$1"
  check "wg0 has $expected" sh -c 'ip -4 addr show dev wg0 | grep -Fq -- "$1"' _ "$expected"
}
check_service() { check "service $1 active" systemctl is-active --quiet "$1"; }
start_service() {
  systemctl cat "$1" >/dev/null 2>&1 || stop "Missing installed service: $1"
  sudo systemctl start "$1" || stop "Cannot start $1; inspect journalctl -u $1"
}
enable_service() {
  systemctl cat "$1" >/dev/null 2>&1 || stop "Missing installed service: $1"
  sudo systemctl enable "$1" || stop "Could not enable $1"
}
ensure_wg() {
  if ! ip -4 addr show dev wg0 >/dev/null 2>&1; then
    start_service wg-quick@wg0.service
  fi
}
postgres_exists() { sudo docker inspect "$POSTGRES" >/dev/null 2>&1; }
postgres_running() { [[ "$(sudo docker inspect --format '{{.State.Running}}' "$POSTGRES" 2>/dev/null)" == true ]]; }
postgres_ready() {
  sudo docker exec "$POSTGRES" sh -c 'pg_isready -U "${POSTGRES_USER:-mon}" -d "${POSTGRES_DB:-mon}"' >/dev/null 2>&1
}

status_local() {
  ERRORS=0
  say "Checking current services; no configuration will change"
  case "$ROLE" in
    pc-2)
      check_tunnel "$GATEWAY_IP/"
      check_service mon-three-lab-portal.service
      check_service mon-three-console-v2.service
      check_service mon-suricata-passive.service
      check_service mon-stage4-gate.service
      check "existing PostgreSQL container running" postgres_running
      check "existing PostgreSQL accepts connections" postgres_ready
      check_http "MON API health" http://127.0.0.1:8080/health
      check_http "MON console" http://127.0.0.1:5174/
      check "MON portal READY + CAPTURING (real packet sensor)" check_portal_capture
      check "PC-5 website READY / training version 4" check_victim_version
      if [[ -s "$TOKEN_FILE" ]]; then
        local token
        token="$(<"$TOKEN_FILE")"
        check_http "operator identity (expired JWT? see renewal runbook)" http://127.0.0.1:5174/api/v1/me 200 "$token"
        check_http "authenticated live snapshot (500? check DB/logs)" 'http://127.0.0.1:5174/api/v1/live/snapshot?tenant_id=mon-lab&site_id=site-a' 200 "$token"
        unset token
      else
        warn "Missing operator JWT at configured lab location"
        ERRORS=$((ERRORS+1))
      fi
      ;;
    pc-5)
      check_tunnel "$VICTIM_IP/32"
      check_service mon-training-site.service
      check "can reach PC-2 WireGuard gateway" ping -c 1 -W 2 "$GATEWAY_IP"
      check "training website READY / version 4" check_victim_version
      ;;
    pc-7)
      check_tunnel "$ATTACKER_IP/32"
      check_service mon-batch2-attack-console.service
      check "can reach PC-2 WireGuard gateway" ping -c 1 -W 2 "$GATEWAY_IP"
      check_http "attacker console (no attack launched)" http://127.0.0.1:8766/
      check "PC-5 training website READY / version 4" check_victim_version
      ;;
  esac
  if (( ERRORS > 0 )); then say "$ERRORS health check(s) failed"; return 1; fi
  say "READY: verified checks passed (not proof of an end-to-end attack/containment test)"
}

start_local() {
  say "Starting only existing, role-specific lab components"
  case "$ROLE" in
    pc-2)
      sudo systemctl start docker.service || stop 'Docker engine failed'
      postgres_exists || stop "Container $POSTGRES missing; refusing to create a new database"
      if ! postgres_running; then
        sudo docker start "$POSTGRES" >/dev/null || stop "Cannot start $POSTGRES"
      fi
      local database_up=0
      for attempt in {1..25}; do
        if postgres_ready; then database_up=1; break; fi
        sleep 1
      done
      [[ "$database_up" == 1 ]] || stop "Existing PostgreSQL did not become ready; inspect its logs"
      ensure_wg
      for unit in mon-three-lab-portal.service mon-three-console-v2.service mon-suricata-passive.service mon-stage4-gate.service; do
        start_service "$unit"
      done
      ;;
    pc-5)
      ensure_wg
      start_service mon-training-site.service
      ;;
    pc-7)
      ensure_wg
      start_service mon-batch2-attack-console.service
      ;;
  esac
  status_local
}

enable_local() {
  say "Opt-in VM boot startup for existing components; no reboot performed"
  case "$ROLE" in
    pc-2)
      sudo systemctl enable docker.service || stop 'Could not enable Docker'
      postgres_exists || stop "Container $POSTGRES missing; refusing replacement"
      sudo docker update --restart unless-stopped "$POSTGRES" >/dev/null || stop 'Could not set database restart policy'
      for unit in wg-quick@wg0.service mon-three-lab-portal.service mon-three-console-v2.service mon-suricata-passive.service mon-stage4-gate.service; do
        enable_service "$unit"
      done
      ;;
    pc-5) for unit in wg-quick@wg0.service mon-training-site.service; do enable_service "$unit"; done ;;
    pc-7) for unit in wg-quick@wg0.service mon-batch2-attack-console.service; do enable_service "$unit"; done ;;
  esac
  say "Boot settings enabled. They do NOT boot the underlying Windows PC/VM automatically."
}

backup_pc2() {
  [[ "$ROLE" == pc-2 ]] || stop 'PostgreSQL backup runs on PC-2 only'
  postgres_exists || stop 'Existing Postgres container missing'
  postgres_ready || stop 'Postgres is not ready; not creating an empty backup'
  local dir="$HOME/mon-lab-backups" file tmp
  mkdir -p "$dir"
  chmod 0700 "$dir"
  file="$dir/mon-postgres-$(date -u +%Y%m%dT%H%M%SZ).dump"
  [[ ! -e "$file" ]] || stop "Backup already exists: $file"
  tmp="$(mktemp "$dir/.pgdump.XXXXXXXX")"
  trap 'rm -f -- "$tmp"' EXIT
  say "Backing up existing PostgreSQL database; credentials and telemetry may be present"
  if ! sudo docker exec "$POSTGRES" sh -c 'exec pg_dump -U "${POSTGRES_USER:-mon}" -d "${POSTGRES_DB:-mon}" -Fc' > "$tmp"; then
    stop 'pg_dump failed; temporary backup will be deleted'
  fi
  [[ -s "$tmp" ]] || stop 'Empty database backup rejected'
  if ! sudo docker exec -i "$POSTGRES" pg_restore --list < "$tmp" >/dev/null 2>&1; then
    stop 'Backup archive verification failed'
  fi
  chmod 0600 "$tmp"
  mv -n -- "$tmp" "$file" || stop 'Could not move verified backup into place'
  trap - EXIT
  sha256sum "$file" > "$file.sha256"
  chmod 0600 "$file.sha256"
  pass "Verified private PostgreSQL backup: $file"
  warn 'Database dump is NOT a VM snapshot, and must never be committed to GitHub'
}

renew_token() {
  [[ "$ROLE" == pc-2 ]] || stop 'Only PC-2 may renew the operator token'
  local python="$HOME/mon-three-code/.venv/bin/python"
  [[ -x "$python" ]] || stop 'Expected MON virtualenv Python not installed; no changes made'
  "$python" - <<'PYJWT'
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import shutil
import tempfile
from urllib.request import ProxyHandler, Request, build_opener

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

home = Path.home()
identity = home / 'mon-three/identity'
target = identity / 'operator.jwt'
if not target.is_file() or target.is_symlink():
    raise SystemExit('STOP: regular operator.jwt file not found')
keys = [identity / 'auth-private.pem', home / 'mon-lab-identity/auth-private.pem']
keyfile = next((key for key in keys if key.is_file()), None)
if keyfile is None:
    raise SystemExit('STOP: existing signing key not found; never regenerate trust here')
old = target.read_text(encoding='utf-8').strip()
header = jwt.get_unverified_header(old)
if header.get('alg') != 'RS256' or not isinstance(header.get('kid'), str):
    raise SystemExit('STOP: unexpected signing algorithm/key ID')
key = load_pem_private_key(keyfile.read_bytes(), password=None)
# Only inspect issuer/audience unverified in order to pass those values to the verifier.
preview = jwt.decode(old, options={'verify_signature': False})
if not isinstance(preview.get('iss'), str) or not isinstance(preview.get('aud'), str):
    raise SystemExit('STOP: issuer/audience missing')
claims = jwt.decode(
    old, key.public_key(), algorithms=['RS256'], issuer=preview['iss'],
    audience=preview['aud'],
    options={'verify_exp': False, 'verify_iat': False, 'verify_nbf': False,
             'require': ['sub', 'exp', 'iat']},
)
if claims.get('tenant_id') != 'mon-lab' or not isinstance(claims.get('roles'), list):
    raise SystemExit('STOP: operator scope inconsistent with the lab')
now = datetime.now(timezone.utc)
claims['iat'] = int(now.timestamp())
claims['exp'] = int((now + timedelta(hours=8)).timestamp())
if 'nbf' in claims:
    claims['nbf'] = int(now.timestamp())
renewed = jwt.encode(claims, key, algorithm='RS256', headers={'kid': header['kid']})

# A new cookie must actually be accepted by the running MON API.
opener = build_opener(ProxyHandler({}))
request = Request('http://127.0.0.1:8080/api/v1/me',
                  headers={'Cookie': 'mon_session=' + renewed})
try:
    with opener.open(request, timeout=8) as response:
        if response.status != 200:
            raise RuntimeError('backend rejected the new JWT')
except Exception as exc:
    raise SystemExit(f'STOP: new token not accepted; original unchanged: {type(exc).__name__}: {exc}')

backup = identity / ('operator.jwt.backup-' + now.strftime('%Y%m%dT%H%M%SZ'))
if backup.exists():
    raise SystemExit('STOP: existing backup name; retry after one second')
shutil.copy2(target, backup)
os.chmod(backup, 0o600)
fd, pending = tempfile.mkstemp(dir=identity, prefix='.operator-')
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        output.write(renewed + '\n')
        output.flush()
        os.fsync(output.fileno())
    os.chmod(pending, 0o600)
    os.replace(pending, target)
finally:
    if os.path.exists(pending):
        os.unlink(pending)
print('PASS: Existing-key signed 8-hour operator token accepted by MON backend.')
print('Expiry UTC:', datetime.fromtimestamp(claims['exp'], timezone.utc).isoformat())
print('Token stored locally; its value has NOT been printed. Re-login to refresh browser cookie.')
PYJWT
}

remote_task() {
  local remote_role="$1" host="$2" command="$3"
  say "Remote $remote_role at $host: $command"
  # This requires the remote VM to have booted and WireGuard SSH to be available.
  ssh -tt -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new \
    "$remote_role@$host" 'bash "$HOME/mon-labctl.sh"' "$command"
}

all_nodes() {
  [[ "$ROLE" == pc-2 ]] || stop 'start-all/status-all must run on PC-2'
  local operation="$1" failures=0
  if [[ "$operation" == start ]]; then start_local || failures=$((failures+1));
  else status_local || failures=$((failures+1)); fi
  for role_host in "pc-5:$VICTIM_IP" "pc-7:$ATTACKER_IP"; do
    local role="${role_host%%:*}" host="${role_host#*:}"
    if ! remote_task "$role" "$host" "$operation"; then
      warn "$role failed or SSH unavailable; check remote VM, SSH, sudo, wg0 and installed script"
      failures=$((failures+1))
    fi
  done
  (( failures == 0 )) || stop "$failures node(s) failed; not claiming the whole lab is ready"
  say 'All 3 PCs passed their individual health gates'
}

case "$COMMAND" in
  status) status_local ;;
  start) start_local ;;
  enable) enable_local ;;
  backup) backup_pc2 ;;
  renew-token) renew_token ;;
  start-all) all_nodes start ;;
  status-all) all_nodes status ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 2 ;;
esac
