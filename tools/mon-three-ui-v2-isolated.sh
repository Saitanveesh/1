#!/usr/bin/env bash
# Three-PC MON lab: isolated V2 console on port 5174.
# Existing 5173 frontend, API, Site Controller, VPN, and firewall remain intact.
set -euo pipefail
umask 077

CODE="$HOME/mon-three-code"
STATE="$HOME/mon-three"
APP="$STATE/console-v2"
PORTAL_ENV="/etc/mon-three/lab-portal.env"
PORTAL_SERVICE="mon-three-lab-portal.service"
FRONTEND_SERVICE="mon-three-console-v2.service"
FRONTEND_UNIT="/etc/systemd/system/$FRONTEND_SERVICE"
SOURCE_PIN="1213410ac8f2dc757815dde5e4be899632cce34a"
BRANCH="fix/linux-ssh-journal-ingestion-20261010"
HOST_IP="100.75.116.62"
PORT=5174
STAGING=""
BACKUP_ENV=""
APP_CREATED=0
UNIT_CREATED=0
PORTAL_CHANGED=0
PORTAL_WAS_ACTIVE=0
INSTALL_COMPLETE=0

say(){ printf '\n========== %s ==========\n' "$1"; }
pass(){ printf '[PASS] %s\n' "$1"; }
fail(){ printf '[FAIL] %s\n' "$1" >&2; return 1; }

restore() {
  rc=$?
  trap - EXIT
  if [[ "$INSTALL_COMPLETE" != 1 ]]; then
    echo "[RECOVER] Isolated UI setup did not finish; restoring only V2 resources" >&2
    if [[ "$UNIT_CREATED" == 1 ]]; then
      sudo systemctl disable --now "$FRONTEND_SERVICE" >/dev/null 2>&1 || true
      sudo rm -f -- "$FRONTEND_UNIT"
      sudo systemctl daemon-reload || true
    fi
    if [[ "$PORTAL_CHANGED" == 1 && -n "$BACKUP_ENV" ]]; then
      sudo cp -p -- "$BACKUP_ENV" "$PORTAL_ENV" || true
      if [[ "$PORTAL_WAS_ACTIVE" == 1 ]]; then
        sudo systemctl restart "$PORTAL_SERVICE" || true
      else
        sudo systemctl stop "$PORTAL_SERVICE" || true
      fi
    fi
    if [[ "$APP_CREATED" == 1 && -d "$APP" && ! -L "$APP" ]]; then
      rm -rf -- "$APP"
    fi
  fi
  if [[ -n "$STAGING" && -d "$STAGING" ]]; then
    rm -rf -- "$STAGING"
  fi
  exit "$rc"
}
trap restore EXIT

say 'SAFE PC2 PREFLIGHT'
[[ "$(id -un)" == pc-2 ]] || fail 'Run on PC2 as pc-2, not root'
[[ "$CODE" == "/home/pc-2/mon-three-code" ]] || fail 'Unexpected MON checkout'
[[ "$APP" == "/home/pc-2/mon-three/console-v2" ]] || fail 'Unexpected destination'
[[ -d "$CODE/.git" && -d "$CODE/console/node_modules" ]] || fail 'Existing MON console checkout/dependencies missing'
[[ -x "$CODE/console/node_modules/.bin/tsc" && -x "$CODE/console/node_modules/.bin/vite" ]] || fail 'Frontend build tools missing'
for cmd in git npm curl tar ss systemctl python3; do command -v "$cmd" >/dev/null || fail "$cmd unavailable"; done
curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:8080/health >/dev/null || fail 'Control API unavailable'
curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:8090/health >/dev/null || fail 'Site Controller unavailable'
curl --noproxy '*' -fsS --max-time 6 "http://$HOST_IP:5173/" >/dev/null || fail 'Existing 5173 console not reachable'
sudo -v
sudo test -f "$PORTAL_ENV" || fail 'Prior portal password configuration missing'
sudo test -f /etc/systemd/system/mon-three-lab-portal.service || fail 'Portal systemd unit missing'

json_ready() {
  local output
  output=$(curl --noproxy '*' -fsS --max-time 5 "$1" 2>/dev/null) || return 1
  printf '%s' "$output" | python3 -c '
import json,sys
try:
    data=json.load(sys.stdin)
    ok=isinstance(data,dict) and data.get("state")=="READY" and data.get("capture")=="CAPTURING"
except (ValueError, TypeError):
    ok=False
sys.exit(0 if ok else 1)
' 2>/dev/null
}
if json_ready "http://127.0.0.1:$PORT/portal/health"; then
  INSTALL_COMPLETE=1
  pass 'V2 console already responds with real packet sensor JSON'
  echo "Open http://$HOST_IP:$PORT/?tenant=mon-lab&site=site-a"
  exit 0
fi
if ss -H -lnt "( sport = :$PORT )" | grep -q LISTEN; then
  fail "Port $PORT is occupied by another process; existing processes remain untouched"
fi
[[ ! -e "$APP" && ! -L "$APP" ]] || fail "V2 target already exists at $APP; refusing to overwrite it"
[[ ! -e "$FRONTEND_UNIT" ]] || fail 'V2 service unit already exists; refusing to replace it'
pass 'Existing backend, router and port 5173 are healthy; port 5174 is free'

say 'BUILD NEW V2 CONSOLE IN ITS OWN DIRECTORY'
git -C "$CODE" fetch --no-tags https://github.com/Saitanveesh/1.git "refs/heads/$BRANCH"
git -C "$CODE" merge-base --is-ancestor "$SOURCE_PIN" FETCH_HEAD || fail 'Pinned UI revision not reachable'
git -C "$CODE" cat-file -e "$SOURCE_PIN^{commit}"
mkdir -p "$STATE"
STAGING=$(mktemp -d "$STATE/console-v2-stage.XXXXXXXX")
git -C "$CODE" archive "$SOURCE_PIN" console | tar -xf - -C "$STAGING"
[[ -f "$STAGING/console/package.json" && -f "$STAGING/console/src/App.tsx" ]] || fail 'Pinned source extraction incomplete'
# Read-only dependency reuse avoids another sudo/chown or installation.
ln -s -- "$CODE/console/node_modules" "$STAGING/console/node_modules"
( cd "$STAGING/console" && npm run build )
pass 'Isolated V2 frontend built successfully with existing dependencies'
mv -- "$STAGING/console" "$APP"
APP_CREATED=1
pass "Isolated V2 installed: $APP (original 5173 sources unchanged)"

say 'USE EXISTING LAB PASSWORD; UPDATE ONLY ALLOWED BROWSER ORIGIN'
if sudo systemctl is-active --quiet "$PORTAL_SERVICE"; then
  PORTAL_WAS_ACTIVE=1
fi
BACKUP_ENV="$PORTAL_ENV.before-console-v2-$(date -u +%Y%m%dT%H%M%SZ)"
sudo cp -p -- "$PORTAL_ENV" "$BACKUP_ENV"
sudo python3 - "$PORTAL_ENV" "$HOST_IP" "$PORT" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
ip=sys.argv[2]
port=sys.argv[3]
original=p.read_text()
lines=original.splitlines()
if not any(x.startswith("MON_PORTAL_PASSWORD_HASH=scrypt:") for x in lines):
    raise SystemExit("Missing existing salted lab password verifier")
replaced=False
for idx,line in enumerate(lines):
    if line.startswith("MON_PORTAL_ORIGIN="):
        lines[idx]=f"MON_PORTAL_ORIGIN=http://{ip}:{port}"
        replaced=True
if not replaced:
    raise SystemExit("Existing operator portal origin missing")
p.write_text("\n".join(lines)+"\n")
PY
PORTAL_CHANGED=1
sudo systemctl enable --now "$PORTAL_SERVICE" >/dev/null
sudo systemctl restart "$PORTAL_SERVICE"
ready=0
for attempt in $(seq 1 20); do
  if json_ready http://127.0.0.1:8088/portal/health; then
    ready=1; break
  fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then
  sudo journalctl -u "$PORTAL_SERVICE" -n 18 --no-pager >&2 || true
  fail 'Real packet capture is not healthy after portal restart'
fi
pass 'Existing sai password retained; real wg0 sensor CAPTURING'

say 'LAUNCH V2 AS A SEPARATE SYSTEMD SERVICE'
NPM=$(command -v npm)
sudo tee "$FRONTEND_UNIT" >/dev/null <<EOF
[Unit]
Description=MON V2 isolated operator console on port 5174
After=network-online.target $PORTAL_SERVICE
Wants=network-online.target

[Service]
Type=simple
User=pc-2
Group=pc-2
WorkingDirectory=$APP
ExecStart=$NPM run dev -- --host 0.0.0.0 --port $PORT --strictPort
NoNewPrivileges=true
Restart=on-failure
RestartSec=4
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
UNIT_CREATED=1
sudo chmod 0644 "$FRONTEND_UNIT"
sudo systemctl daemon-reload
sudo systemctl enable --now "$FRONTEND_SERVICE"

say 'STRICT END-TO-END VERIFICATION'
ok=0
for attempt in $(seq 1 30); do
  if json_ready "http://127.0.0.1:$PORT/portal/health" &&
     json_ready "http://$HOST_IP:$PORT/portal/health"; then
    ok=1; break
  fi
  sleep 1
done
if [[ "$ok" != 1 ]]; then
  echo "[CHECK] V2 service recent logs:" >&2
  sudo journalctl -u "$FRONTEND_SERVICE" -n 25 --no-pager >&2 || true
  fail 'V2 frontend did not proxy the gateway READY/CAPTURING JSON'
fi
curl --noproxy '*' -fsS --max-time 6 "http://$HOST_IP:$PORT/" >/dev/null || fail 'New V2 frontend root is unavailable'
curl --noproxy '*' -fsS --max-time 6 "http://$HOST_IP:5173/" >/dev/null || fail 'Original frontend unexpectedly unavailable'
curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:8080/health >/dev/null || fail 'Control API health lost'
curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:8090/health >/dev/null || fail 'Site Controller health lost'
INSTALL_COMPLETE=1
pass 'Port 5174 has correct same-origin /portal proxy and CAPTURING sensor'
pass 'Original dashboard on 5173 still reachable'
pass 'Control plane, Site Controller and existing network untouched'
printf '\nOPEN: http://%s:%s/?tenant=mon-lab&site=site-a\n' "$HOST_IP" "$PORT"
echo 'Use operator ID sai and the lab password you already configured.'
echo 'If a previous browser cookie logs you in automatically, click SIGN OUT first.'
echo 'This is a limited HTTP lab credential flow; it is not production SSO/MFA.'
