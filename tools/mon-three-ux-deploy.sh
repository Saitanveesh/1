#!/usr/bin/env bash
# PC2 only: upgrade the running Vite console, start local lab login and wg0 capture.
# Does not touch WireGuard, nftables, MON API, Site Controller or PC5.
set -Eeuo pipefail
umask 077
CODE="$HOME/mon-three-code"
STATE="$HOME/mon-three"
BRANCH=fix/linux-ssh-journal-ingestion-20261010
PIN=fcd749e6d65e07c7d11b25cd9c5b345562a468e9
UNIT=mon-three-lab-portal.service
PORTAL="$STATE/tools/mon-lab-portal.py"
ENVFILE=/etc/mon-three/lab-portal.env
SERVICE="/etc/systemd/system/$UNIT"
BACKUP=""
FRONTEND=""
SWAPPED=0
started=0
rollback() {
  rc=$?
  trap - ERR
  echo "[ROLLBACK] Upgrade failed: $rc" >&2
  if [[ "$SWAPPED" == 1 && -f "$BACKUP" ]]; then
    tar -xzf "$BACKUP" -C "$FRONTEND" || true
    rm -f "$FRONTEND/src/LoginPage.tsx" "$FRONTEND/src/PacketObservability.tsx"
  fi
  if [[ "$started" == 1 ]]; then
    sudo systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap rollback ERR
echo "========== PC2 PREFLIGHT =========="
[[ "$(id -un)" == pc-2 ]] || { echo "Run as pc-2"; exit 1; }
[[ -d "$CODE/.git" ]] || { echo "Missing $CODE"; exit 1; }
command -v npm >/dev/null
command -v git >/dev/null
curl -fsS --max-time 6 http://127.0.0.1:8080/health >/dev/null
curl -fsS --max-time 6 http://127.0.0.1:5173/ >/dev/null
sudo -v
pid=$(ss -H -lntp '( sport = :5173 )' | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1)
[[ "$pid" =~ ^[0-9]+$ ]] || { echo "Cannot identify Vite PID"; exit 1; }
FRONTEND=$(readlink -f "/proc/$pid/cwd")
[[ -f "$FRONTEND/src/App.tsx" && -f "$FRONTEND/vite.config.ts" ]] || {
  echo "Running Vite root does not look like MON: $FRONTEND"; exit 1;
}
[[ -d "$FRONTEND/node_modules" ]] || { echo "Frontend dependencies unavailable"; exit 1; }
echo "[PASS] Existing MON and running frontend: $FRONTEND"

echo "========== STAGE PINNED MON UI FILES =========="
git -C "$CODE" fetch --no-tags https://github.com/Saitanveesh/1.git "refs/heads/$BRANCH"
git -C "$CODE" merge-base --is-ancestor "$PIN" FETCH_HEAD
mkdir -p "$STATE/tools"
chmod 700 "$STATE" "$STATE/tools"
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT
for path in src/App.tsx src/IncidentDetail.tsx src/types.ts src/styles.css src/LoginPage.tsx src/PacketObservability.tsx vite.config.ts; do
  mkdir -p "$TEMP/$(dirname "$path")"
  git -C "$CODE" show "$PIN:console/$path" > "$TEMP/$path"
done
git -C "$CODE" show "$PIN:tools/mon-lab-portal.py" > "$TEMP/mon-lab-portal.py"
python3 -m py_compile "$TEMP/mon-lab-portal.py"

echo "========== UI BUILD + RESTORE POINT =========="
BACKUP="$STATE/console-pre-v2-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
tar czf "$BACKUP" -C "$FRONTEND" src/App.tsx src/IncidentDetail.tsx src/types.ts src/styles.css vite.config.ts
SWAPPED=1
for path in src/App.tsx src/IncidentDetail.tsx src/types.ts src/styles.css src/LoginPage.tsx src/PacketObservability.tsx vite.config.ts; do
  cp "$TEMP/$path" "$FRONTEND/$path"
  chmod 0644 "$FRONTEND/$path"
done
(cd "$FRONTEND" && npm run build)
echo "[PASS] UI built; backup: $BACKUP"

echo "========== SET LAB LOGIN CREDENTIAL =========="
cp "$TEMP/mon-lab-portal.py" "$PORTAL"
chmod 0700 "$PORTAL"
echo 'Operator ID: sai'
echo 'Enter the password you selected for this lab (you requested 12345).'
PASSWORD_HASH=$(python3 "$PORTAL" --hash-password)
[[ "$PASSWORD_HASH" == scrypt:* ]]
sudo install -d -m 0700 /etc/mon-three
printf '%s\n' "MON_PORTAL_USERNAME=sai" "MON_PORTAL_PASSWORD_HASH=$PASSWORD_HASH" \
  "MON_PORTAL_OPERATOR_TOKEN_FILE=$STATE/identity/operator.jwt" \
  "MON_PORTAL_ORIGIN=http://100.75.116.62:5173" "MON_PORTAL_INTERFACE=wg0" |
  sudo tee "$ENVFILE" >/dev/null
sudo chmod 0600 "$ENVFILE"
unset PASSWORD_HASH
echo "[PASS] Password stored as a salted scrypt verifier"

echo "========== START LOGIN + REAL PACKET SENSOR =========="
sudo tee "$SERVICE" >/dev/null <<EOF
[Unit]
Description=MON lab operator portal and WireGuard packet metadata capture
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=pc-2
Group=pc-2
WorkingDirectory=$STATE
EnvironmentFile=$ENVFILE
ExecStart=/usr/bin/python3 $PORTAL
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectKernelTunables=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET
UMask=0077
Restart=on-failure
RestartSec=4
[Install]
WantedBy=multi-user.target
EOF
sudo chmod 0644 "$SERVICE"
sudo systemctl daemon-reload
started=1
sudo systemctl enable --now "$UNIT"
ready=0
for attempt in $(seq 1 30); do
  if curl -fsS --max-time 3 http://127.0.0.1:8088/portal/health >/dev/null 2>&1 &&
     curl -fsS --max-time 3 http://127.0.0.1:5173/portal/health >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then
  sudo journalctl -u "$UNIT" -n 20 --no-pager >&2 || true
  echo "[FAIL] Portal or Vite /portal proxy unavailable" >&2
  exit 1
fi
curl -fsS --max-time 5 http://127.0.0.1:8090/health >/dev/null
curl -fsS --max-time 5 http://127.0.0.1:8080/health >/dev/null
echo "[PASS] Control, site, UI and login gateway healthy"
curl -fsS --max-time 5 http://127.0.0.1:5173/portal/health | python3 -m json.tool
echo "Open http://100.75.116.62:5173/?tenant=mon-lab&site=site-a"
echo 'Sign out of the old cookie session to see Welcome to MON.'
echo 'NOTE: sai/12345 is lab-only. Use real SSO + MFA for production.'
