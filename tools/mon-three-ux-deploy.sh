#!/usr/bin/env bash
# PC2 only: upgrade the running Vite console, start local lab login and wg0 capture.
# Does not touch WireGuard, nftables, MON API, Site Controller or PC5.
set -euo pipefail
umask 077
CODE="$HOME/mon-three-code"
STATE="$HOME/mon-three"
BRANCH=fix/linux-ssh-journal-ingestion-20261010
PIN=1213410ac8f2dc757815dde5e4be899632cce34a
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
command -v tmux >/dev/null
curl -fsS --max-time 6 http://127.0.0.1:8080/health >/dev/null
curl -fsS --max-time 6 http://127.0.0.1:8090/health >/dev/null
sudo -v

# Prefer the live process directory when present, but recover gracefully if
# the Vite tmux process exited. Never modify the API/site/WireGuard services.
pid=$(ss -H -lntp '( sport = :5173 )' | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1)
if [[ "$pid" =~ ^[0-9]+$ ]]; then
  FR=$(readlink -f "/proc/$pid/cwd")
  if [[ -f "$FR/src/App.tsx" && -f "$FR/vite.config.ts" ]]; then
    FRONTEND="$FR"
  fi
fi
if [[ -z "$FRONTEND" ]]; then
  for FR in "$HOME/mon-three-code/console" "$HOME/mon-three/console" "$HOME/mon/console" "$HOME/console"; do
    if [[ -f "$FR/src/App.tsx" && -f "$FR/vite.config.ts" ]]; then
      FRONTEND="$FR"
      break
    fi
  done
fi
[[ -n "$FRONTEND" ]] || {
  echo "[FAIL] MON console directory not found in expected PC2 locations" >&2
  exit 1
}
# This deployment changes ONLY MON console sources. A prior sudo/npm install
# has left mixed ownership in this lab's node_modules tree (EACCES mkdir).
# Keep privilege narrowly scoped to the verified console directory, never the
# full repo, HOME, WireGuard config or MON runtime identity material.
EXPECTED_FRONTEND=$(realpath -e "$CODE/console")
FRONTEND=$(realpath -e "$FRONTEND")
[[ "$FRONTEND" == "$EXPECTED_FRONTEND" &&
   "$FRONTEND" == "$HOME/mon-three-code/console" ]] || {
  echo "[FAIL] Console path differs from the authorized PC2 lab checkout" >&2
  exit 1
}
[[ -f "$FRONTEND/package.json" && -f "$FRONTEND/src/App.tsx" ]] || {
  echo "[FAIL] Expected MON console source files are missing" >&2
  exit 1
}
# Refuse symlinked writable subtrees: neither npm nor privilege repair may
# escape into other directories through node_modules/src symlinks.
[[ ! -L "$FRONTEND/node_modules" && ! -L "$FRONTEND/src" ]] || {
  echo "[FAIL] Console dependencies or source directory is a symlink; refusing ownership repair" >&2
  exit 1
}
# Repair once within this exact console tree; GNU chown -P does not traverse
# symlinks. Never run npm as root.
if [[ ! -w "$FRONTEND" || ! -w "$FRONTEND/src" ||
      ! -w "$FRONTEND/node_modules" ||
      -n "$(find "$FRONTEND/node_modules" -xdev \( -type d -o -type f \) ! -writable -print -quit 2>/dev/null)" ]]; then
  echo "[REPAIR] Mixed console ownership detected; restoring pc-2 permissions for the MON console only"
  sudo chown -hR -- "$(id -un):$(id -gn)" "$FRONTEND"
fi
[[ -w "$FRONTEND" && -w "$FRONTEND/src" &&
   -w "$FRONTEND/node_modules" ]] || {
  echo "[FAIL] Console remains unwritable; refusing npm/build" >&2
  exit 1
}
echo "[PASS] MON console ownership/write access verified for pc-2"

# On this lab host a populated node_modules directory may contain Vite but no
# TypeScript compiler: npm may have been run with devDependencies omitted.
# Confirm actual build tools, not merely node_modules' existence.
if [[ ! -x "$FRONTEND/node_modules/.bin/tsc" ||
      ! -x "$FRONTEND/node_modules/.bin/vite" ]]; then
  echo "[REPAIR] Local frontend build tools missing; installing development dependencies"
  (
    cd "$FRONTEND"
    npm install --include=dev --no-audit --no-fund --no-save --package-lock=false
  )
fi
[[ -x "$FRONTEND/node_modules/.bin/tsc" ]] || {
  echo "[FAIL] TypeScript compiler still unavailable after npm installation" >&2
  exit 1
}
[[ -x "$FRONTEND/node_modules/.bin/vite" ]] || {
  echo "[FAIL] Vite build binary still unavailable after npm installation" >&2
  exit 1
}
echo "[PASS] Local TypeScript and Vite build tools available"

# A healthy Vite server may be bound to PC2's Tailscale address only,
# making 127.0.0.1:5173 fail while the Windows browser is connected.
# Probe both local interface addresses without guessing process health.
CONSOLE_URL=""
probe_console() {
  local address
  for address in 127.0.0.1 100.75.116.62; do
    if curl --noproxy '*' -fsS --max-time 4 "http://$address:5173/" >/dev/null 2>&1; then
      CONSOLE_URL="http://$address:5173"
      return 0
    fi
  done
  return 1
}
if probe_console; then
  echo "[PASS] Existing frontend reachable at $CONSOLE_URL"
else
  # When a listener is present but unresponsive, replace it ONLY if
  # /proc confirms it is a Vite process owned by pc-2 in this exact MON
  # frontend directory. Never kill a generic process on this port.
  listener_pid=$(ss -H -lntp '( sport = :5173 )' |
    sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1)
  if ss -H -lnt '( sport = :5173 )' | grep -q LISTEN; then
    [[ "$listener_pid" =~ ^[0-9]+$ ]] || {
      echo "[FAIL] Port 5173 occupied and its PID cannot be read" >&2
      ss -H -lntp '( sport = :5173 )' >&2
      exit 1
    }
    cmd=$(tr '\0' ' ' < "/proc/$listener_pid/cmdline")
    live_root=$(readlink -f "/proc/$listener_pid/cwd")
    if [[ "$live_root" != "$FRONTEND" || "$cmd" != *vite* ]]; then
      echo "[FAIL] Port 5173 belongs to an unrecognized service; refusing to stop it" >&2
      printf '[CHECK] PID %s CMD %s\n' "$listener_pid" "$cmd" >&2
      exit 1
    fi
    echo "[RECOVER] Verified MON Vite PID $listener_pid is unhealthy; restarting only that web process"
    kill -TERM "$listener_pid"
    for attempt in $(seq 1 16); do
      if ! ss -H -lnt '( sport = :5173 )' | grep -q LISTEN; then
        break
      fi
      sleep 1
    done
    if ss -H -lnt '( sport = :5173 )' | grep -q LISTEN; then
      echo "[FAIL] The old Vite process did not release port 5173; left untouched" >&2
      exit 1
    fi
  fi
  echo "[RECOVER] Starting MON frontend on both loopback and overlay interfaces"
  SESSION=mon-console-ux
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "[FAIL] tmux session $SESSION already exists; refusing to disrupt it" >&2
    exit 1
  fi
  tmux new-session -d -s "$SESSION" "cd '$FRONTEND' && npm run dev -- --host 0.0.0.0 --port 5173 --strictPort"
  online=0
  for attempt in $(seq 1 24); do
    if probe_console; then
      online=1; break
    fi
    sleep 1
  done
  if [[ "$online" != 1 ]]; then
    tmux capture-pane -pt "$SESSION" -S -30 || true
    echo "[FAIL] Frontend recovery failed; MON backend was not modified" >&2
    exit 1
  fi
  echo "[PASS] Frontend recovered at $CONSOLE_URL (tmux $SESSION)"
fi

echo "[PASS] Existing MON, Site Controller, and frontend: $FRONTEND"

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
(
  cd "$FRONTEND"
  npm run build
)
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
# Vite returns HTML with status 200 for unknown routes. A successful
# HTTP status therefore does NOT prove the /portal proxy is configured.
portal_healthy() {
  local body
  body=$(curl --noproxy '*' -fsS --max-time 4 "$1/portal/health" 2>/dev/null) || return 1
  printf '%s' "$body" | python3 -c 'import json,sys
try:
  x=json.load(sys.stdin)
  ok=isinstance(x,dict) and x.get("state")=="READY" and x.get("capture")=="CAPTURING"
except (ValueError,TypeError):
  ok=False
sys.exit(0 if ok else 1)' 2>/dev/null
}
ready=0
for attempt in $(seq 1 25); do
  if portal_healthy http://127.0.0.1:8088 && portal_healthy "$CONSOLE_URL"; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then
  echo "[FAIL] Gateway or Vite proxy did not return READY/CAPTURING JSON" >&2
  echo "[CHECK] Direct gateway health:" >&2
  curl --noproxy '*' --max-time 4 -sS http://127.0.0.1:8088/portal/health >&2 || true
  printf '\n' >&2
  echo "[CHECK] Browser proxy response headers:" >&2
  curl --noproxy '*' --max-time 4 -sSI "$CONSOLE_URL/portal/health" >&2 || true
  sudo journalctl -u "$UNIT" -n 18 --no-pager >&2 || true
  false
fi
curl -fsS --max-time 5 http://127.0.0.1:8090/health >/dev/null
curl -fsS --max-time 5 http://127.0.0.1:8080/health >/dev/null
echo "[PASS] Control, site, UI, proxy and live capture healthy"
curl --noproxy '*' -fsS --max-time 5 "$CONSOLE_URL/portal/health" | python3 -m json.tool
echo "Open http://100.75.116.62:5173/?tenant=mon-lab&site=site-a"
echo 'Sign out of the old cookie session to see Welcome to MON.'
echo 'NOTE: sai/12345 is lab-only. Use real SSO + MFA for production.'
