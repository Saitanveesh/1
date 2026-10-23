#!/usr/bin/env bash
# PC-2 Stage 4: narrow, timed lab web containment + impact UI.
# Does not restart WireGuard/Suricata, change the MON database, or mutate peers.
set -Eeuo pipefail
umask 077
MODE="${1:---check}"
[[ "$MODE" == "--check" || "$MODE" == "--apply" ]] || {
  echo "Usage: bash mon-stage4-pc2.sh --check|--apply" >&2; exit 2;
}
[[ "$(id -un)" == "pc-2" ]] || { echo "Run as pc-2 on PC-2" >&2; exit 1; }

ROOT="$HOME/mon-three"
WEB="$ROOT/console-v2"
TOOLS="$ROOT/tools"
CODE="$HOME/mon-three-code"
PORTAL="$TOOLS/mon-lab-portal.py"
BRANCH=feature/mon-stage4-containment-impact-20261023
REPO=https://github.com/Saitanveesh/1.git
GATE_UNIT=/etc/systemd/system/mon-stage4-gate.service
GATE_BIN=/usr/local/libexec/mon-stage4-gate.py
PORTAL_SERVICE=mon-three-lab-portal.service
FRONTEND_SERVICE=mon-three-console-v2.service
STAGE=""
BACKUP=""
TOUCHED=0
SUCCESS=0
log(){ printf '[MON STAGE4] %s\n' "$*"; }
fail(){ log "STOP: $*" >&2; exit 1; }
restore(){
  status=$?
  trap - EXIT
  if [[ "$TOUCHED" == 1 && "$SUCCESS" != 1 ]]; then
    log "Upgrade error. Restoring the operator portal and frontend from backup."
    sudo systemctl stop mon-stage4-gate.service >/dev/null 2>&1 || true
    tar -xzf "$BACKUP/frontend.tar.gz" -C "$ROOT" || true
    for n in mon-lab-portal.py mon_stage4_bridge.py mon_stage4_gate.py; do
      if [[ -f "$BACKUP/$n" ]]; then
        cp -a "$BACKUP/$n" "$TOOLS/$n" || true
      elif [[ "$n" != mon-lab-portal.py ]]; then
        rm -f "$TOOLS/$n" || true
      fi
    done
    if [[ -f "$BACKUP/gate-unit" ]]; then sudo cp -a "$BACKUP/gate-unit" "$GATE_UNIT" || true
    else sudo rm -f "$GATE_UNIT" || true; fi
    if [[ -f "$BACKUP/gate-binary" ]]; then sudo cp -a "$BACKUP/gate-binary" "$GATE_BIN" || true
    else sudo rm -f "$GATE_BIN" || true; fi
    sudo systemctl daemon-reload || true
    if [[ -f "$BACKUP/gate-unit" ]]; then
      sudo systemctl restart mon-stage4-gate.service || true
    else
      sudo systemctl disable --now mon-stage4-gate.service >/dev/null 2>&1 || true
    fi
    sudo systemctl restart "$PORTAL_SERVICE" || true
    sudo systemctl restart "$FRONTEND_SERVICE" || true
    log "Restore point retained at $BACKUP"
    log "Kernel timed-set elements, if any, expire independently; inspect nftables status."
  fi
  [[ -z "$STAGE" ]] || rm -rf "$STAGE"
  exit "$status"
}
trap restore EXIT

for item in git python3 npm node curl tar nft sudo ip; do
  command -v "$item" >/dev/null || fail "Required program missing: $item"
done
[[ -d "$CODE/.git" && -s "$PORTAL" && -f "$WEB/src/App.tsx" &&
   -x "$WEB/node_modules/.bin/tsc" ]] || fail "Existing MON operator console not found"
[[ -x /usr/sbin/nft ]] || fail "Expected nft binary /usr/sbin/nft missing"
sudo -v
sudo systemctl is-active --quiet "$PORTAL_SERVICE" || fail "Original portal not active"
sudo systemctl is-active --quiet "$FRONTEND_SERVICE" || fail "Original console not active"
curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8088/portal/health >/dev/null ||
  fail "Original portal health endpoint unavailable"
curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:5174/ >/dev/null ||
  fail "Original frontend health endpoint unavailable"
ip -4 route get 10.77.0.50 | grep -Fq ' dev wg0' ||
  fail "The victim is not routed through PC-2 wg0. Refusing firewall changes."
sudo nft list tables >/dev/null || fail "nftables unavailable"

git -C "$CODE" fetch --no-tags "$REPO" "refs/heads/$BRANCH" ||
  fail "Cannot fetch final Stage 4 release"
REV="$(git -C "$CODE" rev-parse FETCH_HEAD)"
STAGE="$(mktemp -d "$ROOT/mon-stage4-staged.XXXXXXXX")"
git -C "$CODE" archive "$REV" console tools/mon-lab-portal.py \
  tools/mon_stage4_gate.py tools/mon_stage4_bridge.py tools/test_mon_stage4.py \
  lab/pc5-training-site | tar -xf - -C "$STAGE"
[[ -s "$STAGE/tools/mon_stage4_gate.py" &&
   -s "$STAGE/lab/pc5-training-site/mon_stage4_impact.py" ]] ||
  fail "Stage 4 components missing"
ln -s "$WEB/node_modules" "$STAGE/console/node_modules"
python3 -m py_compile "$STAGE/tools/"*.py "$STAGE/lab/pc5-training-site/"*.py
(
  cd "$STAGE"
  PYTHONPATH="$STAGE/tools" python3 -m unittest discover -s tools -p test_mon_stage4.py
  python3 -m unittest discover -s lab/pc5-training-site -p 'test_*.py'
  cd "$STAGE/console"
  npm run build
  npm test -- --run
) || fail "Staged tests/build failed. Running system unchanged."
log "Validated staged revision $REV and existing portal/route; no simulated packet data."
if [[ "$MODE" == --check ]]; then
  log "CHECK PASSED; no MON services or firewall modified."
  SUCCESS=1
  exit 0
fi

BACKUP="$(mktemp -d "$ROOT/mon-stage4-rollback.XXXXXXXX")"
tar -czf "$BACKUP/frontend.tar.gz" --exclude='console-v2/node_modules' -C "$ROOT" console-v2
cp -a "$PORTAL" "$BACKUP/mon-lab-portal.py"
for name in mon_stage4_gate.py mon_stage4_bridge.py; do
  [[ ! -f "$TOOLS/$name" ]] || cp -a "$TOOLS/$name" "$BACKUP/$name"
done
[[ ! -f "$GATE_UNIT" ]] || sudo cp -a "$GATE_UNIT" "$BACKUP/gate-unit"
[[ ! -f "$GATE_BIN" ]] || sudo cp -a "$GATE_BIN" "$BACKUP/gate-binary"
sha256sum "$BACKUP/frontend.tar.gz" "$BACKUP/mon-lab-portal.py" > "$BACKUP/SHA256SUMS"
log "Original operator console and portal saved at $BACKUP"

TOUCHED=1
cp -a "$STAGE/tools/mon-lab-portal.py" "$PORTAL"
cp -a "$STAGE/tools/mon_stage4_gate.py" "$TOOLS/mon_stage4_gate.py"
cp -a "$STAGE/tools/mon_stage4_bridge.py" "$TOOLS/mon_stage4_bridge.py"
# Root must never execute a mutable user-owned script from ~/mon-three.
sudo install -d -o root -g root -m 0755 /usr/local/libexec
sudo install -o root -g root -m 0755 "$STAGE/tools/mon_stage4_gate.py" "$GATE_BIN"

# Root capability is isolated to an AF_UNIX-only process with a hard-coded
# destination/port/source whitelist. The HTTP portal itself gets NO nft rights.
sudo tee "$GATE_UNIT" >/dev/null <<'EOF'
[Unit]
Description=MON training-range temporary source isolation
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/usr/local/libexec
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 /usr/local/libexec/mon-stage4-gate.py
Restart=on-failure
RestartSec=3
RuntimeDirectory=mon-stage4
RuntimeDirectoryMode=0750
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
LockPersonality=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable mon-stage4-gate.service
sudo systemctl restart mon-stage4-gate.service

# Check actual helper socket before deploying a UI that exposes its controls.
READY=0
for iteration in 1 2 3 4 5 6 7 8; do
  if sudo systemctl is-active --quiet mon-stage4-gate.service &&
     python3 - <<'PY' >/dev/null 2>&1
import json,socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.settimeout(2)
s.connect("/run/mon-stage4/control.sock")
s.sendall(b'{"action":"health"}\n')
d=s.recv(4096)
s.close()
assert json.loads(d)["ready"]
PY
  then READY=1; break; fi
  sleep 2
done
[[ "$READY" == 1 ]] || fail "Guarded nft helper cannot start or communicate over its private socket"

# Reuse the already-private PC-2 alerts directory for evidence-based actions.
install -d -m 0700 "$ROOT/alerts"
sudo systemctl restart "$PORTAL_SERVICE"

tar -C "$STAGE/console" --exclude=node_modules --exclude=dist -cf - . |
  tar -C "$WEB" -xf -
(cd "$WEB" && npm run build)
sudo systemctl restart "$FRONTEND_SERVICE"

UP=0
for iteration in 1 2 3 4 5 6 7 8 9 10; do
  if sudo systemctl is-active --quiet "$PORTAL_SERVICE" &&
     sudo systemctl is-active --quiet "$FRONTEND_SERVICE" &&
     curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:8088/portal/health >/dev/null 2>&1 &&
     curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:5174/ >/dev/null 2>&1; then
    UP=1; break
  fi
  sleep 2
done
[[ "$UP" == 1 ]] || fail "Stage 4 portal/frontend failed readiness checks"

# The gateway helper status comes from the kernel, not optimistic UI state.
MON_ROOT="$ROOT" python3 - <<'PY'
import json,os,pathlib,urllib.request
root=pathlib.Path(os.environ["MON_ROOT"])
token=(root/"identity/operator.jwt").read_text().strip()
req=urllib.request.Request(
  "http://127.0.0.1:8088/portal/stage4/mitigation?source=10.77.0.70",
  headers={"Cookie":"mon_session="+token})
with urllib.request.urlopen(req,timeout=6) as response:
  data=json.load(response)
assert data["source"]=="10.77.0.70"
assert data["destination"]=="10.77.0.50"
assert data["port"]==8085
print("[MON STAGE4] Authenticated firewall status reports real kernel state:",data["enforcement"])
PY

tar -czf "$ROOT/mon-stage4-pc5.tar.gz" -C "$STAGE/lab" pc5-training-site
log "PC-5 impact upgrade archive: $ROOT/mon-stage4-pc5.tar.gz"
log "PC-2 Stage 4 ready: http://100.75.116.62:5174/?tenant=mon-lab&site=site-a"
log "No current attacker IP is blocked until an authorized operator explicitly requests it."
log "Only the portal/frontend and the new scoped enforcement helper were changed."
log "Restore point: $BACKUP"
SUCCESS=1
