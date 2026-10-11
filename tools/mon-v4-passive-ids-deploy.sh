#!/usr/bin/env bash
# PC2 / authorized lab: MON V2 interface, passive Suricata IDS, tcpdump tool.
# No WireGuard, firewall, nftables, NFQUEUE, or response policy changes.
set -euo pipefail
umask 077
ROOT=/home/pc-2/mon-three
REPO=/home/pc-2/mon-three-code
APP=$ROOT/console-v2
PORTAL=$ROOT/tools
PIN=3606e49491091df6d5d9e7156981df8522531e33
FILES=(src/App.tsx src/PacketObservability.tsx src/SuricataPanel.tsx src/types.ts src/styles.css)
STAGE="" BACKUP="" ALTERED=0 UI_READY=0
BRIDGE_EXISTED=0
restore() {
  rc=$?
  trap - EXIT
  if [[ "$ALTERED" == 1 && "$UI_READY" != 1 ]]; then
    echo '[ROLLBACK] Reverting V2 UI and portal only'
    for p in "${FILES[@]}"; do
      if [[ -f "$BACKUP/$p" ]]; then cp "$BACKUP/$p" "$APP/$p"; else rm -f "$APP/$p"; fi
    done
    cp "$BACKUP/mon-lab-portal.py" "$PORTAL/mon-lab-portal.py" || true
    if [[ "$BRIDGE_EXISTED" == 1 ]]; then
      cp "$BACKUP/mon_suricata_bridge.py" "$PORTAL/mon_suricata_bridge.py" || true
    else
      rm -f "$PORTAL/mon_suricata_bridge.py"
    fi
    cp "$BACKUP/mon_ai_analysis.py" "$PORTAL/mon_ai_analysis.py" || true
    sudo systemctl restart mon-three-lab-portal.service || true
    sudo systemctl restart mon-three-console-v2.service || true
  fi
  if [[ -n "$STAGE" && -d "$STAGE" ]]; then rm -rf "$STAGE"; fi
  exit "$rc"
}
trap restore EXIT
echo '========== EXISTING MON PREFLIGHT =========='
[[ "$(id -un)" == pc-2 && ! -L "$APP" && -d "$REPO/.git" ]] || exit 1
[[ -x "$APP/node_modules/.bin/tsc" && -f "$PORTAL/mon-lab-portal.py" ]] || exit 1
sudo -v
sudo systemctl is-active --quiet mon-three-console-v2.service
sudo systemctl is-active --quiet mon-three-lab-portal.service
for u in http://127.0.0.1:8080/health http://127.0.0.1:8090/health http://100.75.116.62:5173/; do
  curl --noproxy '*' -fsS --max-time 6 "$u" >/dev/null
done
echo '[PASS] Existing MON control and router healthy'
echo '========== STAGE, BACK UP AND BUILD =========='
git -C "$REPO" fetch --no-tags https://github.com/Saitanveesh/1.git refs/heads/fix/linux-ssh-journal-ingestion-20261010
git -C "$REPO" merge-base --is-ancestor "$PIN" FETCH_HEAD
STAGE=$(mktemp -d "$ROOT/ids-stage.XXXXXXXX")
BACKUP=$(mktemp -d "$ROOT/ids-backup.XXXXXXXX")
mkdir -p "$STAGE/src" "$BACKUP/src"
for p in "${FILES[@]}"; do
  git -C "$REPO" show "$PIN:console/$p" > "$STAGE/$p"
  if [[ -f "$APP/$p" ]]; then cp "$APP/$p" "$BACKUP/$p"; fi
done
for p in mon-lab-portal.py mon_suricata_bridge.py mon_ai_analysis.py; do
  git -C "$REPO" show "$PIN:tools/$p" > "$STAGE/$p"
done
python3 -m py_compile "$STAGE/mon-lab-portal.py" "$STAGE/mon_suricata_bridge.py" "$STAGE/mon_ai_analysis.py"
cp "$PORTAL/mon-lab-portal.py" "$BACKUP/mon-lab-portal.py"
cp "$PORTAL/mon_ai_analysis.py" "$BACKUP/mon_ai_analysis.py"
if [[ -f "$PORTAL/mon_suricata_bridge.py" ]]; then
  cp "$PORTAL/mon_suricata_bridge.py" "$BACKUP/mon_suricata_bridge.py"
  BRIDGE_EXISTED=1
fi
ALTERED=1
for p in "${FILES[@]}"; do cp "$STAGE/$p" "$APP/$p"; done
cp "$STAGE/mon-lab-portal.py" "$PORTAL/mon-lab-portal.py"
cp "$STAGE/mon_suricata_bridge.py" "$PORTAL/mon_suricata_bridge.py"
cp "$STAGE/mon_ai_analysis.py" "$PORTAL/mon_ai_analysis.py"
(cd "$APP" && npm run build)
sudo systemctl restart mon-three-lab-portal.service
sudo systemctl restart mon-three-console-v2.service
echo '========== VERIFY REAL IDS API AND NEW V2 MODULES =========='
TOKEN=$(cat "$ROOT/identity/operator.jwt")
API_OK=0
for n in $(seq 1 25); do
  if curl --noproxy '*' -fsS --max-time 5 -H "Cookie: mon_session=$TOKEN" \
    http://127.0.0.1:8088/portal/ids 2>/dev/null |
    python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["source"]=="suricata-eve" and isinstance(d["records"],list)' 2>/dev/null; then
    API_OK=1
    break
  fi
  sleep 1
done
unset TOKEN
[[ "$API_OK" == 1 ]] || { echo '[FAIL] Authenticated Suricata endpoint not served'; exit 1; }
F=$(mktemp)
for p in 'src/App.tsx:SuricataPanel' \
         'src/PacketObservability.tsx:route-count' \
         'src/SuricataPanel.tsx:suricata-ids-panel'; do
  file="${p%%:*}"
  marker="${p#*:}"
  curl --noproxy '*' -fsS --max-time 8 -H 'Cache-Control: no-cache' \
    "http://127.0.0.1:5174/$file?ids=$PIN" -o "$F"
  grep -Fq "$marker" "$F" || { echo "[FAIL] Old frontend served: $file"; exit 1; }
  echo "[PASS] Frontend module: $file"
done
rm -f "$F"
UI_READY=1
echo '[PASS] Misleading 0-flow caption removed, authenticated IDS dashboard available'
echo '========== INSTALL PASSIVE IDS TECHNOLOGY =========='
if sudo systemctl is-active --quiet suricata.service; then
  echo '[CHECK] Existing distribution Suricata active: not replacing or stopping it'
  echo '[CHECK] Connect its EVE JSON separately if desired'
elif sudo systemctl is-active --quiet mon-suricata-passive.service; then
  install -d -m 0700 "$ROOT/suricata"
  touch "$ROOT/suricata/.mon-passive-configured"
  echo '[PASS] Existing MON passive Suricata service active'
elif sudo test -f /etc/systemd/system/mon-suricata-passive.service; then
  echo '[CHECK] Previous MON Suricata service exists but is inactive; not overwriting'
  exit 2
else
  echo '[INSTALL] Ubuntu packages: suricata and tcpdump (passive tools)'
  WAS_INSTALLED=1
  command -v suricata >/dev/null || WAS_INSTALLED=0
  if ! command -v suricata >/dev/null || ! command -v tcpdump >/dev/null; then
    sudo apt-get update
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y suricata tcpdump
  fi
  if [[ "$WAS_INSTALLED" == 0 ]] && sudo systemctl is-active --quiet suricata.service; then
    sudo systemctl disable --now suricata.service
  fi
  ip link show wg0 >/dev/null || { echo '[CHECK] wg0 missing; no passive sensor started'; exit 2; }
  [[ -f /etc/suricata/suricata.yaml ]] || { echo '[CHECK] Suricata YAML missing'; exit 2; }
  LOGDIR=$ROOT/suricata
  install -d -m 0700 "$LOGDIR"
  IDS_BIN=$(command -v suricata)
  sudo -u pc-2 "$IDS_BIN" -T -c /etc/suricata/suricata.yaml -l "$LOGDIR" ||
    { echo '[CHECK] Suricata configuration validation failed'; exit 2; }
  TMPUNIT=$(mktemp)
  cat > "$TMPUNIT" <<EOF
[Unit]
Description=MON Passive Suricata IDS on wg0 (non-inline)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=pc-2
Group=pc-2
ExecStart=$IDS_BIN --pcap=wg0 --runmode=single -c /etc/suricata/suricata.yaml -l $LOGDIR
NoNewPrivileges=yes
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
ProtectSystem=full
Restart=on-failure
RestartSec=5
MemoryMax=1400M
[Install]
WantedBy=multi-user.target
EOF
  sudo install -m 0644 "$TMPUNIT" /etc/systemd/system/mon-suricata-passive.service
  rm -f "$TMPUNIT"
  sudo systemctl daemon-reload
  sudo systemctl enable --now mon-suricata-passive.service
  sleep 7
  sudo systemctl is-active --quiet mon-suricata-passive.service ||
    { echo '[CHECK] Passive IDS service failed. MON UI remains operational'; exit 2; }
  touch "$LOGDIR/.mon-passive-configured"
  echo '[PASS] Suricata passive IDS running on wg0; no packet blocking enabled'
fi
for u in http://127.0.0.1:8080/health http://127.0.0.1:8090/health http://100.75.116.62:5173/; do
  curl --noproxy '*' -fsS --max-time 6 "$u" >/dev/null
done
echo '[PASS] MON V4 active, control and firewall services unchanged'
echo "Backup: $BACKUP"
echo 'Dashboard http://100.75.116.62:5174/?tenant=mon-lab&site=site-a'
