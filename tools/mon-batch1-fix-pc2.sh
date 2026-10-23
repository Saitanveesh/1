#!/usr/bin/env bash
# PC-2 only. Deploy MON Batch 1 with protected backup and automatic rollback.
# Does not rewrite WireGuard keys, configure an invented gateway IP,
# flush nftables, create attack events, or delete the existing database.
set -Eeuo pipefail
umask 077
MODE=--check
if [[ $# -gt 0 ]]; then MODE="$1"; fi
[[ "$MODE" == --check || "$MODE" == --apply ]] || { echo 'Use --check or --apply'; exit 2; }
ROOT=/home/pc-2/mon-three
CODE=/home/pc-2/mon-three-code
WEB="$ROOT/console-v2"
SITE=10.77.0.50
PEER=10.77.0.60
REF=feature/mon-batch1-live-security-alert-20261023
DROPIN=/etc/systemd/system/mon-three-lab-portal.service.d/mon-batch1.conf
ENVFILE="$ROOT/mon-batch1.env"
IDSUNIT=/etc/systemd/system/mon-suricata-passive.service
APIUNIT=/etc/systemd/system/mon-three-control-plane.service
ROUTEUNIT=/etc/systemd/system/mon-batch1-overlay-routes.service
RULE="$ROOT/suricata/mon-batch1.rules"
IPBIN="$(command -v ip)"
SURIBIN="$(command -v suricata)"
BACKUP=""
STAGE=""
CHANGED=0
SUCCESS=0
ADDED50=0
ADDED60=0
log(){ printf '[MON BATCH1] %s\n' "$*"; }
fail(){ log "FAIL: $*"; exit 1; }
restore(){
  code=$?
  trap - EXIT
  if [[ "$CHANGED" == 1 && "$SUCCESS" != 1 && -n "$BACKUP" ]]; then
    log "Deploy failed; restoring original frontend, portal and unit configuration."
    sudo systemctl disable --now mon-suricata-passive.service >/dev/null 2>&1 || true
    sudo systemctl disable --now mon-batch1-overlay-routes.service >/dev/null 2>&1 || true
    cp -a "$BACKUP/portal.py" "$ROOT/tools/mon-lab-portal.py"
    if [[ -f "$BACKUP/bridge.py" ]]; then cp -a "$BACKUP/bridge.py" "$ROOT/tools/mon_suricata_bridge.py"; else rm -f "$ROOT/tools/mon_suricata_bridge.py"; fi
    tar -xzf "$BACKUP/console.tar.gz" -C "$ROOT" || true
    for spec in "dropin.conf:$DROPIN" "sensor.unit:$IDSUNIT" "api.unit:$APIUNIT" "route.unit:$ROUTEUNIT" "sensor.env:$ENVFILE" "sensor.rules:$RULE"; do
      name="$(printf '%s' "$spec" | cut -d: -f1)"
      dest="$(printf '%s' "$spec" | cut -d: -f2-)"
      if [[ -f "$BACKUP/$name" ]]; then sudo cp -a "$BACKUP/$name" "$dest"; else sudo rm -f "$dest"; fi
    done
    if [[ "$ADDED50" == 1 ]]; then sudo ip route del "$SITE/32" dev wg0 2>/dev/null || true; fi
    if [[ "$ADDED60" == 1 ]]; then sudo ip route del "$PEER/32" dev wg0 2>/dev/null || true; fi
    sudo systemctl daemon-reload || true
    sudo systemctl restart mon-three-lab-portal.service || true
    sudo systemctl restart mon-three-console-v2.service || true
    log "Original MON restored. Files retained: $BACKUP"
  fi
  [[ -z "$STAGE" ]] || rm -rf "$STAGE"
  exit "$code"
}
trap restore EXIT

[[ "$(id -un)" == "pc-2" ]] || fail "Execute only as pc-2 on PC-2"
[[ -d "$CODE/.git" && -d "$WEB/src" && -f "$ROOT/identity/operator.jwt" ]] || fail "Original V5.3 installation missing"
for prog in git tar npm python3 curl docker sudo systemctl wg suricata; do command -v "$prog" >/dev/null || fail "Missing $prog"; done
[[ -x "$WEB/node_modules/.bin/tsc" ]] || fail "Original console dependencies missing"
[[ -f /etc/suricata/suricata.yaml ]] || fail "Suricata YAML missing"
sudo -v
ip link show wg0 >/dev/null || fail "wg0 missing"
sudo wg show wg0 allowed-ips | grep -Fq "$SITE/32" || fail "PC5 peer missing on wg0"
sudo wg show wg0 allowed-ips | grep -Fq "$PEER/32" || fail "PC6 peer missing on wg0"
[[ "$(sysctl -n net.ipv4.ip_forward)" == 1 ]] || fail "ip_forward disabled"
sudo docker exec mon-three-postgres pg_isready -U mon -d mon >/dev/null || fail "Original PostgreSQL unavailable"
sudo systemctl is-active --quiet mon-three-console-v2.service || fail "Console currently down"
sudo systemctl is-active --quiet mon-three-lab-portal.service || fail "Portal currently down"
log "Current PC2 route to PC5: $(ip -4 route get "$SITE" | head -1)"
log "Current PC2 route to PC6: $(ip -4 route get "$PEER" | head -1)"
log "Distributor Suricata: $(systemctl is-active suricata.service || true)"
log "MON passive IDS: $(systemctl is-active mon-suricata-passive.service || true)"
if [[ "$MODE" == --check ]]; then log "Read-only preflight complete; no changes applied."; SUCCESS=1; exit 0; fi
if sudo systemctl is-active --quiet suricata.service; then fail "An existing active Suricata must not be replaced"; fi

git -C "$CODE" fetch --no-tags https://github.com/Saitanveesh/1.git "refs/heads/$REF"
REV="$(git -C "$CODE" rev-parse FETCH_HEAD)"
STAGE="$(mktemp -d "$ROOT/batch1-stage.XXXXXXXX")"
git -C "$CODE" archive "$REV" console tools lab | tar -x -C "$STAGE"
ln -s "$WEB/node_modules" "$STAGE/console/node_modules"
python3 -m py_compile "$STAGE/tools/mon-lab-portal.py" "$STAGE/tools/mon_suricata_bridge.py"
(cd "$STAGE/console" && npm run build && npm test -- --run)
mkdir -p "$STAGE/suri-logs"
sudo "$SURIBIN" -T -c /etc/suricata/suricata.yaml -S "$STAGE/lab/pc5-training-site/mon-training-suricata.rules" -l "$STAGE/suri-logs" --init-errors-fatal || fail "Suricata config/rule invalid"
log "Validated source $REV, frontend tests and Suricata rule"
# Validate route introspection using the same PC2 Python interpreter before
# touching a running service. The previous release failed at this precise
# point because JSON iproute2 parsing returned UNVERIFIED.
MON_ROUTE_STAGE="$STAGE/tools/mon-lab-portal.py" \
MON_PROTECTED_HOST_IP="$SITE" \
MON_PROTECTED_CAPTURE_INTERFACE=wg0 python3 - <<'PY'
import importlib.util, os
module_path = os.environ["MON_ROUTE_STAGE"]
spec = importlib.util.spec_from_file_location("mon_batch1_route_preflight", module_path)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)
result = module.inspect_protected_route()
print("PREDEPLOY ROUTE CHECK:", result, flush=True)
assert result["protected_route_check"] == "MATCHES_CAPTURE_INTERFACE", result
PY

BACKUP="$(mktemp -d "$ROOT/batch1-rollback.XXXXXXXX")"
tar -czf "$BACKUP/console.tar.gz" --exclude='console-v2/node_modules' -C "$ROOT" console-v2
cp -a "$ROOT/tools/mon-lab-portal.py" "$BACKUP/portal.py"
[[ ! -f "$ROOT/tools/mon_suricata_bridge.py" ]] || cp -a "$ROOT/tools/mon_suricata_bridge.py" "$BACKUP/bridge.py"
for spec in "dropin.conf:$DROPIN" "sensor.unit:$IDSUNIT" "api.unit:$APIUNIT" "route.unit:$ROUTEUNIT" "sensor.env:$ENVFILE" "sensor.rules:$RULE"; do
  name="$(printf '%s' "$spec" | cut -d: -f1)"
  source_path="$(printf '%s' "$spec" | cut -d: -f2-)"
  [[ ! -f "$source_path" ]] || sudo cp -a "$source_path" "$BACKUP/$name"
done
sudo systemctl cat mon-three-console-v2.service > "$BACKUP/console.service.txt"
sudo systemctl cat mon-three-lab-portal.service > "$BACKUP/portal.service.txt"
ip -4 route show table all > "$BACKUP/routes.txt"
sudo docker exec mon-three-postgres pg_dump -U mon -d mon -Fc > "$BACKUP/database.dump"
[[ -s "$BACKUP/database.dump" ]] || fail "Database backup failed"
sha256sum "$BACKUP/database.dump" "$BACKUP/console.tar.gz" > "$BACKUP/checksums.sha256"
log "Verified local source and database backup: $BACKUP"

CHANGED=1
route_peer(){
  ip_address="$1"
  prior="$(ip -4 route show exact "$ip_address/32")"
  [[ -z "$prior" || "$prior" == *" dev wg0"* ]] || fail "Conflicting explicit /32: $prior"
  if [[ -z "$prior" ]]; then
    sudo ip route add "$ip_address/32" dev wg0
    if [[ "$ip_address" == "$SITE" ]]; then ADDED50=1; else ADDED60=1; fi
  fi
}
route_peer "$SITE"
route_peer "$PEER"
ip -4 route get "$SITE" | grep -Fq ' dev wg0' || fail "PC5 kernel route not selecting wg0"
ip -4 route get "$PEER" | grep -Fq ' dev wg0' || fail "PC6 kernel route not selecting wg0"
mkdir -p "$ROOT/suricata"
cp "$STAGE/lab/pc5-training-site/mon-training-suricata.rules" "$RULE"
chmod 0640 "$RULE"
cp "$STAGE/tools/mon-lab-portal.py" "$ROOT/tools/mon-lab-portal.py"
cp "$STAGE/tools/mon_suricata_bridge.py" "$ROOT/tools/mon_suricata_bridge.py"
cat > "$ENVFILE" <<EOF
MON_PORTAL_INTERFACE=wg0
MON_PROTECTED_HOST_IP=$SITE
MON_PROTECTED_CAPTURE_INTERFACE=wg0
MON_SURICATA_EVE_PATH=$ROOT/suricata/eve.json
MON_SURICATA_CAPTURE_INTERFACE=wg0
MON_SURICATA_UNIT=mon-suricata-passive.service
EOF
chmod 0600 "$ENVFILE"
sudo mkdir -p /etc/systemd/system/mon-three-lab-portal.service.d
printf '[Unit]\nAfter=mon-batch1-overlay-routes.service\nWants=mon-batch1-overlay-routes.service\n[Service]\nEnvironmentFile=%s\n' "$ENVFILE" | sudo tee "$DROPIN" >/dev/null
sudo tee "$IDSUNIT" >/dev/null <<EOF
[Unit]
Description=MON passive Suricata IDS on wg0 (non-inline)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=pc-2
Group=pc-2
WorkingDirectory=$ROOT
ExecStart=$SURIBIN --pcap=wg0 --runmode=single -k none -c /etc/suricata/suricata.yaml -S $RULE -l $ROOT/suricata
NoNewPrivileges=yes
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
ProtectSystem=full
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
sudo tee "$ROUTEUNIT" >/dev/null <<EOF
[Unit]
Description=MON known overlay peer host routes (no nftables changes)
After=network-online.target wg-quick@wg0.service
Wants=network-online.target
[Service]
Type=oneshot
Restart=on-failure
RestartSec=10
ExecStart=/usr/bin/test -d /sys/class/net/wg0
ExecStart=$IPBIN route replace $SITE/32 dev wg0
ExecStart=$IPBIN route replace $PEER/32 dev wg0
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
tar -C "$STAGE/console" --exclude=node_modules --exclude=dist -cf - . | tar -C "$WEB" -xf -
(cd "$WEB" && npm run build)
sudo systemctl daemon-reload
sudo systemctl enable mon-batch1-overlay-routes.service mon-suricata-passive.service >/dev/null
sudo systemctl restart mon-suricata-passive.service
sudo systemctl restart mon-three-lab-portal.service
sudo systemctl restart mon-three-console-v2.service
for attempt in 1 2 3 4 5 6 7 8; do
  if sudo systemctl is-active --quiet mon-suricata-passive.service &&
     curl -fsS --max-time 3 http://127.0.0.1:8088/portal/health >/dev/null &&
     curl -fsS --max-time 3 http://127.0.0.1:5174/ >/dev/null; then break; fi
  sleep 2
done
sudo systemctl is-active --quiet mon-suricata-passive.service || fail "Passive IDS failed startup"
curl -fsS --max-time 4 http://127.0.0.1:8088/portal/health | python3 -c 'import sys,json; j=json.load(sys.stdin); assert j.get("capture")=="CAPTURING",j' || fail "Portal sensor offline"
curl -fsS --max-time 4 http://127.0.0.1:5174/ >/dev/null || fail "Frontend offline"

ROOT_FOR_CHECK="$ROOT" python3 - <<'PY'
import json,os,pathlib,urllib.request
root=pathlib.Path(os.environ["ROOT_FOR_CHECK"])
token=(root/"identity/operator.jwt").read_text().strip()
req=urllib.request.Request("http://127.0.0.1:8088/portal/flows",headers={"Cookie":"mon_session="+token})
with urllib.request.urlopen(req,timeout=5) as r: data=json.load(r)
assert data.get("protected_host_ip")=="10.77.0.50",data.get("protected_host_ip")
assert data.get("protected_route_check")=="MATCHES_CAPTURE_INTERFACE", {
    "status":data.get("protected_route_check"),
    "interface":data.get("protected_route_interface"),
    "reason":data.get("protected_route_reason"),
}
assert data.get("protected_capture_interface")=="wg0",data.get("protected_capture_interface")
print("Target route and real PC5 capture selection VERIFIED")
PY

if [[ ! -f "$APIUNIT" ]]; then
  sudo tee "$APIUNIT" >/dev/null <<EOF
[Unit]
Description=MON original control-plane API on PC2
After=network-online.target docker.service
Wants=network-online.target
[Service]
Type=simple
User=pc-2
Group=pc-2
WorkingDirectory=$CODE
EnvironmentFile=$ROOT/control.env
Environment=PYTHONPATH=$CODE/src
ExecStart=$CODE/.venv/bin/uvicorn mon.api:app --host 127.0.0.1 --port 8080
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
fi
sudo systemctl enable mon-three-control-plane.service >/dev/null
if ! curl -fsS --max-time 3 http://127.0.0.1:8080/health >/dev/null; then
  sudo systemctl start mon-three-control-plane.service
  sleep 3
  curl -fsS --max-time 4 http://127.0.0.1:8080/health >/dev/null || fail "MON API unavailable"
else
  log "Existing Uvicorn already serves port 8080; not terminating it."
fi
if ! sudo systemctl is-active --quiet suricata.service; then
  sudo systemctl disable suricata.service >/dev/null 2>&1 || true
  sudo systemctl reset-failed suricata.service || true
fi
tar -czf "$ROOT/mon-batch1-pc5-site.tar.gz" -C "$STAGE/lab" pc5-training-site
log "PC-5 training archive: $ROOT/mon-batch1-pc5-site.tar.gz"
log "Live frontend: http://100.75.116.62:5174/?tenant=mon-lab&site=site-a"
log "Actual PC5 frames and alerts appear only when traffic crosses wg0."
log "Suricata is passive IDS, NOT confirmed IPS. Forwarding requires PC6/PC5 test."
log "Restore checkpoint: $BACKUP"
SUCCESS=1
