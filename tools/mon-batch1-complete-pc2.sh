#!/usr/bin/env bash
# PC-2: finish MON Batch 1 without rebuilding WireGuard, routing, PostgreSQL
# or the already working control plane. Checks, restore point, automatic rollback.
set -Eeuo pipefail
umask 077
MODE="${1:---check}"
[[ "$MODE" == "--check" || "$MODE" == "--apply" ]] || { echo "Usage: $0 --check|--apply"; exit 2; }
ROOT=/home/pc-2/mon-three
WEB="$ROOT/console-v2"
CODE=/home/pc-2/mon-three-code
BRANCH=feature/mon-batch1-live-security-alert-20261023
IDS_RULES="$ROOT/suricata/mon-batch1.rules"
ALERT_STORE="$ROOT/alerts"
DROPIN=/etc/systemd/system/mon-three-lab-portal.service.d/mon-batch1-finalize.conf
STAGE=""
BACKUP=""
TOUCHED=0
GOOD=0
log(){ printf '[MON FINALIZE] %s\n' "$*"; }
fail(){ log "STOP: $*"; exit 1; }
restore(){
  status=$?
  trap - EXIT
  if [[ "$TOUCHED" == 1 && "$GOOD" != 1 ]]; then
    log "Upgrade failed. Restoring existing working Batch 1 sources and units."
    [[ ! -f "$BACKUP/portal.py" ]] || cp -a "$BACKUP/portal.py" "$ROOT/tools/mon-lab-portal.py"
    if [[ -f "$BACKUP/ack.py" ]]; then cp -a "$BACKUP/ack.py" "$ROOT/tools/mon_alert_ack.py"; else rm -f "$ROOT/tools/mon_alert_ack.py"; fi
    if [[ -f "$BACKUP/bridge.py" ]]; then cp -a "$BACKUP/bridge.py" "$ROOT/tools/mon_suricata_bridge.py"; fi
    if [[ -f "$BACKUP/rules" ]]; then cp -a "$BACKUP/rules" "$IDS_RULES"; fi
    if [[ -f "$BACKUP/dropin.conf" ]]; then sudo cp -a "$BACKUP/dropin.conf" "$DROPIN"; else sudo rm -f "$DROPIN"; fi
    if [[ -f "$BACKUP/console.tar.gz" ]]; then tar -xzf "$BACKUP/console.tar.gz" -C "$ROOT" || true; fi
    sudo systemctl daemon-reload || true
    sudo systemctl restart mon-suricata-passive.service || true
    sudo systemctl restart mon-three-lab-portal.service || true
    sudo systemctl restart mon-three-console-v2.service || true
    log "Original services restored. Backup retained: $BACKUP"
  fi
  [[ -z "$STAGE" ]] || rm -rf "$STAGE"
  exit "$status"
}
trap restore EXIT
[[ "$(id -un)" == pc-2 ]] || fail "Run as pc-2 on PC-2, not on Windows or PC-5."
[[ -d "$WEB/src" && -d "$CODE/.git" && -f "$ROOT/tools/mon-lab-portal.py" ]] ||
  fail "Original MON V5.3 directory structure not found."
for tool in npm python3 git curl sudo tar suricata; do command -v "$tool" >/dev/null || fail "Missing $tool"; done
[[ -x "$WEB/node_modules/.bin/tsc" ]] || fail "Current frontend dependencies missing."
sudo -v
for service in mon-three-console-v2.service mon-three-lab-portal.service mon-suricata-passive.service; do
  sudo systemctl is-active --quiet "$service" || fail "Current $service is not active. Do not overwrite a broken host."
done
curl -fsS --max-time 5 http://127.0.0.1:8080/health >/dev/null ||
  fail "Existing MON API unavailable; no changes applied."
ip -4 route get 10.77.0.50 | grep -Fq ' dev wg0' ||
  fail "PC-2 is not routing to protected PC-5 through wg0."
log "Existing sensor, portal, API, console and protected route ready."
[[ "$MODE" == --apply ]] || { log "Read-only check complete. Use --apply to install."; GOOD=1; exit 0; }

git -C "$CODE" fetch --no-tags https://github.com/Saitanveesh/1.git "refs/heads/$BRANCH"
REV="$(git -C "$CODE" rev-parse FETCH_HEAD)"
STAGE="$(mktemp -d "$ROOT/batch1-final-stage.XXXXXXXX")"
git -C "$CODE" archive "$REV" console tools lab/pc5-training-site |
  tar -x -C "$STAGE"
ln -s "$WEB/node_modules" "$STAGE/console/node_modules"
python3 -m py_compile "$STAGE/tools/"*.py
python3 -m unittest discover -s "$STAGE/lab/pc5-training-site" -p 'test_*.py'
(cd "$STAGE/console" && npm run build && npm test -- --run)
mkdir -p "$STAGE/ids-test"
sudo suricata -T -c /etc/suricata/suricata.yaml \
  -S "$STAGE/lab/pc5-training-site/mon-training-suricata.rules" \
  -l "$STAGE/ids-test" --init-errors-fatal ||
  fail "Suricata rejected staged lab rules; old production rules unchanged."
log "Staged revision $REV passed build/tests and Suricata -T."

BACKUP="$(mktemp -d "$ROOT/batch1-final-rollback.XXXXXXXX")"
tar -czf "$BACKUP/console.tar.gz" --exclude='console-v2/node_modules' -C "$ROOT" console-v2
cp -a "$ROOT/tools/mon-lab-portal.py" "$BACKUP/portal.py"
[[ ! -f "$ROOT/tools/mon_alert_ack.py" ]] || cp -a "$ROOT/tools/mon_alert_ack.py" "$BACKUP/ack.py"
[[ ! -f "$ROOT/tools/mon_suricata_bridge.py" ]] || cp -a "$ROOT/tools/mon_suricata_bridge.py" "$BACKUP/bridge.py"
[[ ! -f "$IDS_RULES" ]] || cp -a "$IDS_RULES" "$BACKUP/rules"
[[ ! -f "$DROPIN" ]] || sudo cp -a "$DROPIN" "$BACKUP/dropin.conf"
sha256sum "$BACKUP/console.tar.gz" "$BACKUP/portal.py" > "$BACKUP/sha256.txt"
log "Working Batch 1 backup: $BACKUP"

TOUCHED=1
# Leave the existing MON database, JWT, passwords, WireGuard peer keys, target
# routes, nftables and backend API entirely unchanged.
sudo install -d -o pc-2 -g pc-2 -m 0700 "$ALERT_STORE"
cp -a "$STAGE/tools/mon-lab-portal.py" "$ROOT/tools/mon-lab-portal.py"
cp -a "$STAGE/tools/mon_suricata_bridge.py" "$ROOT/tools/mon_suricata_bridge.py"
cp -a "$STAGE/tools/mon_alert_ack.py" "$ROOT/tools/mon_alert_ack.py"
cp -a "$STAGE/lab/pc5-training-site/mon-training-suricata.rules" "$IDS_RULES"

# Previous service has ProtectSystem=strict and allows only localhost, IP and
# AF_PACKET/AF_NETLINK socket families. Keep restrictions, grant writes only
# to the operator review directory. Origins are exact known MON UI ports.
sudo tee "$DROPIN" >/dev/null <<EOF
[Service]
ReadWritePaths=$ALERT_STORE
Environment=MON_ALERT_ACK_PATH=$ALERT_STORE/acknowledged.jsonl
Environment=MON_PORTAL_ALLOWED_ORIGINS=http://100.75.116.62:5174,http://100.75.116.62:5173
EOF
tar -C "$STAGE/console" --exclude=node_modules --exclude=dist -cf - . |
  tar -C "$WEB" -xf -
(cd "$WEB" && npm run build)
sudo systemctl daemon-reload
sudo systemctl restart mon-suricata-passive.service
sudo systemctl restart mon-three-lab-portal.service
sudo systemctl restart mon-three-console-v2.service

OK=0
for i in 1 2 3 4 5 6 7 8 9 10; do
  if sudo systemctl is-active --quiet mon-suricata-passive.service &&
     sudo systemctl is-active --quiet mon-three-lab-portal.service &&
     curl -fsS --max-time 3 http://127.0.0.1:8088/portal/health >/dev/null 2>&1 &&
     curl -fsS --max-time 3 http://127.0.0.1:5174/ >/dev/null 2>&1; then
    OK=1; break
  fi
  sleep 2
done
[[ "$OK" == 1 ]] || fail "Portal/console/IDS did not restart correctly."
curl -fsS --max-time 5 http://127.0.0.1:8080/health >/dev/null ||
  fail "Existing backend unexpectedly unavailable."

# Use existing operator JWT securely; never echo cookie or pass it on argv.
MON_ROOT="$ROOT" python3 - <<'PY'
import json, os, pathlib, urllib.request
root = pathlib.Path(os.environ["MON_ROOT"])
token = (root/"identity"/"operator.jwt").read_text().strip()
def get(path):
    request=urllib.request.Request("http://127.0.0.1:8088"+path,
        headers={"Cookie":"mon_session="+token})
    with urllib.request.urlopen(request,timeout=6) as response:
        return json.load(response)
review=get("/portal/alerts/acknowledged")
assert isinstance(review.get("records"),list),review
flows=get("/portal/flows")
assert flows.get("protected_host_ip")=="10.77.0.50",flows.get("protected_host_ip")
assert flows.get("protected_capture_interface")=="wg0",flows.get("protected_capture_interface")
assert flows.get("protected_route_check")=="MATCHES_CAPTURE_INTERFACE",flows.get("protected_route_check")
assert flows.get("status")=="CAPTURING",flows.get("status")
ids=get("/portal/ids")
assert ids.get("service_state")=="active",ids.get("service_state")
assert ids.get("capture_interface")=="wg0",ids.get("capture_interface")
print("VERIFIED: portal review endpoint, real scoped AF_PACKET sensor, active Suricata EVE source")
PY

tar -czf "$ROOT/mon-batch1-pc5-site-v2.tar.gz" -C "$STAGE/lab" pc5-training-site
log "PC5 upgrade archive: $ROOT/mon-batch1-pc5-site-v2.tar.gz"
log "MON UI: http://100.75.116.62:5174/?tenant=mon-lab&site=site-a"
log "Sensor captures real IP headers only. IDS alerts are signatures, NOT IPS blocks."
log "Restore checkpoint: $BACKUP"
GOOD=1
