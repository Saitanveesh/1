#!/usr/bin/env bash
# MON V5.3 targeted console/dashboard update. Leave firewall, WireGuard, identities and backend untouched.
set -euo pipefail
umask 077
ROOT=/home/pc-2/mon-three
CODE=/home/pc-2/mon-three-code
WEB=$ROOT/console-v2
MONITOR=$ROOT/monitoring
FILES="src/Incident3D.tsx src/IncidentFlowMap.tsx src/IncidentFlowMap.css src/IncidentWorkspace.css"
DASH=grafana-provisioning/dashboards/mon/mon-network.json
STAGE="" BACKUP="" CHANGED=0 SUCCESS=0 DASH_CHANGED=0
restore() {
  code=$?
  trap - EXIT
  if [[ "$CHANGED" == 1 && "$SUCCESS" != 1 ]]; then
    echo '[ROLLBACK] Restoring previously working frontend'
    for item in $FILES; do
      if [[ -f "$BACKUP/web/$item" ]]; then cp "$BACKUP/web/$item" "$WEB/$item" || true
      else rm -f "$WEB/$item" || true; fi
    done
    if [[ -d "$BACKUP/dist" ]]; then rm -rf "$WEB/dist"; cp -a "$BACKUP/dist" "$WEB/dist" || true; fi
    if [[ "$DASH_CHANGED" == 1 ]]; then
      if [[ -f "$BACKUP/monitor/$DASH" ]]; then cp "$BACKUP/monitor/$DASH" "$MONITOR/$DASH" || true
      else rm -f "$MONITOR/$DASH" || true; fi
    fi
    sudo systemctl restart mon-three-console-v2.service || true
  fi
  if [[ -n "$STAGE" && -d "$STAGE" ]]; then rm -rf "$STAGE"; fi
  echo "MON V5.3 exit code: $code"
  exit "$code"
}
trap restore EXIT
echo '========== MON V5.3 PRECHECK =========='
[[ "$(id -un)" == pc-2 && -d "$CODE/.git" && -f "$WEB/src/Incident3D.tsx" &&
  -x "$WEB/node_modules/.bin/tsc" && ! -L "$WEB" ]] || {
  echo '[FAIL] Run on PC2 as pc-2 with existing V5 console'; exit 1;
}
sudo -v
sudo systemctl is-active --quiet mon-three-console-v2.service
sudo systemctl is-active --quiet mon-three-lab-portal.service
for url in http://127.0.0.1:8080/health http://127.0.0.1:8090/health http://127.0.0.1:5174/; do
  curl --noproxy '*' -fsS --max-time 8 "$url" >/dev/null
done
echo '[PASS] Existing core and console services healthy'
git -C "$CODE" fetch --no-tags https://github.com/Saitanveesh/1.git refs/heads/fix/mon-v5-3-readable-flow-always-on
REV=$(git -C "$CODE" rev-parse FETCH_HEAD)
git -C "$CODE" merge-base --is-ancestor 61526b4329786afa4c9f2a7ed630cc0491615061 "$REV"
echo "Source revision: $REV"
STAGE=$(mktemp -d "$ROOT/v5-3-stage.XXXXXXXX")
BACKUP=$(mktemp -d "$ROOT/v5-3-restore.XXXXXXXX")
mkdir -p "$STAGE/web/src" "$BACKUP/web/src" "$STAGE/monitor/$(dirname "$DASH")" "$BACKUP/monitor/$(dirname "$DASH")"
for item in $FILES; do
  git -C "$CODE" show "$REV:console/$item" > "$STAGE/web/$item"
  if [[ -f "$WEB/$item" ]]; then cp -a "$WEB/$item" "$BACKUP/web/$item"; fi
done
git -C "$CODE" show "$REV:monitoring/$DASH" > "$STAGE/monitor/$DASH"
python3 -m json.tool "$STAGE/monitor/$DASH" >/dev/null
if [[ -f "$MONITOR/$DASH" ]]; then cp -a "$MONITOR/$DASH" "$BACKUP/monitor/$DASH"; fi
if [[ -d "$WEB/dist" ]]; then cp -a "$WEB/dist" "$BACKUP/dist"; fi
echo "Frontend restore point: $BACKUP"
echo '========== BUILD AND VALIDATE =========='
CHANGED=1
for item in $FILES; do cp "$STAGE/web/$item" "$WEB/$item"; done
(cd "$WEB" && npm run build)
sudo systemctl restart mon-three-console-v2.service
READY=0
for n in $(seq 1 25); do
  if curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:5174/ >/dev/null 2>&1; then READY=1; break; fi
  sleep 1
done
[[ "$READY" == 1 ]] || { echo '[FAIL] Console did not restart'; exit 1; }
TMP=$(mktemp)
for spec in 'src/Incident3D.tsx:IncidentFlowMap' 'src/IncidentFlowMap.tsx:mon-flow-workspace' 'src/IncidentWorkspace.css:V5.3 readability'; do
  p=$(cut -d: -f1 <<< "$spec")
  marker=$(cut -d: -f2 <<< "$spec")
  curl --noproxy '*' -fsS --max-time 8 -H 'Cache-Control: no-cache' "http://127.0.0.1:5174/$p?revision=$REV" -o "$TMP"
  grep -Fq "$marker" "$TMP" || { echo "[FAIL] Wrong module served: $p"; rm -f "$TMP"; exit 1; }
done
rm -f "$TMP"
for url in http://127.0.0.1:8080/health http://127.0.0.1:8090/health; do
  curl --noproxy '*' -fsS --max-time 8 "$url" >/dev/null
done
echo '[PASS] Frontend updated; backend and site controller healthy'
echo '========== ALWAYS-ON CAPTURE AND GRAFANA =========='
sudo systemctl enable mon-three-lab-portal.service mon-three-console-v2.service >/dev/null
for service in mon-three-lab-portal.service mon-three-console-v2.service; do
  echo "BOOT SERVICE: $service $(sudo systemctl is-enabled "$service")"
done
if [[ -f "$MONITOR/$DASH" ]]; then
  DASH_CHANGED=1
  cp "$STAGE/monitor/$DASH" "$MONITOR/$DASH"
  echo '[PASS] Grafana adds 5-minute traffic baseline and Prometheus scrape health'
else
  echo '[CHECK] No provisioned Grafana dashboard on PC2; skipped optional dashboard update'
fi
if command -v docker >/dev/null 2>&1; then
  if sudo systemctl is-active --quiet docker.service; then
    sudo systemctl enable docker.service >/dev/null
  fi
  if sudo systemctl is-enabled docker.service >/dev/null 2>&1; then echo 'DOCKER BOOT: ENABLED'
  else echo '[CHECK] Docker boot service not enabled or not managed by docker.service'; fi
fi
if curl --noproxy '*' -fsS --max-time 6 http://100.75.116.62:3000/api/health 2>/dev/null |
  python3 -c 'import json,sys; assert json.load(sys.stdin).get("database")=="ok"' >/dev/null 2>&1; then
  echo 'GRAFANA STATUS: HEALTHY'
else echo 'GRAFANA STATUS: UNAVAILABLE (MON backend unchanged)'; fi
if curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:5174/portal/health 2>/dev/null |
  python3 -c 'import json,sys; assert json.load(sys.stdin).get("capture")=="CAPTURING"' >/dev/null 2>&1; then
  echo 'CAPTURE STATUS: CAPTURING'
else echo 'CAPTURE STATUS: NOT VERIFIED — inspect the portal sensor'; fi
SUCCESS=1
echo '[PASS] MON V5.3 complete. Only traffic visible to PC2 can be monitored.'
echo 'OPEN http://100.75.116.62:5174/?tenant=mon-lab&site=site-a'
echo 'In Chrome press Ctrl+0 and Ctrl+Shift+R'
