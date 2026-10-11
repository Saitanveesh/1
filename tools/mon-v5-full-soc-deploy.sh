#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT=/home/pc-2/mon-three
CODE=/home/pc-2/mon-three-code
WEB=$ROOT/console-v2
LOCAL=$ROOT/tools
PIN=76face5d11377d66b10b3dedcea4622518fa7073
WEBFILES="src/App.tsx src/IncidentDetail.tsx src/Incident3D.tsx src/Incident3D.css src/SocGauges.tsx src/SocGauges.css src/PacketObservability.tsx src/SuricataPanel.tsx src/AiAnalysis.tsx src/AiAnalysis.css src/types.ts src/styles.css"
TOOLFILES="mon-lab-portal.py mon_ai_analysis.py mon_suricata_bridge.py mon-incident-pcap.sh"
STAGE="" BACKUP="" CHANGED=0 SUCCESS=0
restore() {
  rc=$?
  trap - EXIT
  if [[ "$CHANGED" == 1 && "$SUCCESS" != 1 ]]; then
    echo '[ROLLBACK] Restoring previous MON V2 deployment'
    for p in $WEBFILES; do
      if [[ -f "$BACKUP/web/$p" ]]; then cp "$BACKUP/web/$p" "$WEB/$p"; else rm -f "$WEB/$p"; fi
    done
    for p in $TOOLFILES; do
      if [[ -f "$BACKUP/tools/$p" ]]; then cp "$BACKUP/tools/$p" "$LOCAL/$p"; else rm -f "$LOCAL/$p"; fi
    done
    if [[ -d "$BACKUP/dist" ]]; then
      rm -rf "$WEB/dist"
      cp -a "$BACKUP/dist" "$WEB/dist"
    fi
    sudo systemctl restart mon-three-lab-portal.service || true
    sudo systemctl restart mon-three-console-v2.service || true
  fi
  if [[ -n "$STAGE" && -d "$STAGE" ]]; then rm -rf "$STAGE"; fi
  exit "$rc"
}
trap restore EXIT
echo '========== MON V5 PREFLIGHT =========='
[[ "$(id -un)" == pc-2 && ! -L "$WEB" && -d "$CODE/.git" ]] || exit 1
[[ -x "$WEB/node_modules/.bin/tsc" && -f "$LOCAL/mon-lab-portal.py" ]] || exit 1
sudo -v
sudo systemctl is-active --quiet mon-three-console-v2.service
sudo systemctl is-active --quiet mon-three-lab-portal.service
for u in http://127.0.0.1:8080/health http://127.0.0.1:8090/health http://100.75.116.62:5173/; do
  curl --noproxy '*' -fsS --max-time 6 "$u" >/dev/null
done
echo '[PASS] MON core unaffected'
git -C "$CODE" fetch --no-tags https://github.com/Saitanveesh/1.git refs/heads/fix/linux-ssh-journal-ingestion-20261010
git -C "$CODE" merge-base --is-ancestor "$PIN" FETCH_HEAD
STAGE=$(mktemp -d "$ROOT/v5-stage.XXXXXXXX")
BACKUP=$(mktemp -d "$ROOT/v5-backup.XXXXXXXX")
mkdir -p "$STAGE/web/src" "$STAGE/tools" "$BACKUP/web/src" "$BACKUP/tools"
for p in $WEBFILES; do
  git -C "$CODE" show "$PIN:console/$p" > "$STAGE/web/$p"
  if [[ -f "$WEB/$p" ]]; then cp "$WEB/$p" "$BACKUP/web/$p"; fi
done
for p in $TOOLFILES; do
  git -C "$CODE" show "$PIN:tools/$p" > "$STAGE/tools/$p"
  if [[ -f "$LOCAL/$p" ]]; then cp "$LOCAL/$p" "$BACKUP/tools/$p"; fi
done
python3 -m py_compile "$STAGE/tools/mon-lab-portal.py" "$STAGE/tools/mon_ai_analysis.py" "$STAGE/tools/mon_suricata_bridge.py"
bash -n "$STAGE/tools/mon-incident-pcap.sh"
if [[ -d "$WEB/dist" ]]; then cp -a "$WEB/dist" "$BACKUP/dist"; fi
CHANGED=1
echo '========== BUILD MON V5 =========='
for p in $WEBFILES; do cp "$STAGE/web/$p" "$WEB/$p"; done
for p in $TOOLFILES; do cp "$STAGE/tools/$p" "$LOCAL/$p"; done
chmod 0700 "$LOCAL/mon-incident-pcap.sh"
(cd "$WEB" && npm run build)
sudo systemctl restart mon-three-lab-portal.service
sudo systemctl restart mon-three-console-v2.service
READY=0
for n in $(seq 1 25); do
  if curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:5174/portal/health 2>/dev/null |
    python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["state"]=="READY" and d["capture"]=="CAPTURING"' 2>/dev/null; then
    READY=1
    break
  fi
  sleep 1
done
[[ "$READY" == 1 ]] || { echo '[FAIL] Capture portal did not restart'; exit 1; }
F=$(mktemp)
for item in 'src/App.tsx:Investigation3D' 'src/Incident3D.tsx:incident-3d-scene' 'src/SocGauges.tsx:soc-gauges' 'src/IncidentDetail.tsx:incident-chronology'; do
  IFS=: read -r path marker <<< "$item"
  curl --noproxy '*' -fsS --max-time 8 -H 'Cache-Control: no-cache' "http://127.0.0.1:5174/$path?revision=$PIN" -o "$F"
  grep -Fq "$marker" "$F" || { echo "[FAIL] Wrong V2 module: $path"; exit 1; }
  echo "[PASS] V2 module $path"
done
rm -f "$F"
for u in http://127.0.0.1:8080/health http://127.0.0.1:8090/health http://100.75.116.62:5173/; do
  curl --noproxy '*' -fsS --max-time 6 "$u" >/dev/null
done
SUCCESS=1
echo '[PASS] 3D Investigation, gauges and existing MON services'
echo '========== OPTIONAL GRAFANA / LOKI =========='
MONITOR=$ROOT/monitoring
mkdir -p "$MONITOR/grafana-provisioning/dashboards/mon" "$MONITOR/grafana-provisioning/datasources" "$MONITOR/logging"
for item in monitoring/grafana-provisioning/dashboards/mon/mon-network.json monitoring/grafana-provisioning/datasources/mon-loki.yaml monitoring/logging/loki-config.yaml monitoring/logging/alloy.config monitoring/compose-logs.yaml; do
  dest=$(echo "$item" | cut -c 12-)
  git -C "$CODE" show "$PIN:$item" > "$MONITOR/$dest"
done
if command -v docker >/dev/null 2>&1 && sudo docker compose version >/dev/null 2>&1; then
  if [[ -f "$MONITOR/compose.yaml" && -f "$MONITOR/metrics-token" && -f "$MONITOR/grafana-admin.env" ]]; then
    sudo docker compose -f "$MONITOR/compose.yaml" -p mon-observability up -d || echo '[CHECK] Grafana not started'
    sudo docker compose -f "$MONITOR/compose.yaml" -p mon-observability restart grafana || true
  fi
  sudo docker compose -f "$MONITOR/compose-logs.yaml" -p mon-logs up -d || echo '[CHECK] Loki/Alloy not started'
else
  echo '[CHECK] Docker Compose absent. Did not install Docker or change host networking.'
fi
GRAFANA=DOWN
LOKI=DOWN
if curl --noproxy '*' -fsS --max-time 5 http://100.75.116.62:3000/api/health 2>/dev/null |
  python3 -c 'import json,sys; assert json.load(sys.stdin).get("database")=="ok"' 2>/dev/null; then GRAFANA=UP; fi
if curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:3100/ready >/dev/null 2>&1; then LOKI=UP; fi
echo "GRAFANA STATUS: $GRAFANA"
echo "LOKI STATUS: $LOKI"
echo '[PASS] MON V5 installed; optional service statuses above'
echo 'Open http://100.75.116.62:5174/?tenant=mon-lab&site=site-a'
echo "Backup: $BACKUP"
