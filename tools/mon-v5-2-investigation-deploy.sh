#!/usr/bin/env bash
# UI-only incident investigation repair + separate optional Grafana recovery.
# Preserve Overview, PC2->PC5 detection, WireGuard, nftables, identities, portal and AI.
set -euo pipefail
umask 077
ROOT=/home/pc-2/mon-three
CODE=/home/pc-2/mon-three-code
WEB=$ROOT/console-v2
PIN=1273d9638ddfb273404cd8e2e1a9ed86db0db244
FILES="src/App.tsx src/IncidentDetail.tsx src/IncidentQueue.tsx src/IncidentEventFlow.tsx src/IncidentWorkspace.css src/Incident3D.tsx"
STAGE="" BACKUP="" CHANGED=0 VERIFIED=0
restore() {
  rc=$?
  trap - EXIT
  if [[ "$CHANGED" == 1 && "$VERIFIED" != 1 ]]; then
    echo '[ROLLBACK] Restoring previous MON UI; backend/router untouched'
    for file in $FILES; do
      if [[ -f "$BACKUP/$file" ]]; then
        cp "$BACKUP/$file" "$WEB/$file" || true
      else
        rm -f "$WEB/$file" || true
      fi
    done
    if [[ -d "$BACKUP/dist" ]]; then
      rm -rf "$WEB/dist"
      cp -a "$BACKUP/dist" "$WEB/dist"
    fi
    sudo systemctl restart mon-three-console-v2.service || true
  fi
  if [[ -n "$STAGE" && -d "$STAGE" ]]; then rm -rf "$STAGE"; fi
  exit "$rc"
}
trap restore EXIT

echo '========== PRESERVE WORKING MON =========='
[[ "$(id -un)" == pc-2 && -d "$CODE/.git" && ! -L "$WEB" ]] || {
  echo '[FAIL] Must run as pc-2 on PC2 with the existing MON console'; exit 1;
}
[[ -f "$WEB/src/Incident3D.tsx" && -x "$WEB/node_modules/.bin/tsc" ]] || {
  echo '[FAIL] V5 console not present or dependencies missing'; exit 1;
}
sudo -v
sudo systemctl is-active --quiet mon-three-console-v2.service
sudo systemctl is-active --quiet mon-three-lab-portal.service
for url in http://127.0.0.1:8080/health http://127.0.0.1:8090/health http://127.0.0.1:5174/; do
  curl --noproxy '*' -fsS --max-time 7 "$url" >/dev/null
done
echo '[PASS] MON control, routing and existing console healthy'

echo '========== BACKUP, COMPILE AND DEPLOY =========='
git -C "$CODE" fetch --no-tags https://github.com/Saitanveesh/1.git refs/heads/fix/linux-ssh-journal-ingestion-20261010
git -C "$CODE" merge-base --is-ancestor "$PIN" FETCH_HEAD
STAGE=$(mktemp -d "$ROOT/v5-2-stage.XXXXXXXX")
BACKUP=$(mktemp -d "$ROOT/v5-2-restore.XXXXXXXX")
mkdir -p "$STAGE/src" "$BACKUP/src"
for file in $FILES; do
  git -C "$CODE" show "$PIN:console/$file" > "$STAGE/$file"
  if [[ -f "$WEB/$file" ]]; then cp "$WEB/$file" "$BACKUP/$file"; fi
done
git -C "$CODE" show "$PIN:tools/mon-grafana-recover.sh" > "$STAGE/mon-grafana-recover.sh"
bash -n "$STAGE/mon-grafana-recover.sh"
if [[ -d "$WEB/dist" ]]; then cp -a "$WEB/dist" "$BACKUP/dist"; fi
CHANGED=1
for file in $FILES; do cp "$STAGE/$file" "$WEB/$file"; done
(cd "$WEB" && npm run build)
echo '[PASS] MON incidents UI compiles and backup is available'

echo '========== VERIFY ACTUAL SERVED FRONTEND =========='
sudo systemctl restart mon-three-console-v2.service
STARTED=0
for n in $(seq 1 20); do
  if curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:5174/ >/dev/null 2>&1; then
    STARTED=1; break
  fi
  sleep 1
done
[[ "$STARTED" == 1 ]] || { echo '[FAIL] Frontend did not restart'; exit 1; }
TMP=$(mktemp)
for item in 'src/App.tsx:mon-incidents-workspace' \
  'src/IncidentDetail.tsx:mon-case-tabs' \
  'src/Incident3D.tsx:IncidentEventFlow' \
  'src/IncidentQueue.tsx:incident-case-queue'; do
  component=$(cut -d: -f1 <<< "$item")
  marker=$(cut -d: -f2 <<< "$item")
  curl --noproxy '*' -fsS --max-time 8 -H 'Cache-Control: no-cache' \
    "http://127.0.0.1:5174/$component?mon_v52=$PIN" -o "$TMP"
  grep -Fq "$marker" "$TMP" || {
    echo "[FAIL] Browser not serving new component: $component"
    head -c 150 "$TMP"; echo; rm -f "$TMP"; exit 1;
  }
  echo "[PASS] Browser serves $component"
done
rm -f "$TMP"
for url in http://127.0.0.1:8080/health http://127.0.0.1:8090/health; do
  curl --noproxy '*' -fsS --max-time 7 "$url" >/dev/null
done
VERIFIED=1
echo '[PASS] Incident queue, event flow, evidence and response views deployed'
echo "[PASS] Previous frontend restore point: $BACKUP"

echo '========== OPTIONAL GRAFANA RESTORE (NO MON BACKEND CHANGES) =========='
if bash "$STAGE/mon-grafana-recover.sh"; then
  echo 'GRAFANA STATUS: HEALTHY'
else
  echo 'GRAFANA STATUS: UNAVAILABLE (details above; MON is unaffected)'
fi
echo '[PASS] MON V5.2 frontend ready'
echo 'MON URL: http://100.75.116.62:5174/?tenant=mon-lab&site=site-a'
echo 'At normal Chrome zoom: Ctrl+0 then Ctrl+Shift+R'
