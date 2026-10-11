#!/usr/bin/env bash
# MON V5.1 UI-only release: no MON backend, VPN, firewall or IDS changes.
set -euo pipefail
umask 077
ROOT=/home/pc-2/mon-three
REPO=/home/pc-2/mon-three-code
APP=$ROOT/console-v2
PIN=37a6163d41ddd13eed552d96af871f599ef3ff8c
FILES="src/App.tsx src/Incident3D.tsx src/Incident3D.css src/styles.css src/SocGauges.css src/PacketObservability.tsx"
STAGE="" BACKUP="" MUTATED=0 PASSED=0
on_exit() {
  rc=$?
  trap - EXIT
  if [[ "$MUTATED" == 1 && "$PASSED" != 1 ]]; then
    echo '[ROLLBACK] Restore working V5 frontend'
    for file in $FILES; do
      if [[ -f "$BACKUP/$file" ]]; then cp "$BACKUP/$file" "$APP/$file" || true; else rm -f "$APP/$file" || true; fi
    done
    if [[ -d "$BACKUP/dist" ]]; then rm -rf "$APP/dist"; cp -a "$BACKUP/dist" "$APP/dist"; fi
    sudo systemctl restart mon-three-console-v2.service || true
  fi
  if [[ -n "$STAGE" && -d "$STAGE" ]]; then rm -rf "$STAGE"; fi
  exit "$rc"
}
trap on_exit EXIT

echo '========== CHECK WORKING MON V5 =========='
[[ "$(id -un)" == pc-2 && -d "$REPO/.git" && ! -L "$APP" ]] || exit 1
[[ -f "$APP/src/Incident3D.tsx" && -x "$APP/node_modules/.bin/tsc" ]] || exit 1
sudo -v
sudo systemctl is-active --quiet mon-three-console-v2.service
for url in http://127.0.0.1:8080/health http://127.0.0.1:8090/health http://127.0.0.1:5174/; do
  curl --noproxy '*' -fsS --max-time 7 "$url" >/dev/null
done
echo '[PASS] Backend, Site Controller and existing V5 frontend healthy'

echo '========== STAGE, BACK UP AND COMPILE =========='
git -C "$REPO" fetch --no-tags https://github.com/Saitanveesh/1.git refs/heads/fix/linux-ssh-journal-ingestion-20261010
git -C "$REPO" merge-base --is-ancestor "$PIN" FETCH_HEAD
STAGE=$(mktemp -d "$ROOT/v5-1-stage.XXXXXXXX")
BACKUP=$(mktemp -d "$ROOT/v5-1-backup.XXXXXXXX")
mkdir -p "$STAGE/src" "$BACKUP/src"
for file in $FILES; do
  git -C "$REPO" show "$PIN:console/$file" > "$STAGE/$file"
  if [[ -f "$APP/$file" ]]; then cp "$APP/$file" "$BACKUP/$file"; fi
done
if [[ -d "$APP/dist" ]]; then cp -a "$APP/dist" "$BACKUP/dist"; fi
MUTATED=1
for file in $FILES; do cp "$STAGE/$file" "$APP/$file"; done
(cd "$APP" && npm run build)
echo '[PASS] React/TypeScript production bundle compiled'

echo '========== VERIFY SERVED CONSOLE MODULES =========='
sudo systemctl restart mon-three-console-v2.service
READY=0
for n in $(seq 1 20); do
  if curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:5174/ >/dev/null 2>&1; then READY=1; break; fi
  sleep 1
done
[[ "$READY" == 1 ]] || { echo '[FAIL] UI did not restart'; exit 1; }
TMP=$(mktemp)
for entry in 'src/App.tsx:mon-single-console' 'src/Incident3D.tsx:mon3d-studio-grid' 'src/PacketObservability.tsx:mon-traffic-compact'; do
  component=$(cut -d: -f1 <<< "$entry")
  marker=$(cut -d: -f2 <<< "$entry")
  curl --noproxy '*' -fsS --max-time 8 -H 'Cache-Control: no-cache' "http://127.0.0.1:5174/$component?check=$PIN" -o "$TMP"
  if ! grep -Fq "$marker" "$TMP"; then
    echo "[FAIL] Old frontend still served: $component"
    head -c 180 "$TMP"; echo
    rm -f "$TMP"; exit 1
  fi
  echo "[PASS] Browser serves $component"
done
rm -f "$TMP"
for url in http://127.0.0.1:8080/health http://127.0.0.1:8090/health; do
  curl --noproxy '*' -fsS --max-time 7 "$url" >/dev/null
done
PASSED=1
echo '[PASS] MON V5.1 command desk and improved 3D studio installed'
echo "Restore point: $BACKUP"
echo 'Open http://100.75.116.62:5174/?tenant=mon-lab&site=site-a'
echo 'Use Ctrl+0 to reset browser zoom and Ctrl+Shift+R to reload'
