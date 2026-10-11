#!/usr/bin/env bash
set -euo pipefail
umask 077
REPO=/home/pc-2/mon-three-code
V2=/home/pc-2/mon-three/console-v2
PIN=e40395e0579fe20ae9ddd2e0a2806c9cef4ba2e2
UNIT=mon-three-console-v2.service
FILES=(src/App.tsx src/AiAnalysis.tsx src/AiAnalysis.css)
STAGE="" BACKUP="" ALTERED=0 OK=0

on_exit() {
  rc=$?
  trap - EXIT
  if [[ "$OK" != 1 && "$ALTERED" == 1 ]]; then
    echo '[ROLLBACK] Restoring MON V2 prior frontend source'
    for file in "${FILES[@]}"; do
      if [[ -f "$BACKUP/$file" ]]; then
        cp "$BACKUP/$file" "$V2/$file" || true
      else
        rm -f "$V2/$file"
      fi
    done
    sudo systemctl restart "$UNIT" || true
  fi
  if [[ -n "$STAGE" && -d "$STAGE" ]]; then rm -rf "$STAGE"; fi
  exit "$rc"
}
trap on_exit EXIT

echo '========== MON V2 AI WORKSPACE PREFLIGHT =========='
[[ "$(id -un)" == pc-2 && ! -L "$V2" && -d "$REPO/.git" ]] || exit 1
[[ -f "$V2/src/App.tsx" && -x "$V2/node_modules/.bin/tsc" ]] || exit 1
sudo -v
sudo systemctl is-active --quiet "$UNIT"
sudo systemctl cat "$UNIT" | grep -Fq "$V2"
for url in http://127.0.0.1:8080/health http://127.0.0.1:8090/health http://100.75.116.62:5173/; do
  curl --noproxy '*' -fsS --max-time 6 "$url" >/dev/null
done
curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:5174/portal/health |
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["state"]=="READY" and d["capture"]=="CAPTURING"'
echo '[PASS] Existing MON V2 and backend services healthy'

echo '========== STAGE, BACK UP AND COMPILE =========='
git -C "$REPO" fetch --no-tags https://github.com/Saitanveesh/1.git refs/heads/fix/linux-ssh-journal-ingestion-20261010
git -C "$REPO" merge-base --is-ancestor "$PIN" FETCH_HEAD
STAGE=$(mktemp -d /home/pc-2/mon-three/ai-stage.XXXXXXXX)
for file in "${FILES[@]}"; do
  mkdir -p "$STAGE/$(dirname "$file")"
  git -C "$REPO" show "$PIN:console/$file" > "$STAGE/$file"
done
grep -Fq '"AI Analysis"' "$STAGE/src/App.tsx"
BACKUP=$(mktemp -d /home/pc-2/mon-three/ai-backup.XXXXXXXX)
mkdir -p "$BACKUP/src"
for file in "${FILES[@]}"; do
  if [[ -f "$V2/$file" ]]; then cp "$V2/$file" "$BACKUP/$file"; fi
done
ALTERED=1
for file in "${FILES[@]}"; do cp "$STAGE/$file" "$V2/$file"; done
(cd "$V2" && npm run build)
echo '[PASS] AI Analysis compiled in existing V2'

echo '========== RESTART ISOLATED FRONTEND =========='
sudo systemctl restart "$UNIT"
READY=0
for i in $(seq 1 25); do
  if curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:5174/portal/health 2>/dev/null |
    python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["state"]=="READY" and d["capture"]=="CAPTURING"' 2>/dev/null; then
    READY=1; break
  fi
  sleep 1
done
[[ "$READY" == 1 ]] || { echo '[FAIL] V2 frontend/portal health failed'; exit 1; }
MODULE=$(mktemp)
curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:5174/src/App.tsx -o "$MODULE"
if ! grep -Fq 'AI Analysis' "$MODULE"; then
  rm -f "$MODULE"
  echo '[FAIL] Old frontend still served'; exit 1
fi
rm -f "$MODULE"
for url in http://127.0.0.1:8080/health http://127.0.0.1:8090/health http://100.75.116.62:5173/; do
  curl --noproxy '*' -fsS --max-time 6 "$url" >/dev/null
done
OK=1
echo '[PASS] AI Analysis tab is served by MON V2; network/control services untouched'
echo "Backup: $BACKUP"
echo 'OPEN http://100.75.116.62:5174/?tenant=mon-lab&site=site-a'
