#!/usr/bin/env bash
# MON three-PC lab V2: update only packet visualization in isolated 5174 console.
set -euo pipefail
ROOT="$HOME/mon-three"
APP="$ROOT/console-v2"
CODE="$HOME/mon-three-code"
COMMIT="d091528f112fafe6649d46a76e8c489b111237d2"
BRANCH="fix/linux-ssh-journal-ingestion-20261010"
UNIT="mon-three-console-v2.service"
BACKUP=""
SWAPPED=0
restore(){
  local rc=$?
  trap - EXIT
  if [[ "$SWAPPED" == 1 && -f "$BACKUP" ]]; then
    tar -xzf "$BACKUP" -C "$APP" || true
  fi
  exit "$rc"
}
trap restore EXIT

echo "========== CHECK V2 ONLY =========="
[[ "$(id -un)" == "pc-2" ]] || { echo '[FAIL] Run on PC2 as pc-2'; exit 1; }
[[ "$APP" == "/home/pc-2/mon-three/console-v2" ]] || exit 1
[[ ! -L "$APP" && -f "$APP/src/PacketObservability.tsx" &&
   -f "$APP/src/styles.css" && -f "$APP/package.json" ]] || {
  echo '[FAIL] Isolated MON V2 frontend missing'; exit 1;
}
[[ -x "$APP/node_modules/.bin/tsc" && -x "$APP/node_modules/.bin/vite" ]] || {
  echo '[FAIL] Existing development tools missing'; exit 1;
}
sudo systemctl is-active --quiet "$UNIT" || {
  echo "[FAIL] $UNIT inactive"; exit 1;
}
curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8080/health >/dev/null
curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8090/health >/dev/null
curl --noproxy '*' -fsS --max-time 5 http://100.75.116.62:5173/ >/dev/null
curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:5174/portal/health |
  python3 -c 'import sys,json; x=json.load(sys.stdin); assert x["capture"]=="CAPTURING"'
echo '[PASS] MON V2 + packet sensor running, original 5173 console untouched'

echo "========== STAGE PINNED UI PATCH =========="
git -C "$CODE" fetch --no-tags https://github.com/Saitanveesh/1.git "refs/heads/$BRANCH"
git -C "$CODE" merge-base --is-ancestor "$COMMIT" FETCH_HEAD
STAGED=$(mktemp -d)
trap 'rm -rf "$STAGED"' EXIT
for file in src/PacketObservability.tsx src/styles.css; do
  mkdir -p "$STAGED/$(dirname "$file")"
  git -C "$CODE" show "$COMMIT:console/$file" > "$STAGED/$file"
done
BACKUP="$ROOT/mon-v2-live-flow-before-$(date -u +%Y%m%dT%H%M%SZ).tgz"
tar -czf "$BACKUP" -C "$APP" src/PacketObservability.tsx src/styles.css
SWAPPED=1
for file in src/PacketObservability.tsx src/styles.css; do
  cp "$STAGED/$file" "$APP/$file"
done
(cd "$APP" && npm run build)
echo '[PASS] Live chart and topology animation compiled'

echo "========== VERIFY NEW V2 AND PRESERVED BACKEND =========="
curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:5174/portal/health |
  python3 -c 'import sys,json; x=json.load(sys.stdin); assert x["state"]=="READY" and x["capture"]=="CAPTURING"'
curl --noproxy '*' -fsS --max-time 5 http://100.75.116.62:5173/ >/dev/null
curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8080/health >/dev/null
curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8090/health >/dev/null
SWAPPED=0
echo '[PASS] MON V2 chart upgraded, sensor live, original MON undisturbed'
echo 'V2: http://100.75.116.62:5174/?tenant=mon-lab&site=site-a'
