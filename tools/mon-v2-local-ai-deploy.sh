#!/usr/bin/env bash
# PC2 MON three-PC lab: deploy local AI to isolated V2 only (port 5174).
set -euo pipefail
umask 077
CODE="/home/pc-2/mon-three-code"
STATE="/home/pc-2/mon-three"
APP="$STATE/console-v2"
PORTAL="$STATE/tools"
PIN="064c852678978a94ca1ce4699a0300518f65a2a6"
INCIDENT="9398913b-3fb4-4f01-874f-87f6d71ed646"
STAGE=""
BACKUP=""
UPDATED=0
SUCCESS=0
EXISTED=0
rollback() {
  rc=$?
  trap - EXIT
  if [[ "$SUCCESS" != 1 && "$UPDATED" == 1 && -d "$BACKUP" ]]; then
    echo "[ROLLBACK] Restoring prior portal and V2 UI" >&2
    cp -- "$BACKUP/original-portal.py" "$PORTAL/mon-lab-portal.py" || true
    if [[ "$EXISTED" == 1 ]]; then
      cp -- "$BACKUP/original-ai.py" "$PORTAL/mon_ai_analysis.py" || true
    else
      rm -f -- "$PORTAL/mon_ai_analysis.py"
    fi
    for p in src/IncidentDetail.tsx src/api.ts src/types.ts src/styles.css; do
      cp -- "$BACKUP/$p" "$APP/$p" || true
    done
    sudo systemctl restart mon-three-lab-portal.service || true
  fi
  if [[ -n "$STAGE" && -d "$STAGE" ]]; then rm -rf -- "$STAGE"; fi
  exit "$rc"
}
trap rollback EXIT

echo '========== MON V2 LOCAL AI PREFLIGHT =========='
[[ "$(id -un)" == pc-2 ]] || { echo '[FAIL] Run as pc-2 on PC2'; exit 1; }
[[ -d "$CODE/.git" && ! -L "$APP" && -f "$APP/src/IncidentDetail.tsx" ]] || exit 1
[[ -x "$APP/node_modules/.bin/tsc" && -f "$PORTAL/mon-lab-portal.py" ]] || exit 1
sudo -v
sudo systemctl is-active --quiet mon-three-lab-portal.service
sudo systemctl is-active --quiet mon-three-console-v2.service
sudo systemctl cat mon-three-lab-portal.service | grep -Fq "$PORTAL/mon-lab-portal.py"
for url in http://127.0.0.1:8080/health http://127.0.0.1:8090/health http://100.75.116.62:5173/; do
  curl --noproxy '*' -fsS --max-time 6 "$url" >/dev/null
done
curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:5174/portal/health |
  python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["state"]=="READY" and x["capture"]=="CAPTURING"'
python3 - <<'PY'
import json, urllib.request
with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=8) as response:
    models = json.load(response).get("models", [])
assert any(m.get("name", "").startswith("qwen3:4b") for m in models), "qwen3:4b not installed"
print("[PASS] Ollama qwen3:4b present on PC2")
PY
echo '[PASS] MON backend, isolated V2, capture and Ollama online'

echo '========== STAGE PINNED CODE =========='
git -C "$CODE" fetch --no-tags https://github.com/Saitanveesh/1.git refs/heads/fix/linux-ssh-journal-ingestion-20261010
git -C "$CODE" merge-base --is-ancestor "$PIN" FETCH_HEAD
STAGE=$(mktemp -d "$STATE/ai-stage.XXXXXXXX")
for p in src/IncidentDetail.tsx src/api.ts src/types.ts src/styles.css; do
  mkdir -p -- "$STAGE/$(dirname "$p")"
  git -C "$CODE" show "$PIN:console/$p" > "$STAGE/$p"
done
git -C "$CODE" show "$PIN:tools/mon-lab-portal.py" > "$STAGE/mon-lab-portal.py"
git -C "$CODE" show "$PIN:tools/mon_ai_analysis.py" > "$STAGE/mon_ai_analysis.py"
python3 -m py_compile "$STAGE/mon-lab-portal.py" "$STAGE/mon_ai_analysis.py"

echo '========== BACK UP AND DEPLOY =========='
BACKUP=$(mktemp -d "$STATE/ai-backup.XXXXXXXX")
mkdir -p -- "$BACKUP/src"
cp -- "$PORTAL/mon-lab-portal.py" "$BACKUP/original-portal.py"
if [[ -f "$PORTAL/mon_ai_analysis.py" ]]; then
  cp -- "$PORTAL/mon_ai_analysis.py" "$BACKUP/original-ai.py"
  EXISTED=1
fi
for p in src/IncidentDetail.tsx src/api.ts src/types.ts src/styles.css; do
  cp -- "$APP/$p" "$BACKUP/$p"
done
UPDATED=1
cp -- "$STAGE/mon-lab-portal.py" "$PORTAL/mon-lab-portal.py"
cp -- "$STAGE/mon_ai_analysis.py" "$PORTAL/mon_ai_analysis.py"
for p in src/IncidentDetail.tsx src/api.ts src/types.ts src/styles.css; do
  cp -- "$STAGE/$p" "$APP/$p"
done
(cd "$APP" && npm run build)
echo '[PASS] New local AI panel compiled'

echo '========== RESTART ONLY PORTAL SERVICE =========='
sudo systemctl restart mon-three-lab-portal.service
READY=0
for i in $(seq 1 20); do
  if curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:5174/portal/health 2>/dev/null |
     python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["state"]=="READY" and x["capture"]=="CAPTURING"' 2>/dev/null; then
    READY=1; break
  fi
  sleep 1
done
[[ "$READY" == 1 ]] || { echo '[FAIL] Portal or capture did not recover'; exit 1; }
echo '[PASS] Real packet capture and local portal operational'

echo '========== REAL AI INVESTIGATION ACCEPTANCE =========='
python3 - "$INCIDENT" <<'PY'
import json, sys, urllib.request
from pathlib import Path
token=Path("/home/pc-2/mon-three/identity/operator.jwt").read_text().strip()
payload=json.dumps({"incident_id":sys.argv[1],"tenant_id":"mon-lab","site_id":"site-a"}).encode()
req=urllib.request.Request("http://127.0.0.1:5174/portal/ai/investigate",
    data=payload, method="POST", headers={
        "Cookie":"mon_session="+token,
        "Origin":"http://100.75.116.62:5174",
        "Content-Type":"application/json"})
with urllib.request.urlopen(req,timeout=140) as result:
    data=json.load(result)
assert data.get("read_only") is True and data.get("evidence_ids") and data.get("analysis")
print("[PASS] Qwen3 analyzed the real PC6 incident read-only")
print("Model:",data.get("model"))
print("MON evidence references:",data.get("evidence_count"))
print("Analysis characters:",len(data.get("analysis","")))
PY
curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:8080/health >/dev/null
curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:8090/health >/dev/null
curl --noproxy '*' -fsS --max-time 6 http://100.75.116.62:5173/ >/dev/null
SUCCESS=1
echo '[PASS] MON V2 AI installed; MON control plane, WireGuard and 5173 not modified'
echo 'Open http://100.75.116.62:5174/?tenant=mon-lab&site=site-a'
echo 'Incidents > PC6 incident > ANALYZE WITH LOCAL AI'
echo "Rollback sources retained: $BACKUP"
