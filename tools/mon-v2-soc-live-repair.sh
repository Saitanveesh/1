#!/usr/bin/env bash
# MON V2 SOC observability repair for the existing 3-PC lab.
# Does not touch WireGuard, nftables, the MON API or Site Controller.
set -euo pipefail
umask 077
CODE=/home/pc-2/mon-three-code
BASE=/home/pc-2/mon-three
V2="$BASE/console-v2"
GATEWAY="$BASE/tools"
ENVFILE=/etc/mon-three/lab-portal.env
METRICS="$BASE/monitoring"
PIN=5400bf2a9139fa9f3b9afecef7f42029a7078d13
BRANCH=fix/linux-ssh-journal-ingestion-20261010
TEMP=""
BACKUP=""
CHANGED=0
SUCCESS=0
NEW_METRICS=0
FILES=(src/App.tsx src/IncidentDetail.tsx src/PacketObservability.tsx src/types.ts src/styles.css src/api.ts)

cleanup() {
  local rc=$?
  trap - EXIT
  if [[ "$CHANGED" == 1 && "$SUCCESS" != 1 && -d "$BACKUP" ]]; then
    echo '[ROLLBACK] Restoring MON V2, portal, and environment configuration' >&2
    for file in "${FILES[@]}"; do cp "$BACKUP/$file" "$V2/$file" || true; done
    cp "$BACKUP/mon-lab-portal.py" "$GATEWAY/mon-lab-portal.py" || true
    cp "$BACKUP/mon_ai_analysis.py" "$GATEWAY/mon_ai_analysis.py" || true
    sudo cp -p "$BACKUP/portal-env" "$ENVFILE" || true
    sudo systemctl restart mon-three-lab-portal.service || true
    sudo systemctl restart mon-three-console-v2.service || true
    if [[ "$NEW_METRICS" == 1 && -d "$METRICS" ]]; then
      mv "$METRICS" "$BACKUP/monitoring-failed" || true
    fi
  fi
  if [[ -n "$TEMP" && -d "$TEMP" ]]; then rm -rf "$TEMP"; fi
  exit "$rc"
}
trap cleanup EXIT

echo '========== VERIFY CURRENT MON SYSTEM =========='
[[ "$(id -un)" == pc-2 ]] || { echo '[FAIL] Run on PC2 as pc-2'; exit 1; }
[[ "$CODE" == /home/pc-2/mon-three-code && -d "$CODE/.git" ]] || exit 1
[[ "$V2" == /home/pc-2/mon-three/console-v2 && ! -L "$V2" ]] || exit 1
[[ -x "$V2/node_modules/.bin/tsc" && -f "$GATEWAY/mon-lab-portal.py" && -f "$GATEWAY/mon_ai_analysis.py" ]] || {
  echo '[FAIL] MON V2 or prior local AI installation is not present'; exit 1;
}
sudo -v
sudo systemctl is-active --quiet mon-three-lab-portal.service
sudo systemctl is-active --quiet mon-three-console-v2.service
sudo test -f "$ENVFILE"
for url in http://127.0.0.1:8080/health http://127.0.0.1:8090/health http://100.75.116.62:5173/; do
  curl --noproxy '*' -fsS --max-time 6 "$url" >/dev/null
done
echo '[PASS] Working MON backend, Site Controller, original console and V2 available'

echo '========== BACK UP AND BUILD VERIFIED SOURCES =========='
git -C "$CODE" fetch --no-tags https://github.com/Saitanveesh/1.git "refs/heads/$BRANCH"
git -C "$CODE" merge-base --is-ancestor "$PIN" FETCH_HEAD
TEMP=$(mktemp -d "$BASE/soc-stage.XXXXXXXX")
for file in "${FILES[@]}"; do
  mkdir -p "$TEMP/$(dirname "$file")"
  git -C "$CODE" show "$PIN:console/$file" > "$TEMP/$file"
done
git -C "$CODE" show "$PIN:tools/mon-lab-portal.py" > "$TEMP/mon-lab-portal.py"
git -C "$CODE" show "$PIN:tools/mon_ai_analysis.py" > "$TEMP/mon_ai_analysis.py"
python3 -m py_compile "$TEMP/mon-lab-portal.py" "$TEMP/mon_ai_analysis.py"
BACKUP=$(mktemp -d "$BASE/soc-backup.XXXXXXXX")
mkdir -p "$BACKUP/src"
for file in "${FILES[@]}"; do cp "$V2/$file" "$BACKUP/$file"; done
cp "$GATEWAY/mon-lab-portal.py" "$BACKUP/mon-lab-portal.py"
cp "$GATEWAY/mon_ai_analysis.py" "$BACKUP/mon_ai_analysis.py"
sudo cp -p "$ENVFILE" "$BACKUP/portal-env"
CHANGED=1
for file in "${FILES[@]}"; do cp "$TEMP/$file" "$V2/$file"; done
cp "$TEMP/mon-lab-portal.py" "$GATEWAY/mon-lab-portal.py"
cp "$TEMP/mon_ai_analysis.py" "$GATEWAY/mon_ai_analysis.py"
(cd "$V2" && npm run build)
sudo systemctl restart mon-three-console-v2.service
echo '[PASS] New 5-second rate curve, raw packet log and compact AI bar compiled and V2 refreshed'

echo '========== ENSURE METRICS CONFIGURATION =========='
if [[ ! -d "$METRICS" && ! -L "$METRICS" ]]; then
  git -C "$CODE" archive "$PIN" monitoring | tar -xf - -C "$TEMP"
  mv "$TEMP/monitoring" "$METRICS"
  chmod 700 "$METRICS"
  NEW_METRICS=1
fi
[[ -f "$METRICS/compose.yaml" && -f "$METRICS/prometheus.yml" ]] || {
  echo '[FAIL] Grafana provisioning files missing; no other MON services touched'; exit 1;
}
if [[ ! -f "$METRICS/metrics-token" ]]; then
  python3 - "$METRICS/metrics-token" <<'PY'
from pathlib import Path
import secrets,sys
target=Path(sys.argv[1])
target.write_text(secrets.token_urlsafe(32)+"\n")
target.chmod(0o600)
PY
fi
if [[ ! -f "$METRICS/grafana-admin.env" ]]; then
  python3 - "$METRICS/grafana-admin.env" <<'PY'
from pathlib import Path
import secrets,sys
p=Path(sys.argv[1])
p.write_text("GF_SECURITY_ADMIN_USER=admin\nGF_SECURITY_ADMIN_PASSWORD="
             +secrets.token_urlsafe(24)+"\n")
p.chmod(0o600)
PY
fi
# The existing operator password verifier and JWT are never printed or replaced.
sudo python3 - "$ENVFILE" "$METRICS/metrics-token" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
token=Path(sys.argv[2]).read_text().strip()
rows=[x for x in p.read_text().splitlines()
      if not x.startswith(("MON_PORTAL_INTERFACE=","MON_METRICS_TOKEN="))]
rows+=["MON_PORTAL_INTERFACE=any","MON_METRICS_TOKEN="+token]
p.write_text("\n".join(rows)+"\n")
p.chmod(0o600)
PY
sudo systemctl restart mon-three-lab-portal.service

echo '========== PROVE REAL KERNEL PACKETS AND REAL LOG RECORDS =========='
READY=0
for i in $(seq 1 25); do
  if curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:8088/portal/health 2>/dev/null |
    python3 -c 'import json,sys;x=json.load(sys.stdin);assert x["state"]=="READY" and x["capture"]=="CAPTURING"' 2>/dev/null; then
    READY=1;break
  fi
  sleep 1
done
[[ "$READY" == 1 ]] || { echo '[FAIL] Header capture not ready'; exit 1; }
# Generate harmless REAL socket traffic to verify AF_PACKET and event decoding.
for i in $(seq 1 6); do
  curl --noproxy '*' -fsS --max-time 4 http://127.0.0.1:8088/portal/health >/dev/null
  sleep 0.3
done
python3 - <<'PY'
import json,urllib.request
from pathlib import Path
token=Path("/home/pc-2/mon-three/identity/operator.jwt").read_text().strip()
req=urllib.request.Request("http://127.0.0.1:8088/portal/flows",
    headers={"Cookie":"mon_session="+token})
with urllib.request.urlopen(req,timeout=8) as resp:
    capture=json.load(resp)
assert capture.get("capture_scope")=="any", "Capture is not monitoring PC2 interfaces"
assert capture.get("status")=="CAPTURING", "Kernel capture not running"
assert capture.get("raw_frames",0)>0, "No real kernel frames counted"
assert capture.get("decoded_packets",0)>0, "No real IP headers decoded"
assert capture.get("events"), "No network-event header records"
row=capture["events"][0]
assert all(k in row for k in ("timestamp","interface","src_ip","dst_ip","protocol","ip_bytes")),row
print("[PASS] Real IP header events captured; no fabricated packets")
print("Raw frames:",capture["raw_frames"],"Decoded IP:",capture["decoded_packets"])
print("Interfaces:",", ".join(capture.get("observed_interfaces",{})))
print("Latest observation:",row["interface"],row["src_ip"],"->",row["dst_ip"],row["protocol"])
PY
curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:5174/portal/health >/dev/null
echo '[PASS] MON V2 local sensor and same-origin proxy alive'

echo '========== GRAFANA SERVICE CHECK =========='
GRAFANA=DOWN
if curl --noproxy '*' -fsS --max-time 4 http://100.75.116.62:3000/api/health >/dev/null 2>&1; then
  GRAFANA=UP
elif command -v docker >/dev/null 2>&1 && sudo docker compose version >/dev/null 2>&1; then
  echo '[CHECK] Grafana is not listening; starting existing Docker Compose stack'
  if sudo docker compose -p mon-observability -f "$METRICS/compose.yaml" up -d; then
    for i in $(seq 1 18); do
      if curl --noproxy '*' -fsS --max-time 4 http://100.75.116.62:3000/api/health >/dev/null 2>&1; then
        GRAFANA=UP;break
      fi
      sleep 2
    done
  fi
  if [[ "$GRAFANA" != UP ]]; then
    echo '[CHECK] Grafana containers did not become reachable; MON capture is still operational'
    sudo docker compose -p mon-observability -f "$METRICS/compose.yaml" ps || true
  fi
else
  echo '[CHECK] Grafana refused connection because Docker Compose is unavailable and Grafana is not running'
  echo '[CHECK] Docker will NOT be installed automatically: it can change host networking rules'
fi
if [[ "$GRAFANA" == UP ]]; then
  echo '[PASS] Grafana HTTP health reachable: http://100.75.116.62:3000/'
else
  echo '[CHECK] GRAFANA DOWN — do not treat port 3000 as deployed'
fi
curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8080/health >/dev/null
curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8090/health >/dev/null
curl --noproxy '*' -fsS --max-time 5 http://100.75.116.62:5173/ >/dev/null
SUCCESS=1
echo '[PASS] MON V2 SOC interface and real network logs updated; existing MON control/response intact'
echo 'MON V2: http://100.75.116.62:5174/?tenant=mon-lab&site=site-a'
echo "GRAFANA STATUS: $GRAFANA"
echo "Rollback copies: $BACKUP"
