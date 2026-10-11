#!/usr/bin/env bash
# PC2 only: update isolated MON V2 and enable authenticated Grafana metrics.
# V1, MON detection, Site Controller, nftables and WireGuard unchanged.
set -euo pipefail
umask 077
CODE=/home/pc-2/mon-three-code
STATE=/home/pc-2/mon-three
APP=$STATE/console-v2
PORTAL=$STATE/tools
ENV=/etc/mon-three/lab-portal.env
PIN=442b8d41fbc50f93ea9b44691eef15826bcd7c46
DIR=$STATE/monitoring
FILES=(src/App.tsx src/IncidentDetail.tsx src/PacketObservability.tsx src/types.ts src/styles.css)
STAGE="" BACKUP="" MODIFIED=0 DONE=0
restore(){
  rc=$?
  trap - EXIT
  if [[ "$DONE" != 1 && "$MODIFIED" == 1 ]]; then
    echo '[RESTORE] Restoring previous MON V2 and portal' >&2
    for p in ${FILES[@]}; do cp "$BACKUP/$p" "$APP/$p" || true; done
    cp "$BACKUP/mon-lab-portal.py" "$PORTAL/mon-lab-portal.py" || true
    cp "$BACKUP/mon_ai_analysis.py" "$PORTAL/mon_ai_analysis.py" || true
    sudo cp -p "$BACKUP/portal-env" "$ENV" || true
    sudo systemctl restart mon-three-lab-portal.service || true
  fi
  if [[ -n "$STAGE" && -d "$STAGE" ]]; then rm -rf "$STAGE"; fi
  exit "$rc"
}
trap restore EXIT

echo '========== SAFE PRE-FLIGHT =========='
[[ "$(id -un)" == pc-2 && -d "$CODE/.git" && ! -L "$APP" ]] || exit 1
[[ -x "$APP/node_modules/.bin/tsc" &&
    -f "$PORTAL/mon_ai_analysis.py" && -f "$PORTAL/mon-lab-portal.py" ]] || exit 1
sudo -v
sudo systemctl is-active --quiet mon-three-console-v2.service
sudo systemctl is-active --quiet mon-three-lab-portal.service
sudo test -f "$ENV"
curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:8080/health >/dev/null
curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:8090/health >/dev/null
curl --noproxy '*' -fsS --max-time 6 http://100.75.116.62:5173/ >/dev/null
curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:5174/portal/health |
  python3 -c 'import json,sys; assert json.load(sys.stdin)["capture"]=="CAPTURING"'
[[ ! -e "$DIR" && ! -L "$DIR" ]] || {
  echo '[FAIL] Monitoring directory already exists; refusing to overwrite it'; exit 1;
}
echo '[PASS] MON control/site and both consoles preserved'

echo '========== STAGE PINNED SOURCE AND BACKUPS =========='
git -C "$CODE" fetch --no-tags https://github.com/Saitanveesh/1.git refs/heads/fix/linux-ssh-journal-ingestion-20261010
git -C "$CODE" merge-base --is-ancestor "$PIN" FETCH_HEAD
STAGE=$(mktemp -d "$STATE/obs-stage.XXXXXXXX")
for p in ${FILES[@]}; do
  mkdir -p "$STAGE/$(dirname "$p")"
  git -C "$CODE" show "$PIN:console/$p" > "$STAGE/$p"
done
git -C "$CODE" show "$PIN:tools/mon-lab-portal.py" > "$STAGE/mon-lab-portal.py"
git -C "$CODE" show "$PIN:tools/mon_ai_analysis.py" > "$STAGE/mon_ai_analysis.py"
git -C "$CODE" archive "$PIN" monitoring | tar -xf - -C "$STAGE"
python3 -m py_compile "$STAGE/mon-lab-portal.py" "$STAGE/mon_ai_analysis.py"
BACKUP=$(mktemp -d "$STATE/obs-backup.XXXXXXXX")
mkdir -p "$BACKUP/src"
for p in ${FILES[@]}; do cp "$APP/$p" "$BACKUP/$p"; done
cp "$PORTAL/mon-lab-portal.py" "$BACKUP/mon-lab-portal.py"
cp "$PORTAL/mon_ai_analysis.py" "$BACKUP/mon_ai_analysis.py"
sudo cp -p "$ENV" "$BACKUP/portal-env"
echo "[PASS] Restorable copies at $BACKUP"

echo '========== ACTIVATE REAL BIDIRECTIONAL HOST TRAFFIC =========='
MODIFIED=1
for p in ${FILES[@]}; do cp "$STAGE/$p" "$APP/$p"; done
cp "$STAGE/mon-lab-portal.py" "$PORTAL/mon-lab-portal.py"
cp "$STAGE/mon_ai_analysis.py" "$PORTAL/mon_ai_analysis.py"
(cd "$APP" && npm run build)
mv "$STAGE/monitoring" "$DIR"
chmod 0700 "$DIR"
python3 - "$DIR" <<'PY'
import secrets,sys
from pathlib import Path
p=Path(sys.argv[1])
(p/"metrics-token").write_text(secrets.token_urlsafe(32)+"\n")
(p/"grafana-admin.env").write_text(
    "GF_SECURITY_ADMIN_USER=admin\n"
    "GF_SECURITY_ADMIN_PASSWORD="+secrets.token_urlsafe(24)+"\n"
)
(p/"metrics-token").chmod(0o600)
(p/"grafana-admin.env").chmod(0o600)
PY
sudo python3 - "$ENV" "$DIR/metrics-token" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
token=Path(sys.argv[2]).read_text().strip()
rows=[line for line in p.read_text().splitlines()
      if not line.startswith(("MON_PORTAL_INTERFACE=","MON_METRICS_TOKEN="))]
rows += ["MON_PORTAL_INTERFACE=any","MON_METRICS_TOKEN="+token]
p.write_text("\n".join(rows)+"\n")
p.chmod(0o600)
PY
sudo systemctl restart mon-three-lab-portal.service

echo '========== VERIFY MEASURED SENSOR AND AUTHENTICATED EXPORTER =========='
READY=0
for i in $(seq 1 20); do
  if curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:5174/portal/health 2>/dev/null |
    python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["capture"]=="CAPTURING"' 2>/dev/null; then
    READY=1; break
  fi
  sleep 1
done
[[ "$READY" == 1 ]] || { echo '[FAIL] Real capture not operational'; exit 1; }
TOKEN=$(cat "$DIR/metrics-token")
curl --noproxy '*' -fsS --max-time 6 -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8088/portal/metrics |
  grep -q 'mon_capture_packets_total{direction="outbound"}'
unset TOKEN
echo '[PASS] Kernel capture active with authenticated inbound/outbound counters'

echo '========== OPTIONAL GRAFANA + PROMETHEUS =========='
if command -v docker >/dev/null && sudo docker compose version >/dev/null 2>&1; then
  sudo docker compose -f "$DIR/compose.yaml" --project-name mon-observability up -d
  echo '[PASS] Grafana and Prometheus requested at http://100.75.116.62:3000/'
else
  echo '[CHECK] Docker Compose unavailable: Grafana deployment deferred, MON capture works'
fi

curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:8080/health >/dev/null
curl --noproxy '*' -fsS --max-time 6 http://127.0.0.1:8090/health >/dev/null
curl --noproxy '*' -fsS --max-time 6 http://100.75.116.62:5173/ >/dev/null
DONE=1
echo '[PASS] MON V2 new UI, real packet telemetry and metrics exporter installed'
echo 'MON V2: http://100.75.116.62:5174/?tenant=mon-lab&site=site-a'
echo "Grafana credentials (PRIVATE FILE): $DIR/grafana-admin.env"
