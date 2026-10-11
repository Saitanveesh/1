#!/usr/bin/env bash
# Targeted Grafana dashboard and datasource permission repair.
# Do not modify credentials, data volumes, network settings or MON backend.
set -euo pipefail
ROOT=/home/pc-2/mon-three/monitoring
P=$ROOT/grafana-provisioning
[[ "$(id -un)" == pc-2 && -d "$P" && -f "$ROOT/compose.yaml" ]] || { echo '[FAIL] Run as pc-2 on PC2'; exit 1; }
files=(dashboards/provider.yml dashboards/mon/mon-network.json datasources/mon-prometheus.yml datasources/mon-loki.yaml)
echo '========== GRAFANA PROVISIONING =========='
for rel in "${files[@]}"; do
  [[ -f "$P/$rel" && ! -L "$P/$rel" ]] || { echo "[FAIL] Missing or symlinked: $rel"; exit 1; }
  if sudo grep -Eiq '^[[:space:]]*(password|token|apiKey|clientSecret|secureJsonData)[[:space:]]*:' "$P/$rel"; then
    echo "[FAIL] Potential credential in $rel; refusing public-readable permissions"; exit 1;
  fi
done
sudo find "$P" -type d -exec chmod 755 {} +
for rel in "${files[@]}"; do
  sudo chmod 644 "$P/$rel"
  echo "[PASS] Readable: $rel"
done
echo '========== START GRAFANA =========='
STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
(cd "$ROOT" && sudo docker compose -p mon-observability -f compose.yaml up -d --no-deps grafana)
ready=0
for i in $(seq 1 20); do
  if curl --noproxy '*' -fsS --max-time 4 http://100.75.116.62:3000/api/health 2>/dev/null |
    python3 -c 'import json,sys; assert json.load(sys.stdin).get("database")=="ok"' >/dev/null 2>&1; then
    ready=1; break;
  fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then
  echo 'GRAFANA STATUS: UNAVAILABLE'
  (cd "$ROOT" && sudo docker compose -p mon-observability -f compose.yaml logs --tail=30 grafana) || true
  exit 1
fi
echo 'GRAFANA STATUS: HEALTHY'
if (cd "$ROOT" && sudo docker compose -p mon-observability -f compose.yaml logs --since "$STARTED" grafana) |
   grep -Ei 'permission denied|Failed to provision data sources'; then
  echo '[CHECK] Grafana still reports provisioning errors'
  exit 1
fi
echo '[PASS] Provisioning startup has no permission errors'
echo 'Dashboard: http://100.75.116.62:3000/d/mon-network'
echo 'GRAFANA REPAIR: COMPLETE'
