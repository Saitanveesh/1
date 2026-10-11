#!/usr/bin/env bash
# Recover optional MON Grafana without modifying MON control, VPN or firewall.
set -euo pipefail
MONITOR=/home/pc-2/mon-three/monitoring
HOST=100.75.116.62
URL="http://$HOST:3000/api/health"
healthy() {
  curl --noproxy '*' -fsS --max-time 4 "$URL" 2>/dev/null |
    python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("database")=="ok"' >/dev/null 2>&1
}
echo '========== GRAFANA SERVICE CHECK =========='
if healthy; then
  echo '[PASS] Grafana already healthy at port 3000'
  exit 0
fi
if sudo ss -lntp | grep -qE ':[3]000[[:space:]]'; then
  echo '[CHECK] Port 3000 is occupied but Grafana health failed; will not replace another service.'
  sudo ss -lntp | grep -E ':[3]000[[:space:]]' || true
  exit 2
fi
if ! command -v docker >/dev/null || ! sudo docker compose version >/dev/null 2>&1; then
  echo '[CHECK] Docker Compose is unavailable. Grafana was not installed, and no host networking was changed.'
  exit 2
fi
if [[ ! -f "$MONITOR/compose.yaml" || ! -f "$MONITOR/grafana-admin.env" ||
      ! -f "$MONITOR/metrics-token" || ! -f "$MONITOR/prometheus.yml" ]]; then
  echo '[CHECK] Grafana Compose configuration or credential files are missing; no new credentials were invented.'
  exit 2
fi
if ! ip -4 address show | grep -Fq "$HOST/"; then
  echo '[CHECK] PC2 Tailscale address not assigned; Grafana binding would fail.'
  exit 2
fi
echo '[REPAIR] Starting existing MON Prometheus + Grafana Compose services'
if ! (cd "$MONITOR" && sudo docker compose -p mon-observability -f compose.yaml up -d prometheus grafana); then
  echo '[CHECK] Existing Grafana Compose failed. Diagnostic output follows.'
  (cd "$MONITOR" && sudo docker compose -p mon-observability -f compose.yaml ps) || true
  exit 2
fi
for i in $(seq 1 25); do
  if healthy; then
    echo '[PASS] Grafana REST API healthy and database available'
    echo "Grafana: http://$HOST:3000/d/mon-network"
    exit 0
  fi
  sleep 2
done
echo '[CHECK] Container started but no valid Grafana REST health; last 35 log lines:'
(cd "$MONITOR" && sudo docker compose -p mon-observability -f compose.yaml logs --tail 35 grafana) || true
exit 2
