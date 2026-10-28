#!/usr/bin/env bash
# Conservative existing three-PC MON lab operations. NOT a Docker migration.
set -Eeuo pipefail

usage() {
  cat <<'HELP'
Usage (run on PC-2 as pc-2):
  bash tools/mon-three-lab-operator.sh status [--remote]
  bash tools/mon-three-lab-operator.sh up [--remote]
  bash tools/mon-three-lab-operator.sh arm-reboot

--remote requires preconfigured key-based SSH, trusted host keys, and
noninteractive, narrowly scoped sudo on PC-5 and PC-7.
No command creates databases, resets keys, changes peers or nftables policy.
HELP
}
[[ $# -ge 1 && $# -le 2 ]] || { usage; exit 2; }
ACTION=$1
REMOTE=0
if [[ $# -eq 2 ]]; then
  [[ $2 == --remote ]] || { usage; exit 2; }
  REMOTE=1
fi
case "$ACTION" in
  status|up|arm-reboot) ;;
  *) usage; exit 2 ;;
esac
[[ "$ACTION" != arm-reboot || "$REMOTE" -eq 0 ]] || { usage; exit 2; }
[[ $(id -un) == pc-2 ]] || { echo '[FAIL] Run as pc-2 on PC-2 (not sudo bash).' >&2; exit 1; }

DB=mon-three-postgres
SITE=pc-5@10.77.0.50
ATTACKER=pc-7@10.77.0.70
UNITS=(mon-three-lab-portal.service mon-three-console-v2.service mon-suricata-passive.service mon-stage4-gate.service)
FAILS=0
ok() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; FAILS=$((FAILS + 1)); }
http_ok() {
  if curl --noproxy '*' -fsS --max-time 6 "$2" >/dev/null; then
    ok "$1"
  else
    fail "$1 unavailable ($2)"
  fi
}
remote_check() {
  local host=$1 unit=$2 action=$3
  local command="systemctl is-active --quiet '$unit'"
  if [[ "$action" == up ]]; then
    command="systemctl is-active --quiet '$unit' || sudo -n systemctl start '$unit'; systemctl is-active --quiet '$unit'"
  fi
  if ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=8 "$host" "$command"; then
    ok "$host $unit active"
  else
    fail "$host $unit unverified; check SSH, sudo and installed service"
  fi
}

if [[ "$ACTION" == arm-reboot ]]; then
  sudo -v
  sudo systemctl enable docker wg-quick@wg0.service "${UNITS[@]}"
  if sudo docker container inspect "$DB" >/dev/null 2>&1; then
    sudo docker update --restart unless-stopped "$DB" >/dev/null
    ok "Existing $DB will restart after reboot"
  else
    fail "Existing $DB is missing; refusing replacement"
  fi
  echo '[NOTE] Enable PC-5/PC-7 services locally; check PC-2 API boot mechanism.'
  echo '[NOTE] DHCP changes and JWT expiry are not fixed by service auto-start.'
  (( FAILS == 0 ))
  exit
fi

if [[ "$ACTION" == up ]]; then
  sudo -v
  if ! systemctl is-active --quiet docker; then
    sudo systemctl start docker || fail 'Docker service failed to start'
  fi
  if ! sudo docker container inspect "$DB" >/dev/null 2>&1; then
    fail "Existing $DB missing; refusing to create a fresh database"
  elif [[ $(sudo docker inspect -f '{{.State.Running}}' "$DB") == false ]]; then
    sudo docker start "$DB" >/dev/null && ok "$DB started" || fail "$DB failed to start"
  else
    ok "$DB already running"
  fi
  if ! ip -4 addr show wg0 2>/dev/null | grep -Fq '10.77.0.1'; then
    sudo systemctl start wg-quick@wg0.service || fail 'PC-2 WireGuard failed to start'
  fi
  for unit in "${UNITS[@]}"; do
    if ! systemctl is-active --quiet "$unit"; then
      sudo systemctl start "$unit" || fail "$unit failed to start"
    fi
  done
  if ((REMOTE)); then
    remote_check "$SITE" mon-training-site.service up
    remote_check "$ATTACKER" mon-batch2-attack-console.service up
  fi
fi

printf '\n===== MON THREE-PC STATUS =====\n'
if ip -4 addr show wg0 2>/dev/null | grep -Fq '10.77.0.1'; then
  ok 'PC-2 WireGuard address 10.77.0.1 present'
else
  fail 'PC-2 WireGuard address missing'
fi
if sudo docker container inspect "$DB" >/dev/null 2>&1 &&
   [[ $(sudo docker inspect -f '{{.State.Running}}' "$DB") == true ]]; then
  ok "$DB running"
  if sudo docker exec "$DB" pg_isready -q >/dev/null 2>&1; then
    ok 'PostgreSQL accepting connections'
  else
    fail 'PostgreSQL not ready'
  fi
else
  fail "$DB not running"
fi
for unit in "${UNITS[@]}"; do
  if systemctl is-active --quiet "$unit"; then
    ok "$unit active"
  else
    fail "$unit inactive"
  fi
done
http_ok 'MON control plane' 'http://127.0.0.1:8080/health'
http_ok 'MON portal' 'http://127.0.0.1:8088/portal/health'
http_ok 'MON operator console' 'http://127.0.0.1:5174/'
http_ok 'PC-5 training website' 'http://10.77.0.50:8085/health'
if ((REMOTE)); then
  if [[ "$ACTION" == status ]]; then
    remote_check "$SITE" mon-training-site.service status
    remote_check "$ATTACKER" mon-batch2-attack-console.service status
  fi
else
  echo '[UNVERIFIED] PC-5 and PC-7 services not inspected; use --remote if SSH is configured.'
fi
if ((FAILS)); then
  printf '[FAIL] %d checks failed. Do not claim the lab is ready.\n' "$FAILS" >&2
  exit 1
fi
ok 'Local health checks passed (remote status noted above)'
