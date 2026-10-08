#!/usr/bin/env bash
# Remote half of the MON seven-Ubuntu SSH orchestrator. Invoked via sudo on each lab host.
set -Eeuo pipefail
umask 077
[[ $# == 2 ]] || { echo 'Usage: node.sh PCn STAGE' >&2; exit 2; }
PC="$1"; STAGE="$2"
case "$PC" in PC1|PC3|PC4|PC5|PC6) ;; *) echo 'Unsupported PC' >&2; exit 2 ;; esac
[[ "${EUID}" == 0 ]] || { echo 'Must run with sudo' >&2; exit 2; }
LOGIN_USER="${SUDO_USER:?Run from the SSH operator account with sudo}"
LOGIN_HOME="$(getent passwd "$LOGIN_USER" | cut -d: -f6)"
[[ -d "$LOGIN_HOME" ]] || { echo 'Cannot find home directory' >&2; exit 2; }
STAGING="$LOGIN_HOME/.local/share/mon-lab"
# shellcheck disable=SC1091
source "$STAGING/config.env"
[[ "$LOGIN_USER" == "$LAB_USER" ]] || { echo 'SSH operator does not match LAB_USER' >&2; exit 2; }
REPO=/opt/mon-lab/mon
PY="$REPO/.venv/bin/python"
IDENTITY=/etc/mon-lab/identity
REQUESTS=/etc/mon-lab/requests
PRIVATE=/etc/mon

log() { echo "[MON][$PC][$STAGE] $*"; }
need() { command -v "$1" >/dev/null || { log "Missing executable: $1"; exit 1; }; }
finish() { log 'PASS'; }
install_copy() { local name="$1" to="$2" mode="${3:-600}"; install -m "$mode" "$STAGING/incoming/$name" "$to"; }
copy_out() { local from="$1" name="$2"; install -m 600 -o "$LOGIN_USER" -g "$LOGIN_USER" "$from" "$STAGING/outgoing/$name"; }

case "$PC" in
  PC1) IPV4="$PC1_MGMT_IP" ;;
  PC3) IPV4="$PC3_MGMT_IP" ;;
  PC4) IPV4="$PC4_MGMT_IP" ;;
  PC5) IPV4="$PC5_MGMT_IP" ;;
  PC6) IPV4="$PC6_MGMT_IP" ;;
esac

preflight() {
  source /etc/os-release
  [[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]] || { echo 'Ubuntu 24.04 required' >&2; exit 1; }
  need sudo; need ip; need getent
  ip -4 -o addr show | grep -Fq " $IPV4/" || { echo "Configured management IP $IPV4 is not assigned to $PC" >&2; exit 1; }
  [[ "$(getent passwd "$LAB_USER" | cut -d: -f6)" == "$LOGIN_HOME" ]]
  free -h; df -h /; hostname
  finish
}

install_pkgs() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y git python3 python3-venv python3-pip curl jq tmux openssh-client openssh-server openssl wireguard nftables netcat-openbsd
  systemctl enable --now ssh
  case "$PC" in
    PC1)
      apt-get install -y docker.io snapd
      systemctl enable --now docker
      local major=0
      command -v node >/dev/null && major="$(node -v | sed 's/^v//' | cut -d. -f1)"
      if (( major < 20 )); then
        if ! snap list node >/dev/null 2>&1; then snap install node --classic --channel=22/stable; else snap refresh node --channel=22/stable; fi
        export PATH="/snap/bin:$PATH"
      fi
      command -v node >/dev/null || { echo 'Node >=20 required for Vite console' >&2; exit 1; }
      major="$(node -v | sed 's/^v//' | cut -d. -f1)"
      (( major >= 20 )) || { echo 'Node >=20 required for console' >&2; exit 1; }
      ;;
    PC3) apt-get install -y suricata tcpdump; systemctl disable --now suricata 2>/dev/null || : ;;
    PC4|PC5) apt-get install -y auditd python3-systemd; systemctl enable --now auditd ;;
    PC6) apt-get install -y nmap sshpass ;;
  esac
  if [[ "$PC" != PC6 ]]; then
    mkdir -p /opt/mon-lab
    if [[ ! -d "$REPO/.git" ]]; then
      git clone https://github.com/Saitanveesh/1.git "$REPO"
    fi
    [[ -z "$(git -C "$REPO" status --porcelain --untracked-files=no)" ]] || { echo 'MON checkout has local changes; refusing destructive reset' >&2; exit 1; }
    git -C "$REPO" fetch origin
    git -C "$REPO" checkout --detach "$MON_REF"
    [[ "$(git -C "$REPO" rev-parse HEAD)" == "$MON_REF" ]] || exit 1
    if [[ ! -x "$PY" ]]; then python3 -m venv --system-site-packages "$REPO/.venv"; fi
    "$PY" -m pip install -e "$REPO"
    log "Pinned MON HEAD $(git -C "$REPO" rev-parse HEAD)"
  fi
  mkdir -p /etc/mon-lab "$PRIVATE" "$REQUESTS"
  chmod 700 /etc/mon-lab "$PRIVATE" "$REQUESTS"
  finish
}

wg_key() {
  need wg
  mkdir -p /etc/wireguard
  [[ -e /etc/wireguard/mon-lab.key ]] || { wg genkey > /etc/wireguard/mon-lab.key; chmod 600 /etc/wireguard/mon-lab.key; }
  wg pubkey < /etc/wireguard/mon-lab.key > /etc/wireguard/mon-lab.pub
  copy_out /etc/wireguard/mon-lab.pub wg-public.key
  finish
}

wg_activate() {
  chmod 600 /etc/wireguard/wg0.conf
  systemctl enable wg-quick@wg0 >/dev/null
  systemctl restart wg-quick@wg0
  wg show wg0
}

wg_hub() {
  for v in PC4_PUB PC5_PUB PC6_PUB; do [[ -n "${!v:-}" ]] || { echo "Missing $v; run keys first" >&2; exit 1; }; done
  cat > /etc/wireguard/wg0.conf <<EOF2
[Interface]
Address = 10.77.0.1/24
ListenPort = 51820
PrivateKey = $(cat /etc/wireguard/mon-lab.key)

[Peer]
PublicKey = $PC4_PUB
AllowedIPs = 10.77.0.40/32

[Peer]
PublicKey = $PC5_PUB
AllowedIPs = 10.77.0.50/32

[Peer]
PublicKey = $PC6_PUB
AllowedIPs = 10.77.0.60/32
EOF2
  cat > /etc/sysctl.d/99-mon-lab-forward.conf <<'EOF2'
net.ipv4.ip_forward=1
EOF2
  sysctl -p /etc/sysctl.d/99-mon-lab-forward.conf
  wg_activate
  finish
}

wg_spoke() {
  [[ -n "${PC3_PUB:-}" ]] || { echo 'Missing PC3_PUB; run keys first' >&2; exit 1; }
  local overlay
  case "$PC" in PC4) overlay=10.77.0.40 ;; PC5) overlay=10.77.0.50 ;; PC6) overlay=10.77.0.60 ;; *) exit 2 ;; esac
  cat > /etc/wireguard/wg0.conf <<EOF2
[Interface]
Address = $overlay/32
PrivateKey = $(cat /etc/wireguard/mon-lab.key)

[Peer]
PublicKey = $PC3_PUB
Endpoint = $PC3_MGMT_IP:51820
AllowedIPs = 10.77.0.0/24
PersistentKeepalive = 15
EOF2
  wg_activate
  finish
}

wg_check() {
  ping -c 2 -W 2 10.77.0.1
  local stamp
  stamp="$(wg show wg0 latest-handshakes | awk 'NR==1{print $2}')"
  [[ "$stamp" =~ ^[0-9]+$ && "$stamp" -gt 0 ]] || { echo 'WireGuard handshake missing' >&2; exit 1; }
  finish
}

wg_guard() {
  # The attested attacker overlay IP may reach only PC4/PC5 via wg0.
  nft delete table inet mon_lab_guard 2>/dev/null || :
  nft add table inet mon_lab_guard
  nft 'add chain inet mon_lab_guard input { type filter hook input priority -100; policy accept; }'
  nft 'add chain inet mon_lab_guard forward { type filter hook forward priority -100; policy accept; }'
  nft 'add rule inet mon_lab_guard input iifname "wg0" ip saddr 10.77.0.60 drop'
  nft 'add rule inet mon_lab_guard forward iifname "wg0" ip saddr 10.77.0.60 ip daddr { 10.77.0.40, 10.77.0.50 } accept'
  nft 'add rule inet mon_lab_guard forward iifname "wg0" ip saddr 10.77.0.60 drop'
  nft 'add rule inet mon_lab_guard forward iifname "wg0" oifname != "wg0" drop'
  nft list table inet mon_lab_guard
  finish
}

start_tmux() {
  local name="$1" command="$2"
  tmux kill-session -t "$name" 2>/dev/null || :
  tmux new-session -d -s "$name" "$command"
  sleep 3
  tmux has-session -t "$name" || { echo "Session $name exited unexpectedly" >&2; exit 1; }
}

control() {
  mkdir -p /etc/mon-lab "$IDENTITY" /var/lib/mon-lab
  if [[ ! -f /etc/mon-lab/db.env ]]; then
    printf 'MON_DB_ADMIN_PASSWORD=%s\nMON_APP_DB_PASSWORD=%s\n' "$(openssl rand -hex 20)" "$(openssl rand -hex 20)" > /etc/mon-lab/db.env
    chmod 600 /etc/mon-lab/db.env
  fi
  # shellcheck disable=SC1091
  source /etc/mon-lab/db.env
  if ! docker container inspect mon-postgres >/dev/null 2>&1; then
    docker run -d --name mon-postgres --restart unless-stopped \
      -e POSTGRES_DB=mon -e POSTGRES_USER=mon -e POSTGRES_PASSWORD="$MON_DB_ADMIN_PASSWORD" \
      -p 127.0.0.1:5432:5432 -v mon-lab-pgdata:/var/lib/postgresql/data postgres:17-alpine
  else
    docker start mon-postgres >/dev/null || :
  fi
  local retries=30
  until docker exec mon-postgres pg_isready -U mon -d mon >/dev/null 2>&1; do
    ((retries--)) || { echo 'PostgreSQL did not start' >&2; exit 1; }
    sleep 1
  done
  ( cd "$REPO" && MON_DATABASE_URL="postgresql+psycopg://mon:$MON_DB_ADMIN_PASSWORD@127.0.0.1:5432/mon" .venv/bin/alembic upgrade head )
  docker exec -i mon-postgres psql -U mon -d mon <<EOF2
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mon_app_lab') THEN
    CREATE ROLE mon_app_lab LOGIN PASSWORD '$MON_APP_DB_PASSWORD'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
END
\$\$;
ALTER ROLE mon_app_lab PASSWORD '$MON_APP_DB_PASSWORD';
GRANT CONNECT ON DATABASE mon TO mon_app_lab;
GRANT USAGE ON SCHEMA public TO mon_app_lab;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO mon_app_lab;
GRANT USAGE,SELECT,UPDATE ON ALL SEQUENCES IN SCHEMA public TO mon_app_lab;
EOF2
  if [[ ! -f "$IDENTITY/jwks.json" ]]; then
    "$PY" "$REPO/tools/lab_identity.py" init --out-dir "$IDENTITY" \
      --tenant-id mon-lab --site-id site-a --site-ingress-host "$PC1_MGMT_IP" \
      --sensor-ingress-host 10.77.0.1 --token-hours 48
  fi
  [[ -f "$IDENTITY/operator.jwt" && -f "$IDENTITY/site-ca-key.pem" ]] || { echo 'Identity directory incomplete' >&2; exit 1; }
  cat > /etc/mon-lab/control.env <<EOF2
MON_DATABASE_URL=postgresql+psycopg://mon_app_lab:$MON_APP_DB_PASSWORD@127.0.0.1:5432/mon
MON_AUTH_JWKS_FILE=$IDENTITY/jwks.json
MON_AUTH_ISSUER=mon-lab
MON_AUTH_AUDIENCE=mon-control-plane
MON_SITE_CA_CERT_FILE=$IDENTITY/site-ca.pem
MON_SITE_CA_KEY_FILE=$IDENTITY/site-ca-key.pem
MON_SENSOR_CA_CERT_FILE=$IDENTITY/sensor-ca.pem
MON_SENSOR_CA_KEY_FILE=$IDENTITY/sensor-ca-key.pem
EOF2
  cat > /etc/mon-lab/ingress.env <<EOF2
MON_INTERNAL_CONTROL_PLANE_URL=http://127.0.0.1:8080
MON_MTLS_SERVER_CERT_FILE=$IDENTITY/site-ingress-server.pem
MON_MTLS_SERVER_KEY_FILE=$IDENTITY/site-ingress-server-key.pem
MON_SITE_CA_CERT_FILE=$IDENTITY/site-ca.pem
MON_MTLS_HOST=0.0.0.0
MON_MTLS_PORT=8443
EOF2
  chmod 600 /etc/mon-lab/{control,ingress}.env
  start_tmux mon-control "cd $REPO && set -a && . /etc/mon-lab/control.env && set +a && $PY -m uvicorn mon.api:app --host 127.0.0.1 --port 8080"
  curl --fail --silent --show-error http://127.0.0.1:8080/health | jq -e '.state=="READY"'
  start_tmux mon-site-ingress "set -a && . /etc/mon-lab/ingress.env && set +a && $PY -m mon.mtls_ingress"
  ss -ltn | grep -q ':8443 '
  # Explicit snap executable path because root tmux may not inherit /snap/bin PATH.
  local node_bin npm_bin
  node_bin="$(command -v node || : )"
  npm_bin="$(command -v npm || : )"
  if [[ -x /snap/bin/node && "${node_bin:-}" != /snap/bin/node ]]; then node_bin=/snap/bin/node; npm_bin=/snap/bin/npm; fi
  [[ -n "$node_bin" && -n "$npm_bin" ]] || { echo 'Node/npm missing' >&2; exit 1; }
  ( cd "$REPO/console" && "$npm_bin" install --no-audit --no-fund )
  start_tmux mon-console "cd $REPO/console && PATH=/snap/bin:\$PATH $npm_bin run dev -- --host 0.0.0.0 --port 5173"
  curl --fail --silent --show-error -o /dev/null http://127.0.0.1:5173/
  finish
}

site_csr() {
  local out="$REQUESTS/site"
  if [[ ! -f "$out/site-client.csr.pem" ]]; then
    mkdir -p "$out"
    "$PY" "$REPO/tools/lab_identity.py" site-request --out-dir "$out" --tenant-id mon-lab --site-id site-a
  fi
  copy_out "$out/site-client.csr.pem" site-client.csr.pem
  finish
}

enroll_site() {
  local out="$REQUESTS/enrolled-site"
  if [[ ! -f "$out/site-client-cert.pem" ]]; then
    "$PY" "$REPO/tools/lab_identity.py" enroll-site-csr \
      --control-url http://127.0.0.1:8080 --admin-token-file "$IDENTITY/operator.jwt" \
      --csr-file "$STAGING/incoming/site-client.csr.pem" --out-dir "$out" \
      --tenant-id mon-lab --site-id site-a
  fi
  copy_out "$out/site-client-cert.pem" site-client-cert.pem
  for f in site-ca.pem site-controller.jwt sensor-ca.pem sensor-ingress-server.pem sensor-ingress-server-key.pem; do
    copy_out "$IDENTITY/$f" "$f"
  done
  finish
}

site_start() {
  mkdir -p /var/lib/mon-site "$PRIVATE"
  install -m 600 "$REQUESTS/site/site-client-key.pem" "$PRIVATE/site-client-key.pem"
  install_copy site-client-cert.pem "$PRIVATE/site-client-cert.pem" 644
  install_copy site-ca.pem "$PRIVATE/site-ca.pem" 644
  install_copy site-controller.jwt "$PRIVATE/site-controller.jwt"
  install_copy sensor-ca.pem "$PRIVATE/sensor-ca.pem" 644
  install_copy sensor-ingress-server.pem "$PRIVATE/sensor-ingress-server.pem" 644
  install_copy sensor-ingress-server-key.pem "$PRIVATE/sensor-ingress-server-key.pem"
  cat > /etc/mon-lab/site.env <<EOF2
MON_TENANT_ID=mon-lab
MON_SITE_ID=site-a
MON_SITE_STATE_DIR=/var/lib/mon-site
MON_SITE_INGRESS_URL=https://$PC1_MGMT_IP:8443
MON_SITE_CA_CERT_FILE=$PRIVATE/site-ca.pem
MON_SITE_CLIENT_CERT_FILE=$PRIVATE/site-client-cert.pem
MON_SITE_CLIENT_KEY_FILE=$PRIVATE/site-client-key.pem
MON_SITE_BEARER_TOKEN_FILE=$PRIVATE/site-controller.jwt
MON_ENABLE_ROUTER_NFTABLES_ENFORCEMENT=1
MON_SITE_ROUTER_NFTABLES_VENDOR=linux-nftables-router
EOF2
  cat > /etc/mon-lab/sensor-ingress.env <<EOF2
MON_TENANT_ID=mon-lab
MON_SITE_ID=site-a
MON_SENSOR_INGRESS_SERVER_CERT_FILE=$PRIVATE/sensor-ingress-server.pem
MON_SENSOR_INGRESS_SERVER_KEY_FILE=$PRIVATE/sensor-ingress-server-key.pem
MON_SENSOR_CA_CERT_FILE=$PRIVATE/sensor-ca.pem
MON_SENSOR_INGRESS_HOST=0.0.0.0
MON_SENSOR_INGRESS_PORT=9443
MON_SENSOR_INTERNAL_SITE_URL=http://127.0.0.1:8090
EOF2
  chmod 600 /etc/mon-lab/{site,sensor-ingress}.env
  start_tmux mon-site "set -a && . /etc/mon-lab/site.env && set +a && $REPO/.venv/bin/mon-site"
  curl --fail --silent --show-error http://127.0.0.1:8090/health | jq -e '.state=="READY"'
  start_tmux sensor-ingress "set -a && . /etc/mon-lab/sensor-ingress.env && set +a && $REPO/.venv/bin/mon-sensor-ingress"
  ss -ltn | grep -q ':9443 '
  finish
}

sensor_id() {
  case "$PC" in PC3) echo suricata-pc3 ;; PC4) echo linux-pc4 ;; PC5) echo linux-pc5 ;; *) exit 2 ;; esac
}
sensor_csr() {
  local out="$REQUESTS/sensor" id
  id="$(sensor_id)"
  if [[ ! -f "$out/sensor-client.csr.pem" ]]; then
    mkdir -p "$out"
    "$PY" "$REPO/tools/lab_identity.py" sensor-request --out-dir "$out" \
      --tenant-id mon-lab --site-id site-a --sensor-id "$id"
  fi
  copy_out "$out/sensor-client.csr.pem" sensor-client.csr.pem
  finish
}

enroll_sensor() {
  local p="$1" id out
  case "$p" in PC3) id=suricata-pc3 ;; PC4) id=linux-pc4 ;; PC5) id=linux-pc5 ;; *) exit 2 ;; esac
  out="$REQUESTS/enrolled-$p"
  if [[ ! -f "$out/sensor-client-cert.pem" ]]; then
    "$PY" "$REPO/tools/lab_identity.py" enroll-sensor-csr \
      --control-url http://127.0.0.1:8080 --admin-token-file "$IDENTITY/operator.jwt" \
      --csr-file "$STAGING/incoming/$p-sensor-client.csr.pem" --out-dir "$out" \
      --tenant-id mon-lab --site-id site-a --sensor-id "$id"
  fi
  copy_out "$out/sensor-client-cert.pem" "$p-sensor-client-cert.pem"
  copy_out "$IDENTITY/sensor-ca.pem" sensor-ca.pem
  finish
}

sensor_install() {
  local id
  id="$(sensor_id)"
  install -m 600 "$REQUESTS/sensor/sensor-client-key.pem" "$PRIVATE/$id-key.pem"
  install_copy sensor-client-cert.pem "$PRIVATE/$id.pem" 644
  install_copy sensor-ca.pem "$PRIVATE/sensor-ca.pem" 644
  finish
}

sensor_start() {
  mkdir -p /var/lib/mon-sensor
  cat > /etc/mon-lab/suricata.env <<EOF2
MON_TENANT_ID=mon-lab
MON_SITE_ID=site-a
MON_SENSOR_ID=suricata-pc3
MON_SENSOR_INGRESS_URL=https://10.77.0.1:9443
MON_SENSOR_SERVER_CA_CERT_FILE=$PRIVATE/sensor-ca.pem
MON_SENSOR_CLIENT_CERT_FILE=$PRIVATE/suricata-pc3.pem
MON_SENSOR_CLIENT_KEY_FILE=$PRIVATE/suricata-pc3-key.pem
MON_SENSOR_STATE_DIR=/var/lib/mon-sensor
MON_SURICATA_EVE_FILE=/var/log/suricata/eve.json
MON_SENSOR_POLL_INTERVAL_SECONDS=1
MON_SENSOR_HEARTBEAT_INTERVAL_SECONDS=15
EOF2
  chmod 600 /etc/mon-lab/suricata.env
  start_tmux suricata 'suricata -c /etc/suricata/suricata.yaml --af-packet=wg0 -k none'
  start_tmux suricata-collector "set -a && . /etc/mon-lab/suricata.env && set +a && $REPO/.venv/bin/mon-suricata-collector"
  finish
}

victim_start() {
  [[ "$PC" == PC4 || "$PC" == PC5 ]] || exit 2
  apt-get install -y openssh-server python3-systemd auditd
  systemctl enable --now ssh auditd
  if ! getent passwd monlab >/dev/null; then
    useradd -m -s /bin/bash monlab
    touch /etc/mon-lab/monlab-created
  fi
  # Only the throwaway monlab user has password-based SSH on the overlay.
  printf 'Match User monlab Address 10.77.0.0/24\n    PasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/99-monlab-lab.conf
  printf '%s\n' 'monlab:Lab-Only-Not-A-Real-Password-1' | chpasswd
  if ! sshd -t; then
    rm -f /etc/ssh/sshd_config.d/99-monlab-lab.conf
    echo 'SSH config validation failed; restored the previous config' >&2
    exit 1
  fi
  systemctl reload ssh
  nft delete table inet mon_lab_victim 2>/dev/null || :
  nft add table inet mon_lab_victim
  nft 'add chain inet mon_lab_victim input { type filter hook input priority 0; policy accept; }'
  nft 'add rule inet mon_lab_victim input ip saddr 10.77.0.60 tcp dport 20000-20099 drop'
  finish
}

collector_start() {
  local id
  id="$(sensor_id)"
  mkdir -p /var/lib/mon-linux-endpoint-collector
  start_tmux mon-linux "${REPO}/.venv/bin/mon-linux-endpoint-collector foreground --tenant-id mon-lab --site-id site-a --sensor-id $id --state-dir /var/lib/mon-linux-endpoint-collector --ssh-unit ssh.service --sensor-ingress-url https://10.77.0.1:9443 --server-ca-file $PRIVATE/sensor-ca.pem --client-cert-file $PRIVATE/$id.pem --client-key-file $PRIVATE/$id-key.pem --poll-interval-seconds 5"
  finish
}

api_get() {
  curl -fsS -H "Authorization: Bearer $(cat "$IDENTITY/operator.jwt")" "http://127.0.0.1:8080$1"
}
api_post() {
  curl -fsS -X POST -H "Authorization: Bearer $(cat "$IDENTITY/operator.jwt")" \
    -H 'Content-Type: application/json' -d "$2" "http://127.0.0.1:8080$1"
}
register_router() {
  if api_get '/api/v1/enforcement-points?tenant_id=mon-lab&site_id=site-a' \
    | jq -e 'any(.[]; .enforcement_point_id=="pc3-router")' >/dev/null; then
    log 'pc3-router already registered'
  else
    api_post /api/v1/enforcement-points '{"enforcement_point_id":"pc3-router","tenant_id":"mon-lab","site_id":"site-a","kind":"ROUTER","vendor":"linux-nftables-router","capabilities":["BLOCK_IP"],"priority":100,"attributes":{}}' | jq .
  fi
  finish
}

status() {
  case "$PC" in
    PC1)
      curl -fsS http://127.0.0.1:8080/health | jq -e '.state=="READY"'
      curl -fsS -o /dev/null http://127.0.0.1:5173/
      ss -ltn | grep -q ':8443 '
      api_get '/api/v1/sensors?tenant_id=mon-lab&site_id=site-a' | jq -c '.[] | {sensor_id,state,collector_kind,heartbeat_age_seconds}'
      api_get '/api/v1/enforcement-points?tenant_id=mon-lab&site_id=site-a' | jq -e 'any(.[]; .enforcement_point_id=="pc3-router")'
      ;;
    PC3)
      curl -fsS http://127.0.0.1:8090/health | jq -e '.state=="READY"'
      tmux has-session -t sensor-ingress; tmux has-session -t suricata; tmux has-session -t suricata-collector
      ss -ltn | grep -q ':9443 '
      nft list table inet mon_lab_guard >/dev/null
      wg show wg0
      ;;
    PC4|PC5)
      tmux has-session -t mon-linux
      wg show wg0
      systemctl is-active --quiet ssh
      ;;
    PC6)
      wg show wg0
      timeout 4 bash -c 'echo > /dev/tcp/10.77.0.50/22'
      ;;
  esac
  finish
}

lockdown() {
  [[ "$PC" == PC6 ]] || exit 2
  need wg; need nft
  wg show wg0 >/dev/null
  timeout 4 bash -c 'echo > /dev/tcp/10.77.0.50/22' || { echo 'PC5 SSH unreachable from PC6; refusing lockdown' >&2; exit 1; }
  local mgmtif
  mgmtif="$(ip route get "$PC3_MGMT_IP" | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
  [[ -n "$mgmtif" && "$mgmtif" != wg0 ]] || { echo 'Cannot find physical management interface' >&2; exit 1; }
  # Preserve precisely the SSH admin replies to PC2 and WG transport to PC3.
  nft delete table inet mon_lab_egress 2>/dev/null || :
  nft add table inet mon_lab_egress
  nft 'add chain inet mon_lab_egress output { type filter hook output priority -100; policy accept; }'
  nft add rule inet mon_lab_egress output oifname "$mgmtif" ip daddr "$PC2_MGMT_IP" tcp sport 22 ct state established accept
  nft add rule inet mon_lab_egress output oifname "$mgmtif" ip daddr "$PC3_MGMT_IP" udp dport 51820 accept
  nft add rule inet mon_lab_egress output oifname "$mgmtif" udp sport 68 udp dport 67 accept
  nft add rule inet mon_lab_egress output oifname "$mgmtif" drop
  nft list table inet mon_lab_egress
  finish
}

cleanup_exchange() {
  # Remove staged CSRs, certificates and the site token from unprivileged
  # SSH users; long-term secret state remains root-readable only.
  find "$STAGING/incoming" "$STAGING/outgoing" -maxdepth 1 -type f ! -name wg-public.key -delete
  finish
}

teardown() {
  case "$PC" in
    PC1) for sess in mon-console mon-site-ingress mon-control; do tmux kill-session -t "$sess" 2>/dev/null || :; done ;;
    PC3)
      for sess in sensor-ingress mon-site suricata-collector suricata; do tmux kill-session -t "$sess" 2>/dev/null || :; done
      nft delete table inet mon_router 2>/dev/null || :
      nft delete table inet mon_lab_guard 2>/dev/null || :
      systemctl disable --now wg-quick@wg0 || :
      ;;
    PC4|PC5)
      tmux kill-session -t mon-linux 2>/dev/null || :
      nft delete table inet mon_lab_victim 2>/dev/null || :
      rm -f /etc/ssh/sshd_config.d/99-monlab-lab.conf
      sshd -t && systemctl reload ssh
      if [[ -f /etc/mon-lab/monlab-created ]]; then userdel -r monlab || :; rm -f /etc/mon-lab/monlab-created; fi
      systemctl disable --now wg-quick@wg0 || :
      ;;
    PC6)
      nft delete table inet mon_lab_egress 2>/dev/null || :
      systemctl disable --now wg-quick@wg0 || :
      ;;
  esac
  finish
}

case "$STAGE" in
  preflight) preflight ;;
  install) install_pkgs ;;
  wg-key) wg_key ;;
  wg-hub) [[ "$PC" == PC3 ]] || exit 2; wg_hub ;;
  wg-spoke) wg_spoke ;;
  wg-check) wg_check ;;
  wg-guard) [[ "$PC" == PC3 ]] || exit 2; wg_guard ;;
  control) [[ "$PC" == PC1 ]] || exit 2; control ;;
  site-csr) [[ "$PC" == PC3 ]] || exit 2; site_csr ;;
  enroll-site) [[ "$PC" == PC1 ]] || exit 2; enroll_site ;;
  site-start) [[ "$PC" == PC3 ]] || exit 2; site_start ;;
  sensor-csr) sensor_csr ;;
  enroll-PC3|enroll-PC4|enroll-PC5) [[ "$PC" == PC1 ]] || exit 2; enroll_sensor "${STAGE#enroll-}" ;;
  sensor-install) sensor_install ;;
  sensor-start) [[ "$PC" == PC3 ]] || exit 2; sensor_start ;;
  victim-start) [[ "$PC" == PC4 || "$PC" == PC5 ]] || exit 2; victim_start ;;
  collector-start) [[ "$PC" == PC4 || "$PC" == PC5 ]] || exit 2; collector_start ;;
  register-router) [[ "$PC" == PC1 ]] || exit 2; register_router ;;
  status) status ;;
  cleanup-exchange) cleanup_exchange ;;
  lockdown) lockdown ;;
  teardown) teardown ;;
  *) echo "Unknown stage: $STAGE" >&2; exit 2 ;;
esac

