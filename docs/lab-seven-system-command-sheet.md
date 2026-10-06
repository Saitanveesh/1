# MON seven-system test-day command sheet

Disposable lab only. Pinned code: `8f66baa9f8d287b8c05da379259b289c661c5828`. Every command below is copy-paste; the only things you edit are the values in section 0. Run the numbered steps **in order**. Each step is tagged with the machine that runs it.

Live scenario (all real, nothing seeded): TCP probe -> Suricata flow evidence -> SSH/SMB authentication abuse -> Linux/Windows endpoint evidence -> correlation on the attacker source -> operator plan/approve/execute -> PC3 router `BLOCK_IP` -> packet-flow check from PC6 -> rollback -> connectivity restored -> audit trail.

Rules for the day:

- Never start `demo/mon_cinematic`, `tools/soc_acceptance_seed.py` or anything under `e2e/` on a lab machine. They are CI/presentation tooling, not live telemetry.
- Attack only the two designated victims (PC4 `10.77.0.40`, PC5 `10.77.0.50`). Nothing else.
- Do not edit code during the demo. If a stage fails, say so; do not substitute recorded data.

## 0. Fixed roles, overlay and shared values

| PC | Role | OS | Overlay IP |
| --- | --- | --- | --- |
| PC1 | control plane, PostgreSQL, site mTLS ingress, console | Ubuntu 24.04 | none (management LAN only) |
| PC2 | admin / evidence station | Ubuntu 24.04 | none |
| PC3 | Site Controller, WireGuard hub, router enforcement, Suricata, sensor ingress | Ubuntu 24.04 | `10.77.0.1` |
| PC4 | Windows victim, MON Windows endpoint collector | Windows 11 | `10.77.0.40` |
| PC5 | Linux victim, SSH, MON Linux endpoint collector | Ubuntu 24.04 | `10.77.0.50` |
| PC6 | attacker | Ubuntu 24.04 or Kali | `10.77.0.60` |
| PC7 | operator browser | any | none |

Identity everywhere: tenant `mon-lab`, site `site-a`. Sensor ids: `suricata-pc3`, `linux-pc5`, `windows-pc4`.

Create this file on **every Ubuntu machine** (PC1, PC2, PC3, PC5, PC6), edit the four `<...>` values once, then `source ~/lab.env` in every new shell.

~~~bash
cat > ~/lab.env <<'EOF'
export MON_REF=8f66baa9f8d287b8c05da379259b289c661c5828
export LAB_USER=<ubuntu-login-user-on-the-lab-machines>
export PC1_MGMT_IP=<PC1-management-IP>
export PC3_MGMT_IP=<PC3-management-IP>
export PC5_MGMT_IP=<PC5-management-IP>
export TENANT=mon-lab
export SITE=site-a
EOF
source ~/lab.env
~~~

`MON_REF` is pinned to the PR 85 merge commit `8f66baa9f8d287b8c05da379259b289c661c5828`. Every MON node (and PC4 in section 8.3) must report exactly that `git rev-parse HEAD`. Do not change code on test day.

## 1. Every Ubuntu MON node — checkout (PC1, PC3, PC5; PC6 does not need MON)

~~~bash
source ~/lab.env
sudo apt-get update
sudo apt-get install -y git python3 python3-venv python3-pip curl jq tmux openssh-client openssl
rm -rf ~/mon
git clone https://github.com/Saitanveesh/1.git ~/mon
cd ~/mon
git checkout "$MON_REF"
python3 -m venv --system-site-packages .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
git rev-parse HEAD
~~~

`--system-site-packages` is required on PC5 so the Linux collector can import the distribution `python3-systemd` journal bindings. It is harmless elsewhere.

## 2. PC1 — database, identity material, control plane, ingress, console

### 2.1 PostgreSQL with a non-bypass application role

~~~bash
source ~/lab.env
sudo apt-get install -y docker.io
sudo systemctl enable --now docker
umask 077
export MON_DB_ADMIN_PASSWORD="$(openssl rand -hex 20)"
export MON_APP_DB_PASSWORD="$(openssl rand -hex 20)"
cat > "$HOME/mon-lab-db.env" <<EOF
MON_DB_ADMIN_PASSWORD=$MON_DB_ADMIN_PASSWORD
MON_APP_DB_PASSWORD=$MON_APP_DB_PASSWORD
EOF
source "$HOME/mon-lab-db.env"

sudo docker rm -f mon-postgres 2>/dev/null || true
sudo docker run -d --name mon-postgres -e POSTGRES_DB=mon -e POSTGRES_USER=mon \
  -e POSTGRES_PASSWORD="$MON_DB_ADMIN_PASSWORD" -p 127.0.0.1:5432:5432 postgres:17-alpine
until sudo docker exec mon-postgres pg_isready -U mon -d mon; do sleep 1; done

cd ~/mon && . .venv/bin/activate
export MON_ADMIN_DATABASE_URL="postgresql+psycopg://mon:$MON_DB_ADMIN_PASSWORD@127.0.0.1:5432/mon"
MON_DATABASE_URL="$MON_ADMIN_DATABASE_URL" alembic upgrade head

sudo docker exec -i mon-postgres psql -U mon -d mon <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mon_app_lab') THEN
    CREATE ROLE mon_app_lab LOGIN PASSWORD '$MON_APP_DB_PASSWORD'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
END
\$\$;
GRANT CONNECT ON DATABASE mon TO mon_app_lab;
GRANT USAGE ON SCHEMA public TO mon_app_lab;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO mon_app_lab;
GRANT USAGE,SELECT,UPDATE ON ALL SEQUENCES IN SCHEMA public TO mon_app_lab;
SQL
~~~

### 2.2 Disposable auth and CA material

The sensor-ingress certificate is issued for the overlay address `10.77.0.1` because victims and the Suricata collector reach PC3 over the overlay. The site-ingress certificate is issued for PC1's management address.

~~~bash
source ~/lab.env
cd ~/mon && . .venv/bin/activate
rm -rf "$HOME/mon-lab-identity"
python tools/lab_identity.py init --out-dir "$HOME/mon-lab-identity" \
  --tenant-id "$TENANT" --site-id "$SITE" \
  --site-ingress-host "$PC1_MGMT_IP" --sensor-ingress-host 10.77.0.1 --token-hours 12
ls -l "$HOME/mon-lab-identity"
~~~

Tokens last 12 hours. Re-run `init` into a fresh directory (and re-enroll everything) if they expire.

### 2.3 Control plane

~~~bash
source ~/lab.env; source "$HOME/mon-lab-db.env"
cat > "$HOME/mon-control.env" <<EOF
MON_DATABASE_URL=postgresql+psycopg://mon_app_lab:$MON_APP_DB_PASSWORD@127.0.0.1:5432/mon
MON_AUTH_JWKS_FILE=$HOME/mon-lab-identity/jwks.json
MON_AUTH_ISSUER=mon-lab
MON_AUTH_AUDIENCE=mon-control-plane
MON_SITE_CA_CERT_FILE=$HOME/mon-lab-identity/site-ca.pem
MON_SITE_CA_KEY_FILE=$HOME/mon-lab-identity/site-ca-key.pem
MON_SENSOR_CA_CERT_FILE=$HOME/mon-lab-identity/sensor-ca.pem
MON_SENSOR_CA_KEY_FILE=$HOME/mon-lab-identity/sensor-ca-key.pem
EOF
chmod 600 "$HOME/mon-control.env"
tmux kill-session -t mon-control 2>/dev/null || true
tmux new-session -d -s mon-control \
  "cd $HOME/mon && . .venv/bin/activate && set -a && . $HOME/mon-control.env && set +a && python -m uvicorn mon.api:app --host 127.0.0.1 --port 8080"
sleep 3
curl -fsS http://127.0.0.1:8080/health | jq
~~~

Expected: `"state": "READY"`.

### 2.4 Site mTLS ingress

~~~bash
source ~/lab.env
cat > "$HOME/mon-site-ingress.env" <<EOF
MON_INTERNAL_CONTROL_PLANE_URL=http://127.0.0.1:8080
MON_MTLS_SERVER_CERT_FILE=$HOME/mon-lab-identity/site-ingress-server.pem
MON_MTLS_SERVER_KEY_FILE=$HOME/mon-lab-identity/site-ingress-server-key.pem
MON_SITE_CA_CERT_FILE=$HOME/mon-lab-identity/site-ca.pem
MON_MTLS_HOST=0.0.0.0
MON_MTLS_PORT=8443
EOF
chmod 600 "$HOME/mon-site-ingress.env"
tmux kill-session -t mon-site-ingress 2>/dev/null || true
tmux new-session -d -s mon-site-ingress \
  "cd $HOME/mon && . .venv/bin/activate && set -a && . $HOME/mon-site-ingress.env && set +a && python -m mon.mtls_ingress"
sleep 2; tmux ls
~~~

### 2.5 Console (live backend only)

~~~bash
sudo apt-get install -y nodejs npm
cd ~/mon/console
npm install --no-audit --no-fund
tmux kill-session -t mon-console 2>/dev/null || true
tmux new-session -d -s mon-console "cd $HOME/mon/console && npm run dev -- --host 0.0.0.0 --port 5173"
sleep 5
curl -fsS -o /dev/null -w "console HTTP %{http_code}\n" http://127.0.0.1:5173/
~~~

The console proxies `/api` and `/ws` to the real control plane on `127.0.0.1:8080`. It has no offline or demo data source.

### 2.6 Helper for later steps (PC1)

~~~bash
cat >> ~/lab.env <<'EOF'
mon_api() { curl -fsS -H "Authorization: Bearer $(cat $HOME/mon-lab-identity/operator.jwt)" "http://127.0.0.1:8080$1"; }
mon_post() { curl -fsS -X POST -H "Authorization: Bearer $(cat $HOME/mon-lab-identity/operator.jwt)" -H 'Content-Type: application/json' -d "$2" "http://127.0.0.1:8080$1"; }
export SCOPE="tenant_id=mon-lab&site_id=site-a"
EOF
source ~/lab.env
mkdir -p ~/csr ~/enrolled
~~~

## 3. WireGuard overlay and hard isolation

Underlay is the management LAN. All attack traffic must stay inside `10.77.0.0/24`.

### 3.1 Keys (PC3, PC5, PC6) — then PC4 in section 8.2

~~~bash
sudo apt-get install -y wireguard nftables
umask 077
wg genkey | tee "$HOME/wg-private.key" | wg pubkey > "$HOME/wg-public.key"
echo "PUBLIC KEY: $(cat $HOME/wg-public.key)"
~~~

Write the three public keys down. On **PC4** (section 8.2) generate the fourth. Then on each of PC3, PC5, PC6 add the keys you need to `~/lab.env`:

~~~bash
cat >> ~/lab.env <<'EOF'
export PC3_PUB=<PC3-public-key>
export PC4_PUB=<PC4-public-key>
export PC5_PUB=<PC5-public-key>
export PC6_PUB=<PC6-public-key>
EOF
source ~/lab.env
~~~

### 3.2 PC3 hub

~~~bash
source ~/lab.env
sudo tee /etc/wireguard/wg0.conf >/dev/null <<EOF
[Interface]
Address = 10.77.0.1/24
ListenPort = 51820
PrivateKey = $(cat $HOME/wg-private.key)

[Peer]
PublicKey = $PC4_PUB
AllowedIPs = 10.77.0.40/32

[Peer]
PublicKey = $PC5_PUB
AllowedIPs = 10.77.0.50/32

[Peer]
PublicKey = $PC6_PUB
AllowedIPs = 10.77.0.60/32
EOF
sudo chmod 600 /etc/wireguard/wg0.conf
sudo systemctl enable --now wg-quick@wg0
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-mon-lab.conf
sudo sysctl --system >/dev/null
sysctl net.ipv4.ip_forward
~~~

### 3.3 PC5 and PC6 spokes

PC5 (`ME_IP=10.77.0.50`) and PC6 (`ME_IP=10.77.0.60`) — set the right one:

~~~bash
source ~/lab.env
export ME_IP=<10.77.0.50-on-PC5-or-10.77.0.60-on-PC6>
sudo tee /etc/wireguard/wg0.conf >/dev/null <<EOF
[Interface]
Address = $ME_IP/32
PrivateKey = $(cat $HOME/wg-private.key)

[Peer]
PublicKey = $PC3_PUB
Endpoint = $PC3_MGMT_IP:51820
AllowedIPs = 10.77.0.0/24
PersistentKeepalive = 15
EOF
sudo chmod 600 /etc/wireguard/wg0.conf
sudo systemctl enable --now wg-quick@wg0
ping -c 2 -W 2 10.77.0.1 || true
sudo wg show
~~~

On PC6 the ping to `10.77.0.1` may be dropped once the guard below is in place; the handshake on PC3 is the proof.

### 3.4 PC3 guard: restrict the attacker overlay address

~~~bash
sudo nft delete table inet mon_lab_guard 2>/dev/null || true
sudo nft add table inet mon_lab_guard
sudo nft 'add chain inet mon_lab_guard input { type filter hook input priority -100; policy accept; }'
sudo nft 'add chain inet mon_lab_guard forward { type filter hook forward priority -100; policy accept; }'
sudo nft 'add rule inet mon_lab_guard input iifname "wg0" ip saddr 10.77.0.60 drop'
sudo nft 'add rule inet mon_lab_guard forward iifname "wg0" ip saddr 10.77.0.60 ip daddr { 10.77.0.40, 10.77.0.50 } accept'
sudo nft 'add rule inet mon_lab_guard forward iifname "wg0" ip saddr 10.77.0.60 drop'
sudo nft 'add rule inet mon_lab_guard forward iifname "wg0" oifname != "wg0" drop'
sudo nft list table inet mon_lab_guard
sudo wg show
~~~

`accept` in this chain does not stop later chains: the MON router chain (priority 0) still evaluates and can drop forwarded traffic.

### 3.5 PC6 packages, then egress guard

**Install everything first and operate PC6 at its own keyboard, not over SSH on the management LAN.** The guard below cuts all PC6 management-LAN traffic except WireGuard transport.

~~~bash
source ~/lab.env
sudo apt-get install -y nmap sshpass netcat-openbsd smbclient jq
export MGMT_IF=<PC6-management-interface-name>
sudo nft delete table inet mon_lab_egress 2>/dev/null || true
sudo nft add table inet mon_lab_egress
sudo nft 'add chain inet mon_lab_egress output { type filter hook output priority -100; policy accept; }'
sudo nft add rule inet mon_lab_egress output oifname "$MGMT_IF" ip daddr "$PC3_MGMT_IP" udp dport 51820 accept
sudo nft add rule inet mon_lab_egress output oifname "$MGMT_IF" udp sport 68 udp dport 67 accept
sudo nft add rule inet mon_lab_egress output oifname "$MGMT_IF" drop
sudo nft list table inet mon_lab_egress
~~~

### 3.5b Isolation proof (do not continue if any line fails)

PC6, after PC5 (section 7) and PC4 (section 8) are online; this check is repeated before the scenario:

~~~bash
source ~/lab.env
echo "--- must succeed ---"
nc -zv -w3 10.77.0.50 22 2>&1 | tail -1      # needs PC5 sshd (section 8)
echo "--- must FAIL (timeout) ---"
! nc -zv -w3 10.77.0.1 22
! nc -zv -w3 "$PC1_MGMT_IP" 22
! nc -zv -w3 "$PC3_MGMT_IP" 22
echo "isolation OK"
~~~

On PC3: `sudo wg show` must show a current `latest handshake` for all three peers.

## 4. PC3 — packages, MON identity, Suricata, router enforcement

### 4.1 Packages

~~~bash
source ~/lab.env
sudo apt-get install -y suricata jq tcpdump
sudo systemctl disable --now suricata 2>/dev/null || true
sudo suricata-update || echo 'rule update skipped (offline); flow evidence does not need rules'
sudo mkdir -p /etc/mon /var/lib/mon-site /var/lib/mon-sensor
sudo chmod 700 /etc/mon
~~~

### 4.2 Site CSR (PC3) and enrollment (PC1)

PC3:

~~~bash
source ~/lab.env
cd ~/mon && . .venv/bin/activate
rm -rf ~/site-id && mkdir ~/site-id
python tools/lab_identity.py site-request --out-dir ~/site-id --tenant-id "$TENANT" --site-id "$SITE"
ssh "$LAB_USER@$PC1_MGMT_IP" "mkdir -p ~/csr/site-pc3"
scp ~/site-id/site-client.csr.pem "$LAB_USER@$PC1_MGMT_IP:~/csr/site-pc3/"
~~~

PC1:

~~~bash
source ~/lab.env
cd ~/mon && . .venv/bin/activate
rm -rf ~/enrolled/site-pc3
python tools/lab_identity.py enroll-site-csr --control-url http://127.0.0.1:8080 \
  --admin-token-file ~/mon-lab-identity/operator.jwt \
  --csr-file ~/csr/site-pc3/site-client.csr.pem --out-dir ~/enrolled/site-pc3 \
  --tenant-id "$TENANT" --site-id "$SITE"
ls ~/enrolled/site-pc3
~~~

PC3 (pull the results and the shared material):

~~~bash
source ~/lab.env
scp "$LAB_USER@$PC1_MGMT_IP:~/enrolled/site-pc3/site-client-cert.pem" ~/site-id/
scp "$LAB_USER@$PC1_MGMT_IP:~/mon-lab-identity/site-ca.pem" ~/site-id/
scp "$LAB_USER@$PC1_MGMT_IP:~/mon-lab-identity/site-controller.jwt" ~/site-id/
scp "$LAB_USER@$PC1_MGMT_IP:~/mon-lab-identity/sensor-ca.pem" ~/site-id/
scp "$LAB_USER@$PC1_MGMT_IP:~/mon-lab-identity/sensor-ingress-server.pem" ~/site-id/
scp "$LAB_USER@$PC1_MGMT_IP:~/mon-lab-identity/sensor-ingress-server-key.pem" ~/site-id/
sudo install -m 600 ~/site-id/site-client-key.pem /etc/mon/site-client-key.pem
sudo install -m 644 ~/site-id/site-client-cert.pem /etc/mon/site-client-cert.pem
sudo install -m 644 ~/site-id/site-ca.pem /etc/mon/site-ca.pem
sudo install -m 600 ~/site-id/site-controller.jwt /etc/mon/site-controller.jwt
sudo install -m 644 ~/site-id/sensor-ca.pem /etc/mon/sensor-ca.pem
sudo install -m 644 ~/site-id/sensor-ingress-server.pem /etc/mon/sensor-ingress-server.pem
sudo install -m 600 ~/site-id/sensor-ingress-server-key.pem /etc/mon/sensor-ingress-server-key.pem
sudo ls -l /etc/mon
~~~

### 4.3 Suricata sensor identity (PC3 CSR, PC1 enroll, PC3 pull)

PC3:

~~~bash
source ~/lab.env
cd ~/mon && . .venv/bin/activate
rm -rf ~/suricata-id && mkdir ~/suricata-id
python tools/lab_identity.py sensor-request --out-dir ~/suricata-id \
  --tenant-id "$TENANT" --site-id "$SITE" --sensor-id suricata-pc3
ssh "$LAB_USER@$PC1_MGMT_IP" "mkdir -p ~/csr/suricata-pc3"
scp ~/suricata-id/sensor-client.csr.pem "$LAB_USER@$PC1_MGMT_IP:~/csr/suricata-pc3/"
~~~

PC1:

~~~bash
source ~/lab.env
cd ~/mon && . .venv/bin/activate
rm -rf ~/enrolled/suricata-pc3
python tools/lab_identity.py enroll-sensor-csr --control-url http://127.0.0.1:8080 \
  --admin-token-file ~/mon-lab-identity/operator.jwt \
  --csr-file ~/csr/suricata-pc3/sensor-client.csr.pem --out-dir ~/enrolled/suricata-pc3 \
  --tenant-id "$TENANT" --site-id "$SITE" --sensor-id suricata-pc3
~~~

PC3:

~~~bash
source ~/lab.env
scp "$LAB_USER@$PC1_MGMT_IP:~/enrolled/suricata-pc3/sensor-client-cert.pem" ~/suricata-id/
sudo install -m 600 ~/suricata-id/sensor-client-key.pem /etc/mon/suricata-pc3-key.pem
sudo install -m 644 ~/suricata-id/sensor-client-cert.pem /etc/mon/suricata-pc3.pem
~~~

### 4.4 Start `mon-site` with router enforcement (PC3, root inside the disposable VM)

~~~bash
source ~/lab.env
sudo tee /etc/mon/mon-site.env >/dev/null <<EOF
MON_TENANT_ID=$TENANT
MON_SITE_ID=$SITE
MON_SITE_STATE_DIR=/var/lib/mon-site
MON_SITE_INGRESS_URL=https://$PC1_MGMT_IP:8443
MON_SITE_CA_CERT_FILE=/etc/mon/site-ca.pem
MON_SITE_CLIENT_CERT_FILE=/etc/mon/site-client-cert.pem
MON_SITE_CLIENT_KEY_FILE=/etc/mon/site-client-key.pem
MON_SITE_BEARER_TOKEN_FILE=/etc/mon/site-controller.jwt
MON_ENABLE_ROUTER_NFTABLES_ENFORCEMENT=1
MON_SITE_ROUTER_NFTABLES_VENDOR=linux-nftables-router
EOF
sudo chmod 600 /etc/mon/mon-site.env
tmux kill-session -t mon-site 2>/dev/null || sudo tmux kill-session -t mon-site 2>/dev/null || true
sudo tmux new-session -d -s mon-site \
  "cd $HOME/mon && set -a && . /etc/mon/mon-site.env && set +a && $HOME/mon/.venv/bin/mon-site"
sleep 5
curl -fsS http://127.0.0.1:8090/health | jq
~~~

Expected: health reports the cloud sender and command channel configured (no "not configured" text). PC3 must not run an unrelated firewall flush; `sudo nft list ruleset` must still contain `mon_lab_guard`.

### 4.5 Sensor ingress (PC3)

~~~bash
source ~/lab.env
sudo tee /etc/mon/sensor-ingress.env >/dev/null <<EOF
MON_TENANT_ID=$TENANT
MON_SITE_ID=$SITE
MON_SENSOR_INGRESS_SERVER_CERT_FILE=/etc/mon/sensor-ingress-server.pem
MON_SENSOR_INGRESS_SERVER_KEY_FILE=/etc/mon/sensor-ingress-server-key.pem
MON_SENSOR_CA_CERT_FILE=/etc/mon/sensor-ca.pem
MON_SENSOR_INGRESS_HOST=0.0.0.0
MON_SENSOR_INGRESS_PORT=9443
MON_SENSOR_INTERNAL_SITE_URL=http://127.0.0.1:8090
EOF
sudo chmod 600 /etc/mon/sensor-ingress.env
sudo tmux kill-session -t sensor-ingress 2>/dev/null || true
sudo tmux new-session -d -s sensor-ingress \
  "set -a && . /etc/mon/sensor-ingress.env && set +a && $HOME/mon/.venv/bin/mon-sensor-ingress"
sleep 3
sudo ss -ltnp | grep 9443
~~~

Wait about 20 seconds for the Site Controller to synchronize the sensor trust snapshot (it polls every 15 s) before starting collectors.

### 4.6 Suricata on the overlay interface (PC3)

~~~bash
sudo tmux kill-session -t suricata 2>/dev/null || true
sudo tmux new-session -d -s suricata \
  "suricata -c /etc/suricata/suricata.yaml --af-packet=wg0 -k none"
sleep 15
sudo tail -n 3 /var/log/suricata/suricata.log
sudo tail -n 5 /var/log/suricata/eve.json | jq -c '.event_type' 
~~~

`-k none` is needed because WireGuard interfaces do not carry meaningful checksums. Expect `stats` records at least. `flow` records appear when traffic crosses `wg0`.

### 4.7 Suricata collector (PC3)

~~~bash
source ~/lab.env
sudo tee /etc/mon/suricata-collector.env >/dev/null <<EOF
MON_TENANT_ID=$TENANT
MON_SITE_ID=$SITE
MON_SENSOR_ID=suricata-pc3
MON_SENSOR_INGRESS_URL=https://10.77.0.1:9443
MON_SENSOR_SERVER_CA_CERT_FILE=/etc/mon/sensor-ca.pem
MON_SENSOR_CLIENT_CERT_FILE=/etc/mon/suricata-pc3.pem
MON_SENSOR_CLIENT_KEY_FILE=/etc/mon/suricata-pc3-key.pem
MON_SENSOR_STATE_DIR=/var/lib/mon-sensor
MON_SURICATA_EVE_FILE=/var/log/suricata/eve.json
MON_SENSOR_POLL_INTERVAL_SECONDS=1
MON_SENSOR_HEARTBEAT_INTERVAL_SECONDS=15
EOF
sudo chmod 600 /etc/mon/suricata-collector.env
sudo tmux kill-session -t suricata-collector 2>/dev/null || true
sudo tmux new-session -d -s suricata-collector \
  "set -a && . /etc/mon/suricata-collector.env && set +a && $HOME/mon/.venv/bin/mon-suricata-collector"
sleep 5
sudo tmux capture-pane -p -t suricata-collector | tail -5
~~~

PC1, confirm the sensor is live (not a seeded row):

~~~bash
source ~/lab.env
mon_api "/api/v1/sensors?$SCOPE" | jq '.[] | {sensor_id, state, collector_kind, heartbeat_age_seconds}'
~~~

Expected: `suricata-pc3`, kind `SURICATA`, small `heartbeat_age_seconds`.

## 5. Enforcement registration (PC1)

Register PC3 as the router. This is control-plane configuration; the matching adapter is already active in `mon-site` on PC3.

~~~bash
source ~/lab.env
mon_post /api/v1/enforcement-points '{
  "enforcement_point_id": "pc3-router",
  "tenant_id": "mon-lab", "site_id": "site-a",
  "kind": "ROUTER", "vendor": "linux-nftables-router",
  "capabilities": ["BLOCK_IP"], "priority": 100, "attributes": {}
}' | jq '{enforcement_point_id, kind, vendor, capabilities, health}'
~~~

Victim assets only exist after their collectors have produced real events, so bind them in section 10.1 (after the baseline logins).

## 6. Operator browser (PC7)

Open `http://<PC1-management-IP>:5173/?tenant=mon-lab&site=site-a`.

You will see "AUTHENTICATION REQUIRED". That is correct: the console only trusts a signed session. On PC1 print the operator token:

~~~bash
cat ~/mon-lab-identity/operator.jwt
~~~

In the PC7 browser developer console (same page) run, pasting the token between the quotes, then reload:

~~~javascript
document.cookie = "mon_session=<PASTE-TOKEN>; path=/; SameSite=Lax";
location.reload();
~~~

Expected: operator context `mon-lab-operator · tenant_admin`, connection `LIVE`. No other tenant is reachable.

## 7. PC5 — Linux victim and endpoint collector

### 7.1 Packages, victim service, dedicated test account

~~~bash
source ~/lab.env
sudo apt-get install -y openssh-server auditd python3-systemd nftables netcat-openbsd
sudo systemctl enable --now ssh auditd
sudo useradd -m -s /bin/bash monlab 2>/dev/null || true
echo 'monlab:Lab-Only-Not-A-Real-Password-1' | sudo chpasswd
sudo tee /etc/ssh/sshd_config.d/00-monlab.conf >/dev/null <<'EOF'
PasswordAuthentication yes
EOF
sudo sshd -t && sudo systemctl reload ssh
~~~

`00-monlab.conf` sorts first so it wins over cloud-image defaults. `monlab` is a throwaway account that exists only for this exercise.

### 7.2 Filtered-port range used by the recon test

`tcp-syn-recon` counts SYNs that the target did not answer (a SYN-only flow). A default closed port answers `RST/ACK`, so a normal scan of closed ports is intentionally not that shape. The lab therefore makes a bounded range look firewalled **on this one victim, for this one attacker address**:

~~~bash
sudo nft delete table inet mon_lab_victim 2>/dev/null || true
sudo nft add table inet mon_lab_victim
sudo nft 'add chain inet mon_lab_victim input { type filter hook input priority 0; policy accept; }'
sudo nft 'add rule inet mon_lab_victim input ip saddr 10.77.0.60 tcp dport 20000-20099 drop'
sudo nft list table inet mon_lab_victim
~~~

### 7.3 Sensor identity (PC5 CSR, PC1 enroll, PC5 pull)

PC5:

~~~bash
source ~/lab.env
cd ~/mon && . .venv/bin/activate
rm -rf ~/sensor-id && mkdir ~/sensor-id
python tools/lab_identity.py sensor-request --out-dir ~/sensor-id \
  --tenant-id "$TENANT" --site-id "$SITE" --sensor-id linux-pc5
ssh "$LAB_USER@$PC1_MGMT_IP" "mkdir -p ~/csr/linux-pc5"
scp ~/sensor-id/sensor-client.csr.pem "$LAB_USER@$PC1_MGMT_IP:~/csr/linux-pc5/"
~~~

PC1:

~~~bash
source ~/lab.env
cd ~/mon && . .venv/bin/activate
rm -rf ~/enrolled/linux-pc5
python tools/lab_identity.py enroll-sensor-csr --control-url http://127.0.0.1:8080 \
  --admin-token-file ~/mon-lab-identity/operator.jwt \
  --csr-file ~/csr/linux-pc5/sensor-client.csr.pem --out-dir ~/enrolled/linux-pc5 \
  --tenant-id "$TENANT" --site-id "$SITE" --sensor-id linux-pc5
~~~

PC5:

~~~bash
source ~/lab.env
scp "$LAB_USER@$PC1_MGMT_IP:~/enrolled/linux-pc5/sensor-client-cert.pem" ~/sensor-id/
scp "$LAB_USER@$PC1_MGMT_IP:~/mon-lab-identity/sensor-ca.pem" ~/sensor-id/
sudo mkdir -p /etc/mon && sudo chmod 700 /etc/mon
sudo install -m 600 ~/sensor-id/sensor-client-key.pem /etc/mon/linux-pc5-key.pem
sudo install -m 644 ~/sensor-id/sensor-client-cert.pem /etc/mon/linux-pc5.pem
sudo install -m 644 ~/sensor-id/sensor-ca.pem /etc/mon/sensor-ca.pem
~~~

### 7.4 Start the collector (PC5, root, over the overlay)

`--ssh-unit ssh.service` is required on Ubuntu: the collector matches the journal `_SYSTEMD_UNIT`, which is `ssh.service`, not `sshd`.

~~~bash
source ~/lab.env
sudo tmux kill-session -t mon-linux 2>/dev/null || true
sudo tmux new-session -d -s mon-linux "$HOME/mon/.venv/bin/mon-linux-endpoint-collector foreground \
  --tenant-id $TENANT --site-id $SITE --sensor-id linux-pc5 \
  --state-dir /var/lib/mon-linux-endpoint-collector \
  --ssh-unit ssh.service \
  --sensor-ingress-url https://10.77.0.1:9443 \
  --server-ca-file /etc/mon/sensor-ca.pem \
  --client-cert-file /etc/mon/linux-pc5.pem \
  --client-key-file /etc/mon/linux-pc5-key.pem \
  --poll-interval-seconds 5"
sleep 8
sudo tmux capture-pane -p -t mon-linux | tail -8
~~~

Expected: no traceback and no `SOURCE_UNAVAILABLE` for the journal. If you see "python3-systemd is not installed", the venv was not created with `--system-site-packages`; redo section 1 on PC5.

## 8. PC4 — Windows victim and endpoint collector

All commands in **elevated** PowerShell (Run as administrator). The Security log cannot be read without elevation.

### 8.1 Tooling

~~~powershell
winget install --id Python.Python.3.12 -e
winget install --id Git.Git -e
winget install --id WireGuard.WireGuard -e
~~~

Close and reopen the elevated PowerShell so PATH refreshes.

### 8.2 WireGuard (generate key, share it, then configure)

~~~powershell
New-Item -ItemType Directory -Force C:\MON | Out-Null
$wg = "C:\Program Files\WireGuard\wg.exe"
$private = & $wg genkey
$private | Set-Content -Encoding ascii C:\MON\wg-private.key
($private | & $wg pubkey) | Set-Content -Encoding ascii C:\MON\wg-public.key
Get-Content C:\MON\wg-public.key
~~~

Give that public key to PC3, PC5 and PC6 (section 3.1). Then, with the PC3 public key and PC3 management IP filled in:

~~~powershell
$PC3_PUB = "<PC3-public-key>"
$PC3_MGMT_IP = "<PC3-management-IP>"
$priv = (Get-Content C:\MON\wg-private.key -Raw).Trim()
@"
[Interface]
PrivateKey = $priv
Address = 10.77.0.40/32

[Peer]
PublicKey = $PC3_PUB
Endpoint = ${PC3_MGMT_IP}:51820
AllowedIPs = 10.77.0.0/24
PersistentKeepalive = 15
"@ | Set-Content -Encoding ascii C:\MON\wg0.conf
& "C:\Program Files\WireGuard\wireguard.exe" /installtunnelservice C:\MON\wg0.conf
Start-Sleep 5
Test-Connection 10.77.0.1 -Count 2
~~~

### 8.3 Checkout, install and audit policy

~~~powershell
$MON_REF = "8f66baa9f8d287b8c05da379259b289c661c5828"
cd C:\MON
if (Test-Path C:\MON\mon) { Remove-Item -Recurse -Force C:\MON\mon }
git clone https://github.com/Saitanveesh/1.git C:\MON\mon
cd C:\MON\mon
git checkout $MON_REF
python -m venv C:\MON\venv
C:\MON\venv\Scripts\python.exe -m pip install --upgrade pip
C:\MON\venv\Scripts\python.exe -m pip install -e .
git rev-parse HEAD

auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /get /subcategory:"Logon"
~~~

### 8.4 Dedicated test account and the one allowed attack path

~~~powershell
net user monlab "Lab-Only-Not-A-Real-Password-1" /add
New-NetFirewallRule -DisplayName "MON lab SMB from attacker only" -Direction Inbound `
  -Protocol TCP -LocalPort 445 -RemoteAddress 10.77.0.60 -Action Allow -Profile Any
~~~

### 8.5 Sensor identity (generate here, enroll on PC1, pull back)

~~~powershell
$LAB_USER = "<ubuntu-login-user>"
$PC1 = "<PC1-management-IP>"
cd C:\MON\mon
C:\MON\venv\Scripts\python.exe tools\lab_identity.py sensor-request --out-dir C:\MON\sensor-id `
  --tenant-id mon-lab --site-id site-a --sensor-id windows-pc4
ssh "$LAB_USER@$PC1" "mkdir -p ~/csr/windows-pc4"
scp C:\MON\sensor-id\sensor-client.csr.pem "${LAB_USER}@${PC1}:~/csr/windows-pc4/"
~~~

PC1:

~~~bash
source ~/lab.env
cd ~/mon && . .venv/bin/activate
rm -rf ~/enrolled/windows-pc4
python tools/lab_identity.py enroll-sensor-csr --control-url http://127.0.0.1:8080 \
  --admin-token-file ~/mon-lab-identity/operator.jwt \
  --csr-file ~/csr/windows-pc4/sensor-client.csr.pem --out-dir ~/enrolled/windows-pc4 \
  --tenant-id "$TENANT" --site-id "$SITE" --sensor-id windows-pc4
~~~

PC4:

~~~powershell
scp "${LAB_USER}@${PC1}:~/enrolled/windows-pc4/sensor-client-cert.pem" C:\MON\sensor-id\
scp "${LAB_USER}@${PC1}:~/mon-lab-identity/sensor-ca.pem" C:\MON\sensor-id\
~~~

### 8.6 Start the collector (PC4, elevated, foreground)

~~~powershell
C:\MON\venv\Scripts\mon-windows-endpoint-collector.exe foreground `
  --tenant-id mon-lab --site-id site-a --sensor-id windows-pc4 `
  --state-dir C:\ProgramData\MON\WindowsCollectorState `
  --sensor-ingress-url https://10.77.0.1:9443 `
  --server-ca-file C:\MON\sensor-id\sensor-ca.pem `
  --client-cert-file C:\MON\sensor-id\sensor-client-cert.pem `
  --client-key-file C:\MON\sensor-id\sensor-client-key.pem `
  --poll-interval-seconds 5
~~~

Leave this window open. The packaged `MONWindows.exe` / MSI path is the production route; for the lab the pinned-source entry point avoids testing a new binary on test day.

## 9. Pre-attack readiness gate (PC1)

Do not start the scenario until all of these are true.

~~~bash
source ~/lab.env
echo "--- sensors"; mon_api "/api/v1/sensors?$SCOPE" | jq -c '.[] | {sensor_id,state,heartbeat_age_seconds}'
echo "--- enforcement points"; mon_api "/api/v1/enforcement-points?$SCOPE" | jq -c '.[] | {enforcement_point_id,kind,vendor,capabilities,health}'
echo "--- site"; ssh "$LAB_USER@$PC3_MGMT_IP" 'curl -fsS http://127.0.0.1:8090/health' | jq -c '.'
~~~

PC3: `sudo wg show` has a recent handshake for PC4, PC5, PC6. PC5 and PC4 collectors are running. PC7 shows `LIVE`.

## 10. Baseline (PC6) — normal reachability and real asset evidence

~~~bash
source ~/lab.env
nc -zv -w3 10.77.0.50 22
nc -zv -w3 10.77.0.40 445
sshpass -p 'Lab-Only-Not-A-Real-Password-1' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no monlab@10.77.0.50 'hostname; id -un'
smbclient -L //10.77.0.40 -U 'monlab%Lab-Only-Not-A-Real-Password-1' -m SMB3 || true
~~~

Expected MON evidence (PC1, wait ~15 s):

~~~bash
source ~/lab.env
mon_api "/api/v1/assets?$SCOPE" | jq -r '.[].asset_id'
mon_api "/api/v1/live/snapshot?$SCOPE" | jq '.telemetry | {observation_count, source_counts, protocol_counts}'
~~~

You should see `linux-host:<pc5-hostname>` (from the real SSH login evidence) and, if the SMB logon was recorded, `windows-host:<pc4-computer-name>`. If an asset is missing, that victim's collector is not delivering. Fix it before continuing; do not create assets by hand.

### 10.1 Bind victims to the PC3 router (PC1)

~~~bash
source ~/lab.env
for ASSET in $(mon_api "/api/v1/assets?$SCOPE" | jq -r '.[].asset_id | select(startswith("linux-host:") or startswith("windows-host:"))'); do
  mon_post /api/v1/enforcement-bindings "$(jq -nc --arg a "$ASSET" '{
    tenant_id:"mon-lab", site_id:"site-a", asset_id:$a,
    enforcement_point_id:"pc3-router", distance:0,
    attributes:{blast_radius_estimate:"single hostile source IP on lab overlay"}}')" | jq -c '{asset_id, enforcement_point_id}'
done
mon_api "/api/v1/enforcement-bindings?$SCOPE" | jq -c '.[] | {asset_id, enforcement_point_id}'
~~~

Both victim assets must be listed against `pc3-router`.

## 11. Live scenario

Times matter only for the detector windows below. Run the stages in order. After each stage, check the stated MON evidence before moving on.

### 11.1 Network reconnaissance (PC6)

Minimum conditions for `tcp-syn-recon`: at least 60 SYN-only flow events within a 10-second window **and** at least 18 distinct destination ports (or 10 destinations). One bounded range on one victim satisfies the port condition; 100 ports gives margin.

~~~bash
source ~/lab.env
sudo nmap -sS -Pn -n -p 20000-20099 --min-rate 200 --max-retries 0 10.77.0.50
~~~

Suricata writes unanswered-SYN flows when they time out (default 60 s). Wait about 75 seconds.

PC3, evidence at the sensor:

~~~bash
sudo tail -n 300 /var/log/suricata/eve.json | jq -c 'select(.event_type=="flow" and .src_ip=="10.77.0.60") | {dest_port, state: .flow.state, syn: .tcp.syn, ack: .tcp.ack}' | head
~~~

PC1, expected MON evidence:

~~~bash
source ~/lab.env
mon_api "/api/v1/findings?$SCOPE" | jq -c '.[] | {detector_id, severity, confidence, src_ip}'
~~~

Expected: a `tcp-syn-recon` finding, severity HIGH, confidence 0.82, `src_ip` `10.77.0.60`, evidence class NETWORK_FLOW. The incident is created with entity `10.77.0.60`. Described honestly: reconnaissance shape, not proof of compromise.

If no finding appears: count flow events (`jq` above). Fewer than 60 SYN-only flows in 10 s means the scan was too slow or the filter in step 7.2 is missing. Re-run the scan after correcting; the detector has a cooldown, so wait a few minutes or use a fresh port range (edit both the nmap range and the PC5 drop range).

### 11.2 Authentication abuse (PC6) — within 300 s of the recon finding

Minimum condition for `endpoint-auth-failure-pressure`: at least 8 failures in 300 s from one source against one identity. Ten against the one lab account on PC5:

~~~bash
source ~/lab.env
for i in $(seq 1 10); do
  sshpass -p 'wrong-password-attempt' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=5 \
    monlab@10.77.0.50 true 2>/dev/null
  sleep 1
done
~~~

Optional second endpoint (PC4, same minimum):

~~~bash
for i in $(seq 1 10); do smbclient -L //10.77.0.40 -U 'monlab%wrong-password-attempt' -m SMB3 2>/dev/null; sleep 1; done
~~~

PC5, local proof the failures are real: `sudo journalctl -u ssh.service --since "5 min ago" | grep "Failed password" | tail -3`.

PC1, expected MON evidence (allow ~15 s for the collector poll):

~~~bash
source ~/lab.env
mon_api "/api/v1/findings?$SCOPE" | jq -c '.[] | {detector_id, severity, confidence, src_ip, asset_id}'
mon_api "/api/v1/incidents?$SCOPE" | jq -c '.[] | {incident_id, title, severity, confidence, detector_ids, affected_asset_ids, entities}'
~~~

Expected: `endpoint-auth-failure-pressure`, MEDIUM, confidence 0.72, evidence class IDENTITY, `src_ip` `10.77.0.60`, victim `asset_id`. Because both findings share the observed source `10.77.0.60` inside the 300 s correlation window, **one incident** lists both detector ids and the victim asset. State exactly what the console shows; do not call it a confirmed compromise (the claim text says "not proof of compromise or successful access").

### 11.3 Investigation (PC7)

Open **Incidents**, select the correlated incident. Confirm: evidence from both NETWORK_FLOW and IDENTITY classes, affected asset(s), identity evidence, the investigation graph edges, and the containment capability `pc3-router · ROUTER · linux-nftables-router · BLOCK_IP` with blast radius "single hostile source IP on lab overlay".

### 11.4 Plan -> approve -> execute (PC7)

1. Target source IP is prefilled from observed evidence. It **must** read `10.77.0.60`. If it does not, stop and report that as a failure.
2. Enforcement point: `pc3-router`. TTL: set `600` (the default 120 is too short for the verification steps).
3. Press **PLAN BLOCK**. Policy returns `REQUIRE_APPROVAL` (confidence is below the auto-allow threshold). Enter an approval reason, then execute.
4. Wait for the execution status to move from `DISPATCH_PENDING` to `APPLIED` (the site command poll interval is 2 s).

### 11.5 Verify containment — two independent proofs

PC3, the exact MON-owned rule:

~~~bash
sudo nft -a list chain inet mon_router mon_block_ip
~~~

Expected: exactly one rule `ip saddr 10.77.0.60 drop comment "mon:v1:..."`.

PC6, packet flow actually stopped:

~~~bash
source ~/lab.env
! nc -zv -w3 10.77.0.50 22
! nc -zv -w3 10.77.0.40 445
~~~

Both must fail (timeout). Management paths unaffected — PC1 console still `LIVE`, PC3 `sudo wg show` still shows the PC6 handshake, PC3 `curl -fsS http://127.0.0.1:8090/health` still healthy. Other overlay traffic (PC4 <-> PC5, anything not from `10.77.0.60`) is untouched: on PC5, `ping -c 2 10.77.0.40`.

### 11.6 Rollback and recovery (PC7, then PC3/PC6)

Press **ROLLBACK** on the response in the console. Status must reach `ROLLED_BACK` with a rollback result message.

PC3, the rule is gone and nothing else moved:

~~~bash
sudo nft -a list chain inet mon_router mon_block_ip
sudo nft list table inet mon_lab_guard
~~~

PC6, connectivity restored:

~~~bash
nc -zv -w3 10.77.0.50 22
nc -zv -w3 10.77.0.40 445
~~~

### 11.7 Audit evidence (PC7 / PC1)

Console **Audit** (and the incident panel): plan/dispatch, approval with the operator identity, execution `APPLIED`, rollback `ROLLED_BACK`, with timestamps and actors. From PC1:

~~~bash
source ~/lab.env
mon_api "/api/v1/audit?$SCOPE" | jq -c '.[] | {occurred_at, actor_id, action, outcome, object_id}'
mon_api "/api/v1/responses?$SCOPE" | jq -c '.[] | {execution_id, status, applied_at, rollback_at}'
~~~

### 11.8 TTL path (optional second run)

Repeat 11.4 with TTL `30`, do not press rollback, wait about 60 s. The Site Controller's recovery loop removes the rule; verify with 11.6's PC3 and PC6 commands. State which path (manual or TTL) you demonstrated.

## 12. Pass/fail record

Mark each as observed with real evidence, or failed/degraded. Do not substitute seeded or cinematic data.

- [ ] Suricata flows from the overlay reached MON (finding `tcp-syn-recon`)
- [ ] Linux endpoint events from PC5 over sensor mTLS (finding `endpoint-auth-failure-pressure`)
- [ ] Windows endpoint events from PC4 over sensor mTLS (asset and, if run, failures)
- [ ] One incident correlated both detectors on `10.77.0.60`
- [ ] Console updated live over WebSocket from the real backend
- [ ] `APPLIED` created exactly one MON-owned rule in `inet mon_router`
- [ ] PC6 traffic to both victims stopped while management paths stayed healthy
- [ ] Rollback removed only that rule; connectivity returned
- [ ] Audit records show request, approval, execution, rollback, actors, timestamps

## 13. Teardown (every lab machine)

PC3: `sudo tmux kill-server`, `sudo nft delete table inet mon_router`, `sudo nft delete table inet mon_lab_guard`, `sudo systemctl disable --now wg-quick@wg0`. PC5: `sudo nft delete table inet mon_lab_victim`, `sudo tmux kill-server`, `sudo userdel -r monlab`. PC6: `sudo nft delete table inet mon_lab_egress`, `sudo systemctl disable --now wg-quick@wg0`. PC4: `net user monlab /delete`, remove the firewall rule `MON lab SMB from attacker only`, `& "C:\Program Files\WireGuard\wireguard.exe" /uninstalltunnelservice wg0`. PC1: `tmux kill-server`, `sudo docker rm -f mon-postgres`, `rm -rf ~/mon-lab-identity ~/enrolled ~/csr`.
