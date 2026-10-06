# MON seven-system test-day command sheet

This is the live-lab fast path. Use disposable VMs and branch lab/test-day-readiness until PR 85 is merged. After merge, pin every MON node to the merge SHA.

Live scenario: TCP probe -> Suricata -> SSH authentication abuse -> Linux endpoint evidence -> correlation -> operator plan -> PC3 router BLOCK_IP -> packet-flow verification -> rollback -> recovery/audit.

Never present cinematic or seeded acceptance data as live evidence.

## 0. Fixed roles and overlay

- PC1: Ubuntu control plane + PostgreSQL + site mTLS ingress + React console
- PC2: Ubuntu admin/PKI/evidence station
- PC3: Ubuntu Site Controller + WireGuard hub + Suricata + sensor ingress + router enforcement
- PC4: Windows 11 victim
- PC5: Ubuntu victim + SSH + Linux endpoint collector
- PC6: Kali/Ubuntu attacker
- PC7: operator browser

Overlay: PC3=10.77.0.1, PC4=10.77.0.40, PC5=10.77.0.50, PC6=10.77.0.60.

## 1. Common Ubuntu checkout

Run where MON source is needed:

~~~bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv python3-pip curl jq tmux openssh-client
git clone https://github.com/Saitanveesh/1.git ~/mon
cd ~/mon
git checkout lab/test-day-readiness
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
git rev-parse HEAD
~~~

Record the SHA. All MON nodes must match.

## 2. PC1 — database, identities and control plane

~~~bash
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
sudo docker run -d --name mon-postgres   -e POSTGRES_DB=mon -e POSTGRES_USER=mon   -e POSTGRES_PASSWORD="$MON_DB_ADMIN_PASSWORD"   -p 127.0.0.1:5432:5432 postgres:17-alpine
until sudo docker exec mon-postgres pg_isready -U mon -d mon; do sleep 1; done

cd ~/mon
. .venv/bin/activate
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

Set the real management IPs and generate disposable lab auth/PKI material:

~~~bash
export PC1_MGMT_IP=<PC1-management-IP>
export PC3_MGMT_IP=<PC3-management-IP>
rm -rf "$HOME/mon-lab-identity"
python tools/lab_identity.py init   --out-dir "$HOME/mon-lab-identity"   --tenant-id mon-lab --site-id site-a   --site-ingress-host "$PC1_MGMT_IP"   --sensor-ingress-host "$PC3_MGMT_IP"   --token-hours 12
~~~

Start control plane:

~~~bash
source "$HOME/mon-lab-db.env"
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
tmux new-session -d -s mon-control   "cd $HOME/mon && . .venv/bin/activate && set -a && . $HOME/mon-control.env && set +a && python -m uvicorn mon.api:app --host 127.0.0.1 --port 8080"
sleep 2
curl -fsS http://127.0.0.1:8080/health | jq
~~~

Start site mTLS ingress on PC1:

~~~bash
cat > "$HOME/mon-site-ingress.env" <<EOF
MON_INTERNAL_CONTROL_PLANE_URL=http://127.0.0.1:8080
MON_MTLS_SERVER_CERT_FILE=$HOME/mon-lab-identity/site-ingress-server.pem
MON_MTLS_SERVER_KEY_FILE=$HOME/mon-lab-identity/site-ingress-server-key.pem
MON_SITE_CA_CERT_FILE=$HOME/mon-lab-identity/site-ca.pem
MON_MTLS_HOST=0.0.0.0
MON_MTLS_PORT=8443
EOF
tmux new-session -d -s mon-site-ingress   "cd $HOME/mon && . .venv/bin/activate && set -a && . $HOME/mon-site-ingress.env && set +a && python -m mon.mtls_ingress"
~~~

Start the console; Vite proxies API/WebSocket to loopback 8080:

~~~bash
sudo apt-get install -y nodejs npm
cd ~/mon/console
npm install --no-audit --no-fund
tmux new-session -d -s mon-console   "cd $HOME/mon/console && npm run dev -- --host 0.0.0.0 --port 5173"
~~~

## 3. WireGuard and hard isolation

PC3, PC5 and PC6:

~~~bash
sudo apt-get install -y wireguard nftables
umask 077
wg genkey | tee "$HOME/wg-private.key" | wg pubkey > "$HOME/wg-public.key"
cat "$HOME/wg-public.key"
~~~

PC4 Administrator PowerShell:

~~~powershell
winget install --id WireGuard.WireGuard -e
New-Item -ItemType Directory -Force C:\MON | Out-Null
$wg = "C:\Program Files\WireGuard\wg.exe"
$private = & $wg genkey
$private | Set-Content C:\MON\wg-private.key
$private | & $wg pubkey | Set-Content C:\MON\wg-public.key
Get-Content C:\MON\wg-public.key
~~~

Configure PC3 as WireGuard hub at 10.77.0.1/24. Peer AllowedIPs must be exactly 10.77.0.40/32, 10.77.0.50/32 and 10.77.0.60/32. PC4/5/6 use PC3 management-IP:51820 as endpoint and AllowedIPs=10.77.0.0/24.

PC3:

~~~bash
sudo systemctl enable --now wg-quick@wg0
sudo sysctl -w net.ipv4.ip_forward=1

sudo nft delete table inet mon_lab_guard 2>/dev/null || true
sudo nft add table inet mon_lab_guard
sudo nft 'add chain inet mon_lab_guard input { type filter hook input priority -100; policy accept; }'
sudo nft 'add chain inet mon_lab_guard forward { type filter hook forward priority -100; policy accept; }'
sudo nft 'add rule inet mon_lab_guard input iifname "wg0" ip saddr 10.77.0.60 drop'
sudo nft 'add rule inet mon_lab_guard forward iifname "wg0" ip saddr 10.77.0.60 ip daddr { 10.77.0.40, 10.77.0.50 } accept'
sudo nft 'add rule inet mon_lab_guard forward iifname "wg0" ip saddr 10.77.0.60 drop'
sudo nft 'add rule inet mon_lab_guard forward iifname "wg0" oifname != "wg0" drop'
sudo nft list table inet mon_lab_guard
~~~

PC6 also blocks direct management-LAN egress except WireGuard transport:

~~~bash
export MGMT_IF=<PC6-management-interface>
export PC3_MGMT_IP=<PC3-management-IP>
sudo nft delete table inet mon_lab_egress 2>/dev/null || true
sudo nft add table inet mon_lab_egress
sudo nft 'add chain inet mon_lab_egress output { type filter hook output priority -100; policy accept; }'
sudo nft add rule inet mon_lab_egress output oifname "$MGMT_IF" ip daddr "$PC3_MGMT_IP" udp dport 51820 accept
sudo nft add rule inet mon_lab_egress output oifname "$MGMT_IF" udp sport 68 udp dport 67 accept
sudo nft add rule inet mon_lab_egress output oifname "$MGMT_IF" drop
~~~

Before attack traffic, PC6 must reach only 10.77.0.40/50, must not reach 10.77.0.1 or a management-LAN host, while PC3 still shows a current WireGuard handshake.
