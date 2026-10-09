#!/usr/bin/env python3
"""Three-Ubuntu MON lab: SSH orchestration over verified Tailscale peers.

No attacks, password storage, SSH host-key bypass, or automatic PC isolation.
Invoke from an operator workstation, not a privileged MON service.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

PINNED_REF = "8f66baa9f8d287b8c05da379259b289c661c5828"
TAILNET = ipaddress.ip_network("100.64.0.0/10")
USER_RE = re.compile(r"[a-z_][a-z0-9_-]*\Z")
ROLES = ("mon", "victim", "attacker")
WG_ADDR = {"mon": "10.77.0.1", "victim": "10.77.0.50", "attacker": "10.77.0.60"}
SSH_ARGS = ("-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15")


@dataclass(frozen=True)
class Peer:
    host: str
    user: str

    @property
    def dest(self) -> str:
        return f"{self.user}@{self.host}"


def read_inventory(path: Path) -> dict[str, Peer]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if set(data) != set(ROLES):
        raise ValueError(f"inventory must contain exactly {', '.join(ROLES)}")
    peers: dict[str, Peer] = {}
    seen = set()
    for role in ROLES:
        item = data[role]
        if not isinstance(item, dict) or set(item) != {"host", "user"}:
            raise ValueError(f"{role}: require only host and user")
        address = ipaddress.ip_address(item["host"])
        if address.version != 4 or address not in TAILNET:
            raise ValueError(f"{role}: use the peer's actual Tailscale IPv4 address")
        user = item["user"]
        if not isinstance(user, str) or not USER_RE.fullmatch(user):
            raise ValueError(f"{role}: invalid SSH username")
        if str(address) in seen:
            raise ValueError("all three roles must be on separate computers")
        seen.add(str(address))
        peers[role] = Peer(str(address), user)
    return peers


class Remote:
    def __init__(self, peers: dict[str, Peer]):
        self.peers = peers

    def ssh(self, role: str, command: str, *, capture: bool = False,
            interactive: bool = False) -> str:
        peer = self.peers[role]
        args = ["ssh", *SSH_ARGS]
        if interactive:
            args.append("-tt")
        args += [peer.dest, command]
        result = subprocess.run(args, check=True, text=True,
                                capture_output=capture)
        return result.stdout.strip() if capture else ""

    def run(self, role: str, script: str, *, root: bool = False,
            label: str = "stage") -> None:
        """Upload a script to the user's private directory; run with interactive sudo."""
        peer = self.peers[role]
        stage = re.sub(r"[^a-z0-9_-]", "-", label.lower()) + ".sh"
        self.ssh(role, "mkdir -p -m 700 ~/.cache/mon-three/stages && "
                       "chmod 700 ~/.cache/mon-three ~/.cache/mon-three/stages")
        source = "#!/usr/bin/env bash\nset -Eeuo pipefail\n" + script
        with tempfile.TemporaryDirectory(prefix="mon-three-") as folder:
            local = Path(folder) / stage
            local.write_text(source, encoding="utf-8")
            subprocess.run(["scp", *SSH_ARGS, str(local),
                            f"{peer.dest}:.cache/mon-three/stages/{stage}"],
                           check=True)
        remote_path = f"$HOME/.cache/mon-three/stages/{stage}"
        # Use real remote user home even when executing sudo; no shell interpolation of inventory.
        shell = ("sudo bash " if root else "bash ") + remote_path
        print(f"\n[{role}] {label}" + (" (sudo password may be requested)" if root else ""),
              flush=True)
        self.ssh(role, shell, interactive=root)

    def copy_from(self, role: str, path: str, local: Path) -> None:
        subprocess.run(["scp", *SSH_ARGS, f"{self.peers[role].dest}:{path}",
                        str(local)], check=True)

    def copy_to(self, role: str, local: Path, path: str) -> None:
        subprocess.run(["scp", *SSH_ARGS, str(local),
                        f"{self.peers[role].dest}:{path}"], check=True)


def preflight(remote: Remote) -> None:
    """No mutations or port sweeps; SSH host keys must already be trusted."""
    for role in ROLES:
        peer = remote.peers[role]
        output = remote.ssh(role, """set -e
printf 'host=%s user=%s\\n' "$(hostname)" "$(id -un)"
. /etc/os-release
printf 'os=%s version=%s\\n' "$ID" "$VERSION_ID"
printf 'tail-ip='; tailscale ip -4
command -v sudo
command -v apt-get
""", capture=True)
        print(f"[{role}] {peer.dest}\n{output}", flush=True)
        fields = output.splitlines()
        if f"user={peer.user}" not in fields[0]:
            raise RuntimeError(f"{role}: SSH account is not the expected user")
        if f"tail-ip={peer.host}" not in fields:
            raise RuntimeError(f"{role}: connected host's Tailscale IP does not match inventory")
        if "os=ubuntu" not in output:
            raise RuntimeError(f"{role}: requires Ubuntu")
        if not any(v in output for v in ("version=24.04", "version=26.04")):
            raise RuntimeError(f"{role}: Ubuntu version requires manual qualification")
    print("Three remote Tailscale identities verified; no remote configuration changed.")


def base_script(role: str) -> str:
    common = "git python3 python3-venv python3-pip openssl curl jq tmux wireguard nftables"
    extra = {"mon": "docker.io suricata tcpdump",
             "victim": "openssh-server auditd python3-systemd netcat-openbsd",
             "attacker": "nmap netcat-openbsd"}[role]
    return f"""export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y {common} {extra}
""" + ("""systemctl enable --now docker
""" if role == "mon" else """true
""") + ("""systemctl enable --now ssh auditd
""" if role == "victim" else "")


def checkout_script(ref: str) -> str:
    # Do not reset a dirty checkout or replace local modifications.
    return f"""REF={shlex.quote(ref)}
if [ ! -d "$HOME/mon-three-code/.git" ]; then
  git clone https://github.com/Saitanveesh/1.git "$HOME/mon-three-code"
fi
cd "$HOME/mon-three-code"
test -z "$(git status --porcelain)" || {{ echo 'Dirty checkout: refusing to overwrite'; exit 1; }}
git fetch --no-tags origin "$REF"
git checkout --detach "$REF"
test "$(git rev-parse HEAD)" = "$REF"
if [ ! -d .venv ]; then python3 -m venv --system-site-packages .venv; fi
. .venv/bin/activate
python -m pip install -e .
echo "Pinned MON checkout: $(git rev-parse HEAD)"
"""


def bootstrap(remote: Remote, ref: str) -> None:
    for role in ROLES:
        remote.run(role, base_script(role), root=True, label="install-packages")
        if role != "attacker":
            remote.run(role, checkout_script(ref), label="install-mon")
    print("Base packages and pinned MON source installed; no attack traffic generated.")


def remote_public_key(remote: Remote, role: str) -> str:
    remote.run(role, """umask 077
mkdir -p -m 700 "$HOME/mon-three"
if [ ! -s "$HOME/mon-three/wg.key" ]; then
  wg genkey > "$HOME/mon-three/wg.key"
fi
wg pubkey < "$HOME/mon-three/wg.key" > "$HOME/mon-three/wg.pub"
""", label="wireguard-key")
    key = remote.ssh(role, "cat ~/mon-three/wg.pub", capture=True)
    if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", key):
        raise RuntimeError(f"{role}: invalid WireGuard public key")
    return key


def overlay(remote: Remote) -> None:
    keys = {role: remote_public_key(remote, role) for role in ROLES}
    mon_host = remote.peers["mon"].host
    for role in ROLES:
        addr = WG_ADDR[role]
        if role == "mon":
            peers = "\n".join(
                f"[Peer]\nPublicKey = {keys[r]}\nAllowedIPs = {WG_ADDR[r]}/32\n"
                for r in ("victim", "attacker"))
            conf = (f"[Interface]\nAddress = {addr}/24\nListenPort = 51820\n"
                    f"{peers}")
        else:
            conf = (f"[Interface]\nAddress = {addr}/32\n"
                    f"[Peer]\nPublicKey = {keys['mon']}\n"
                    f"Endpoint = {mon_host}:51820\nAllowedIPs = 10.77.0.0/24\n"
                    "PersistentKeepalive = 15\n")
        # Key remains on the corresponding host; config incorporates only that host's private key.
        remote.run(role, f"""umask 077
ME=$(getent passwd {shlex.quote(remote.peers[role].user)} | cut -d: -f6)
test -s "$ME/mon-three/wg.key"
mkdir -p -m 700 /etc/wireguard
if [ -e /etc/wireguard/wg0.conf ]; then
  echo 'wg0.conf already exists; refusing to overwrite VPN config'
  exit 1
fi
cat > /etc/wireguard/wg0.conf <<'MON_CONFIG'
{conf}MON_CONFIG
printf 'PrivateKey = %s\\n' "$(cat "$ME/mon-three/wg.key")" >> /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.conf
systemctl enable --now wg-quick@wg0
""", root=True, label="wireguard-config")
    remote.run("mon", """printf 'net.ipv4.ip_forward=1\\n' > /etc/sysctl.d/99-mon-three.conf
sysctl -w net.ipv4.ip_forward=1
""", root=True, label="overlay-forwarding")
    # Refuse to mutate any other nftables tables/chains. No egress lockdown via remote SSH.
    remote.run("mon", """if nft list table inet mon_three_guard >/dev/null 2>&1; then
  echo 'MON overlay guard already exists; inspect before rerun'
  exit 1
fi
nft add table inet mon_three_guard
nft 'add chain inet mon_three_guard input { type filter hook input priority -100; policy accept; }'
nft 'add chain inet mon_three_guard forward { type filter hook forward priority -100; policy accept; }'
nft 'add rule inet mon_three_guard input iifname "wg0" ip saddr 10.77.0.60 drop'
nft 'add rule inet mon_three_guard forward iifname "wg0" ip saddr 10.77.0.60 ip daddr 10.77.0.50 accept'
nft 'add rule inet mon_three_guard forward iifname "wg0" ip saddr 10.77.0.60 drop'
nft 'add rule inet mon_three_guard forward iifname "wg0" oifname != "wg0" drop'
nft list table inet mon_three_guard
""", root=True, label="guard-attacker-overlay")
    for role in ("victim", "attacker"):
        # Handshake test uses an authorized private overlay endpoint.
        print(f"[{role}] tunnel handshake check")
        print(remote.ssh(role, "wg show wg0 latest-handshakes", capture=True))
    print("Overlay configured. Verify handshake freshness and routing before test traffic.")


def control(remote: Remote) -> None:
    """MON host: Postgres + API + site mTLS ingress + operator UI."""
    remote.run("mon", r"""umask 077
mkdir -p -m 700 "$HOME/mon-three"
if [ ! -s "$HOME/mon-three/db.env" ]; then
  ADMIN=$(openssl rand -hex 20)
  APP=$(openssl rand -hex 20)
  printf 'DB_ADMIN=%s\nDB_APP=%s\n' "$ADMIN" "$APP" > "$HOME/mon-three/db.env"
fi
. "$HOME/mon-three/db.env"
if ! sudo docker container inspect mon-three-postgres >/dev/null 2>&1; then
  sudo docker volume create mon-three-pgdata >/dev/null
  sudo docker run -d --name mon-three-postgres -v mon-three-pgdata:/var/lib/postgresql/data \
    -e POSTGRES_DB=mon -e POSTGRES_USER=mon -e POSTGRES_PASSWORD="$DB_ADMIN" \
    -p 127.0.0.1:5432:5432 postgres:17-alpine
else
  sudo docker start mon-three-postgres >/dev/null 2>&1 || true
fi
for i in $(seq 1 60); do
  sudo docker exec mon-three-postgres pg_isready -U mon -d mon >/dev/null 2>&1 && break
  sleep 1
done
sudo docker exec mon-three-postgres pg_isready -U mon -d mon
cd "$HOME/mon-three-code"
. .venv/bin/activate
MON_DATABASE_URL="postgresql+psycopg://mon:$DB_ADMIN@127.0.0.1:5432/mon" alembic upgrade head
sudo docker exec -i mon-three-postgres psql -v ON_ERROR_STOP=1 -U mon -d mon <<SQL
DO \$\$
BEGIN
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mon_app_lab') THEN
  CREATE ROLE mon_app_lab LOGIN PASSWORD '$DB_APP'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
 END IF;
END
\$\$;
GRANT CONNECT ON DATABASE mon TO mon_app_lab;
GRANT USAGE ON SCHEMA public TO mon_app_lab;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO mon_app_lab;
GRANT USAGE,SELECT,UPDATE ON ALL SEQUENCES IN SCHEMA public TO mon_app_lab;
SQL
if [ ! -d "$HOME/mon-three/identity" ]; then
  python tools/lab_identity.py init --out-dir "$HOME/mon-three/identity" \
    --tenant-id mon-lab --site-id site-a \
    --site-ingress-host 127.0.0.1 --sensor-ingress-host 10.77.0.1 \
    --token-hours 12
fi
cat > "$HOME/mon-three/control.env" <<ENV
MON_DATABASE_URL=postgresql+psycopg://mon_app_lab:$DB_APP@127.0.0.1:5432/mon
MON_AUTH_JWKS_FILE=$HOME/mon-three/identity/jwks.json
MON_AUTH_ISSUER=mon-lab
MON_AUTH_AUDIENCE=mon-control-plane
MON_SITE_CA_CERT_FILE=$HOME/mon-three/identity/site-ca.pem
MON_SITE_CA_KEY_FILE=$HOME/mon-three/identity/site-ca-key.pem
MON_SENSOR_CA_CERT_FILE=$HOME/mon-three/identity/sensor-ca.pem
MON_SENSOR_CA_KEY_FILE=$HOME/mon-three/identity/sensor-ca-key.pem
ENV
chmod 600 "$HOME/mon-three/control.env"
if ! tmux has-session -t mon-three-control 2>/dev/null; then
  tmux new-session -d -s mon-three-control \
    "cd $HOME/mon-three-code && set -a && . $HOME/mon-three/control.env && set +a && . .venv/bin/activate && python -m uvicorn mon.api:app --host 127.0.0.1 --port 8080"
fi
for i in $(seq 1 20); do
  curl -fsS http://127.0.0.1:8080/health > /tmp/mon-three-health.json 2>/dev/null && break
  sleep 1
done
python - <<'PY'
import json
data=json.load(open('/tmp/mon-three-health.json'))
assert data.get('state') == 'READY', data
print('Control-plane health READY')
PY
cat > "$HOME/mon-three/site-ingress.env" <<ENV
MON_INTERNAL_CONTROL_PLANE_URL=http://127.0.0.1:8080
MON_MTLS_SERVER_CERT_FILE=$HOME/mon-three/identity/site-ingress-server.pem
MON_MTLS_SERVER_KEY_FILE=$HOME/mon-three/identity/site-ingress-server-key.pem
MON_SITE_CA_CERT_FILE=$HOME/mon-three/identity/site-ca.pem
MON_MTLS_HOST=127.0.0.1
MON_MTLS_PORT=8443
ENV
chmod 600 "$HOME/mon-three/site-ingress.env"
if ! tmux has-session -t mon-three-ingress 2>/dev/null; then
  tmux new-session -d -s mon-three-ingress \
    "cd $HOME/mon-three-code && . .venv/bin/activate && set -a && . $HOME/mon-three/site-ingress.env && set +a && python -m mon.mtls_ingress"
fi
node --version
node -e 'let v=process.versions.node.split(".").map(Number); if(v[0]<22 && !(v[0]===20&&v[1]>=19)) process.exit(1)'
cd "$HOME/mon-three-code/console"
npm ci --no-audit --no-fund
TAIL=$(tailscale ip -4)
if ! tmux has-session -t mon-three-console 2>/dev/null; then
  tmux new-session -d -s mon-three-console \
    "cd $HOME/mon-three-code/console && npm run dev -- --host $TAIL --port 5173"
fi
echo "Console (Tailscale-only): http://$TAIL:5173/?tenant=mon-lab&site=site-a"
""", label="mon-control-plane")


def enroll_local(remote: Remote, kind: str, sensor: str = "") -> None:
    """Issue cert locally on MON host. Does not regenerate CA or existing keys."""
    sid = {"site": "site", "suricata": "suricata"}[kind]
    request = ("site-request" if kind == "site" else "sensor-request")
    enroll = ("enroll-site-csr" if kind == "site" else "enroll-sensor-csr")
    optional = f"--sensor-id {sensor}" if sensor else ""
    remote.run("mon", f"""umask 077
cd "$HOME/mon-three-code"
. .venv/bin/activate
mkdir -p "$HOME/mon-three/{sid}-id"
if [ ! -s "$HOME/mon-three/{sid}-id/{sid if kind == 'site' else 'sensor'}-client-key.pem" ]; then
  python tools/lab_identity.py {request} --out-dir "$HOME/mon-three/{sid}-id" \
    --tenant-id mon-lab --site-id site-a {optional}
fi
if [ ! -s "$HOME/mon-three/{sid}-id/{sid if kind == 'site' else 'sensor'}-client-cert.pem" ]; then
  python tools/lab_identity.py {enroll} \
    --control-url http://127.0.0.1:8080 \
    --admin-token-file "$HOME/mon-three/identity/operator.jwt" \
    --csr-file "$HOME/mon-three/{sid}-id/{sid if kind == 'site' else 'sensor'}-client.csr.pem" \
    --out-dir "$HOME/mon-three/{sid}-enrolled" \
    --tenant-id mon-lab --site-id site-a {optional}
  cp "$HOME/mon-three/{sid}-enrolled/{sid if kind == 'site' else 'sensor'}-client-cert.pem" \
    "$HOME/mon-three/{sid}-id/"
fi
""", label=f"enroll-{sid}")


def site(remote: Remote) -> None:
    enroll_local(remote, "site")
    enroll_local(remote, "suricata", "suricata-three")
    user = shlex.quote(remote.peers["mon"].user)
    remote.run("mon", f"""HOME_MON=$(getent passwd {user} | cut -d: -f6)
mkdir -p -m 700 /etc/mon /var/lib/mon-site /var/lib/mon-sensor
install -m 600 "$HOME_MON/mon-three/site-id/site-client-key.pem" /etc/mon/site-client-key.pem
install -m 644 "$HOME_MON/mon-three/site-id/site-client-cert.pem" /etc/mon/site-client-cert.pem
install -m 644 "$HOME_MON/mon-three/identity/site-ca.pem" /etc/mon/site-ca.pem
install -m 600 "$HOME_MON/mon-three/identity/site-controller.jwt" /etc/mon/site-controller.jwt
install -m 644 "$HOME_MON/mon-three/identity/sensor-ca.pem" /etc/mon/sensor-ca.pem
install -m 644 "$HOME_MON/mon-three/identity/sensor-ingress-server.pem" /etc/mon/sensor-ingress-server.pem
install -m 600 "$HOME_MON/mon-three/identity/sensor-ingress-server-key.pem" /etc/mon/sensor-ingress-server-key.pem
install -m 600 "$HOME_MON/mon-three/suricata-id/sensor-client-key.pem" /etc/mon/suricata-three-key.pem
install -m 644 "$HOME_MON/mon-three/suricata-id/sensor-client-cert.pem" /etc/mon/suricata-three.pem
cat > /etc/mon/mon-three-site.env <<'ENV'
MON_TENANT_ID=mon-lab
MON_SITE_ID=site-a
MON_SITE_STATE_DIR=/var/lib/mon-site
MON_SITE_INGRESS_URL=https://127.0.0.1:8443
MON_SITE_CA_CERT_FILE=/etc/mon/site-ca.pem
MON_SITE_CLIENT_CERT_FILE=/etc/mon/site-client-cert.pem
MON_SITE_CLIENT_KEY_FILE=/etc/mon/site-client-key.pem
MON_SITE_BEARER_TOKEN_FILE=/etc/mon/site-controller.jwt
MON_ENABLE_ROUTER_NFTABLES_ENFORCEMENT=1
MON_SITE_ROUTER_NFTABLES_VENDOR=linux-nftables-router
ENV
chmod 600 /etc/mon/mon-three-site.env
if ! tmux has-session -t mon-three-site 2>/dev/null; then
  tmux new-session -d -s mon-three-site \
    "cd $HOME_MON/mon-three-code && set -a && . /etc/mon/mon-three-site.env && set +a && $HOME_MON/mon-three-code/.venv/bin/mon-site"
fi
cat > /etc/mon/mon-three-sensor-ingress.env <<'ENV'
MON_TENANT_ID=mon-lab
MON_SITE_ID=site-a
MON_SENSOR_INGRESS_SERVER_CERT_FILE=/etc/mon/sensor-ingress-server.pem
MON_SENSOR_INGRESS_SERVER_KEY_FILE=/etc/mon/sensor-ingress-server-key.pem
MON_SENSOR_CA_CERT_FILE=/etc/mon/sensor-ca.pem
MON_SENSOR_INGRESS_HOST=10.77.0.1
MON_SENSOR_INGRESS_PORT=9443
MON_SENSOR_INTERNAL_SITE_URL=http://127.0.0.1:8090
ENV
chmod 600 /etc/mon/mon-three-sensor-ingress.env
if ! tmux has-session -t mon-three-sensor-ingress 2>/dev/null; then
  tmux new-session -d -s mon-three-sensor-ingress \
    "set -a && . /etc/mon/mon-three-sensor-ingress.env && set +a && $HOME_MON/mon-three-code/.venv/bin/mon-sensor-ingress"
fi
""", root=True, label="site-and-sensor-ingress")
    # Enrolled sensors are learned via a periodic trust synchronization.
    print("Waiting for sensor trust synchronization (20 seconds) ...", flush=True)
    time.sleep(20)
    remote.run("mon", f"""HOME_MON=$(getent passwd {user} | cut -d: -f6)
systemctl disable --now suricata 2>/dev/null || true
if ! tmux has-session -t mon-three-suricata 2>/dev/null; then
  tmux new-session -d -s mon-three-suricata \
    "suricata -c /etc/suricata/suricata.yaml --af-packet=wg0 -k none"
fi
cat > /etc/mon/mon-three-suricata.env <<'ENV'
MON_TENANT_ID=mon-lab
MON_SITE_ID=site-a
MON_SENSOR_ID=suricata-three
MON_SENSOR_INGRESS_URL=https://10.77.0.1:9443
MON_SENSOR_SERVER_CA_CERT_FILE=/etc/mon/sensor-ca.pem
MON_SENSOR_CLIENT_CERT_FILE=/etc/mon/suricata-three.pem
MON_SENSOR_CLIENT_KEY_FILE=/etc/mon/suricata-three-key.pem
MON_SENSOR_STATE_DIR=/var/lib/mon-sensor
MON_SURICATA_EVE_FILE=/var/log/suricata/eve.json
MON_SENSOR_POLL_INTERVAL_SECONDS=1
MON_SENSOR_HEARTBEAT_INTERVAL_SECONDS=15
ENV
chmod 600 /etc/mon/mon-three-suricata.env
if ! tmux has-session -t mon-three-suricata-collector 2>/dev/null; then
  tmux new-session -d -s mon-three-suricata-collector \
    "set -a && . /etc/mon/mon-three-suricata.env && set +a && $HOME_MON/mon-three-code/.venv/bin/mon-suricata-collector"
fi
""", root=True, label="suricata-sensor")
    remote.run("mon", r"""TOKEN=$(cat "$HOME/mon-three/identity/operator.jwt")
curl -fsS -X POST \
 -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
 -d '{"enforcement_point_id":"mon-three-router","tenant_id":"mon-lab","site_id":"site-a","kind":"ROUTER","vendor":"linux-nftables-router","capabilities":["BLOCK_IP"],"priority":100,"attributes":{}}' \
 http://127.0.0.1:8080/api/v1/enforcement-points
echo
""", label="register-enforcement-point")


def victim(remote: Remote) -> None:
    remote.run("victim", """umask 077
mkdir -p "$HOME/mon-three/victim-id"
cd "$HOME/mon-three-code"
. .venv/bin/activate
if [ ! -s "$HOME/mon-three/victim-id/sensor-client-key.pem" ]; then
  python tools/lab_identity.py sensor-request \
    --out-dir "$HOME/mon-three/victim-id" \
    --tenant-id mon-lab --site-id site-a --sensor-id linux-victim-three
fi
""", label="victim-csr")
    with tempfile.TemporaryDirectory(prefix="mon-three-certs-") as folder:
        folder = Path(folder)
        csr = folder / "victim.csr.pem"
        cert = folder / "sensor-client-cert.pem"
        ca = folder / "sensor-ca.pem"
        remote.copy_from("victim", "mon-three/victim-id/sensor-client.csr.pem", csr)
        remote.ssh("mon", "mkdir -p -m 700 ~/mon-three/victim-enrolled")
        remote.copy_to("mon", csr, "mon-three/victim.csr.pem")
        remote.run("mon", """cd "$HOME/mon-three-code"
. .venv/bin/activate
python tools/lab_identity.py enroll-sensor-csr \
 --control-url http://127.0.0.1:8080 \
 --admin-token-file "$HOME/mon-three/identity/operator.jwt" \
 --csr-file "$HOME/mon-three/victim.csr.pem" \
 --out-dir "$HOME/mon-three/victim-enrolled" \
 --tenant-id mon-lab --site-id site-a --sensor-id linux-victim-three
""", label="enroll-victim")
        remote.copy_from("mon", "mon-three/victim-enrolled/sensor-client-cert.pem", cert)
        remote.copy_from("mon", "mon-three/identity/sensor-ca.pem", ca)
        remote.copy_to("victim", cert, "mon-three/victim-id/sensor-client-cert.pem")
        remote.copy_to("victim", ca, "mon-three/victim-id/sensor-ca.pem")
    user = shlex.quote(remote.peers["victim"].user)
    remote.run("victim", f"""VH=$(getent passwd {user} | cut -d: -f6)
mkdir -p -m 700 /etc/mon /var/lib/mon-linux-endpoint-collector
install -m 600 "$VH/mon-three/victim-id/sensor-client-key.pem" /etc/mon/linux-victim-three-key.pem
install -m 644 "$VH/mon-three/victim-id/sensor-client-cert.pem" /etc/mon/linux-victim-three.pem
install -m 644 "$VH/mon-three/victim-id/sensor-ca.pem" /etc/mon/sensor-ca.pem
if ! tmux has-session -t mon-three-linux 2>/dev/null; then
  tmux new-session -d -s mon-three-linux \
    "$VH/mon-three-code/.venv/bin/mon-linux-endpoint-collector foreground \
 --tenant-id mon-lab --site-id site-a --sensor-id linux-victim-three \
 --state-dir /var/lib/mon-linux-endpoint-collector --ssh-unit ssh.service \
 --sensor-ingress-url https://10.77.0.1:9443 \
 --server-ca-file /etc/mon/sensor-ca.pem \
 --client-cert-file /etc/mon/linux-victim-three.pem \
 --client-key-file /etc/mon/linux-victim-three-key.pem \
 --poll-interval-seconds 5"
fi
""", root=True, label="victim-collector")
    print("Victim collector started; check its live heartbeat before any exercise.")


def readiness(remote: Remote) -> None:
    print("\nMON health:")
    print(remote.ssh("mon", "curl -fsS http://127.0.0.1:8080/health", capture=True))
    print("\nSite health:")
    print(remote.ssh("mon", "curl -fsS http://127.0.0.1:8090/health", capture=True))
    print("\nSensors (real backend):")
    print(remote.ssh("mon", r"""TOKEN=$(cat "$HOME/mon-three/identity/operator.jwt")
curl -fsS -H "Authorization: Bearer $TOKEN" \
 'http://127.0.0.1:8080/api/v1/sensors?tenant_id=mon-lab&site_id=site-a'
""", capture=True))
    print("\nWireGuard handshakes on hub:")
    print(remote.ssh("mon", "sudo -n wg show wg0 latest-handshakes", capture=True))
    print("\nThis is raw evidence, NOT a claim of healthy sensors.")
    print("Check both sensor IDs, freshness, and tunnel connectivity manually.")
    print("Do not demonstrate an attack until these checks succeed.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--ref", default=PINNED_REF)
    parser.add_argument("--approve-install", action="store_true")
    parser.add_argument("--approve-overlay", action="store_true")
    parser.add_argument("stage", choices=("preflight", "bootstrap", "overlay", "control",
                                           "site", "victim", "ready"))
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.ref):
        parser.error("--ref must be a pinned 40-character hex commit")
    peers = read_inventory(args.inventory)
    remote = Remote(peers)
    if args.stage == "preflight":
        preflight(remote)
    elif args.stage == "bootstrap":
        if not args.approve_install:
            parser.error("bootstrap requires --approve-install")
        preflight(remote)
        bootstrap(remote, args.ref)
    elif args.stage == "overlay":
        if not args.approve_overlay:
            parser.error("overlay changes routes/firewalls: requires --approve-overlay")
        preflight(remote)
        overlay(remote)
    elif args.stage == "control":
        control(remote)
    elif args.stage == "site":
        site(remote)
    elif args.stage == "victim":
        victim(remote)
    elif args.stage == "ready":
        readiness(remote)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError, RuntimeError) as error:
        print(f"MON three-host deployment stopped: {error}", file=sys.stderr)
        raise SystemExit(1) from None
