# MON Batch 1 — PC-5 protected traffic, real IDS alerts, rollback

Status: implementation branch only. **Nothing in this repository branch directly
reconfigures the live PC-2 or PC-5 machines.** Review and stage before deployment.

## Source of the observed-data bug

- The prior topology embedded `10.77.0.60` and `10.77.0.50` and
  called the first PC-6 even without a matching packet.
- `MON_PORTAL_INTERFACE=any` captures background traffic from PC-2, Docker,
  Tailscale and other devices; those IPs may be real, but not evidence of
  an attack against PC-5.
- The old `recent_lab_route` cache only kept 180 recent records, so
  web traffic could crowd out an ICMP ping sample.
- The old Suricata EVE bridge retained the newest 40 mixed entries;
  ordinary flows could crowd out alerts.
- The previous `Network` tab was removed from navigation per the Batch 1
  plan. PC-5 data now belongs in Overview and Investigation.

## New evidence contract

`MON_PROTECTED_HOST_IP` is the confirmed PC-5 tunnel address.
`MON_PROTECTED_CAPTURE_INTERFACE` is the PC-2 interface through which
the PC-5 test traffic must pass (normally `wg0`, VERIFY).

The authenticated `/portal/flows` endpoint now includes:

- `protected_host_ip` and `protected_capture_interface`
- `protected_route_status` (`UNCONFIGURED`, `NO_MATCHING_TRAFFIC`, `OBSERVED`)
- `protected_route_samples`: 90 actual one-second IP-frame, byte and ICMP counts
- `lab_route_events`: recent matching IP header observations with interface,
  direction, source, destination and capture frame identifier

An IP frame is not a unique end-to-end packet. Forwarded packets can appear
on RX and TX. Capturing traffic on PC-2 does not, by itself, prove routing
or firewall enforcement. The UI therefore explicitly distinguishes
**observed capture** from an **intended gateway path**.

The overlay is triggered by new qualifying MON live incidents/findings
or fresh real Suricata EVE signatures. It does not fire on existing snapshots,
low-severity flows, packet rates or fake demo events. No IPS action is
inferred from an IDS alert.

## Step 0 — Create a rollback point on PC-2

Run on PC-2 **before changing any live service**, with the original
`mon-three-console-v2`, portal and database still operational:

```bash
umask 077
B="$HOME/mon-three/batch1-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$B"
tar -C "$HOME/mon-three" --exclude='node_modules' -czf "$B/console-v2.tar.gz" console-v2
cp -a "$HOME/mon-three/tools/mon-lab-portal.py" "$B/mon-lab-portal.py"
[ ! -f "$HOME/mon-three/tools/mon_suricata_bridge.py" ] || cp -a "$HOME/mon-three/tools/mon_suricata_bridge.py" "$B/mon_suricata_bridge.py"
sudo systemctl cat mon-three-console-v2.service > "$B/console.service.txt"
sudo systemctl cat mon-three-lab-portal.service > "$B/portal.service.txt"
sudo docker exec mon-three-postgres pg_dump -U mon -d mon -Fc > "$B/mon.pg-dump"
sha256sum "$B"/* > "$B/SHA256SUMS.txt"
echo "LOCAL BACKUP: $B"
```

Do not upload backup artifacts: service configuration, database and local
files can contain confidential material. Do NOT run `docker compose down -v`
or recreate the original database volume.

Git rollback baseline:
`backup/mon-v5-3-before-batch1-20261023`
at the original V5.3 source. Existing live `console-v2` data is backed up
separately because local PC-2 modifications are not guaranteed in Git.

## Step 1 — Stage and validate without replacing working code

```bash
cd ~/mon-three-code
git status --short
git remote -v
git fetch origin feature/mon-batch1-live-security-alert-20261023
git worktree add ~/mon-batch1-stage origin/feature/mon-batch1-live-security-alert-20261023
cd ~/mon-batch1-stage/console
npm install --no-audit --no-fund
npm run build
npm test -- --run
cd ~/mon-batch1-stage
python3 -m unittest discover -s lab/pc5-training-site -p 'test_*.py'
```

These operations use a separate worktree. They do not restart PC-2 services.
If `git worktree add` says that the directory already exists, inspect
that worktree instead of overwriting it.

## Step 2 — Verify path BEFORE changing gateway defaults

On PC-5, obtain its **actual** tunnel address using
`ip -4 address show` or `ip -br address` and identify its WireGuard peer.

On PC-2:

```bash
ip -br address
ip route
ip link show wg0
sudo systemctl is-active mon-three-lab-portal.service
sudo systemctl is-active suricata.service
sudo systemctl show mon-three-lab-portal.service -p ExecStart
```

On PC-6, use its **confirmed** route to PC-5:
`ip route get <REAL_PC5_IP>`.

On PC-2, observe the route with:
`sudo tcpdump -ni wg0 "host <REAL_PC5_IP> and icmp"`.

From PC-6, perform a limited authorized ping:
`ping -c 5 <REAL_PC5_IP>`.

If PC-2 sees no packets during a successful PC-6 → PC-5 ping,
the traffic may be bypassing PC-2, captured on another interface, or
hidden in a different namespace. **Do not claim inline IDS/IPS coverage.**
Determine the real path before modifying WireGuard or nftables rules.

## Step 3 — Configure and stage the PC-2 portal

The portal needs:

```ini
MON_PROTECTED_HOST_IP=<CONFIRMED_PC5_TUNNEL_IP>
MON_PROTECTED_CAPTURE_INTERFACE=wg0
```

Set these environment variables in the **existing** portal service's
configuration. Do not replace the other environment variables or service
credentials. Find its actual `ExecStart` path before copying patched
`tools/mon-lab-portal.py` and `tools/mon_suricata_bridge.py` into that
live location. Verify service ownership/permissions. Then:

```bash
sudo systemctl daemon-reload
sudo systemctl restart mon-three-lab-portal.service
sudo systemctl status mon-three-lab-portal.service --no-pager
```

Your existing signed `mon_session` cookie remains subject to the
control-plane's JWT validation; no new token is required solely for this
capture change.

In Chrome → MON Network tools, inspect the authenticated response at
`/portal/flows`. It must include the **actual** configured PC-5 IP.
If it reports `UNCONFIGURED`, do not attempt to invent a source address
on the frontend.

## Step 4 — Stage the three-tab frontend

First inspect `sudo systemctl cat mon-three-console-v2.service` to
confirm its current working directory and frontend path. If and only if
the live source directory is `~/mon-three/console-v2`, after Step 0:

```bash
rsync -a --exclude=node_modules --exclude=dist ~/mon-batch1-stage/console/ ~/mon-three/console-v2/
cd ~/mon-three/console-v2
npm install --no-audit --no-fund
npm run build
sudo systemctl restart mon-three-console-v2.service
```

Do not overwrite another service's assets. The original login, V5.3
overview, incident details and 3-D investigation remain intact.

## Step 5 — Stage the PC-5 training application (optional until routing passes)

The site lives in `lab/pc5-training-site`. It uses fictional content,
fake canary documents, no real credentials and an isolated traversal
exercise. It is deliberately vulnerable **only inside its own directory**.

On PC-5, place a copy in a nonprivileged lab directory. Default bind is
`127.0.0.1:8085`; bind to the **confirmed PC-5 tunnel address only**
for the test:

```bash
cd ~/mon-training-site
MON_TRAINING_BIND=<REAL_PC5_IP> MON_TRAINING_PORT=8085 python3 server.py
```

Restrict ingress to authorized lab peers; do not publish this training
service to the Internet or reuse any production college domain.

The controlled test from PC-6 is a small number of HTTP requests against
PC-5's **training** instance, including the lab canary:
`/download?file=../training-private/lab-only.txt`. This canary is fake
and cannot read host paths outside the isolated training directory.

A sample Suricata signature is provided in
`lab/pc5-training-site/mon-training-suricata.rules`; validate with
`suricata -T` against the actual PC-2 configuration before loading it.
Do not claim an IDS alert until the sensor writes a matching EVE `alert`
and MON displays that evidence.

## Rollback

1. Stop only the affected MON frontend/portal services.
2. Restore `console-v2` from the timestamped tar archive.
3. Restore the two original portal Python files from the backup.
4. Restore the original systemd environment/service settings.
5. Restart the original frontend/portal services and check health.
6. The database requires **no rollback** for these frontend/capture changes.
   The dump exists as emergency backup, not an automatic replacement.

Never discard recent incidents just to roll back UI styling.

## Acceptance

- PC-5 IP is read from configuration, not hardcoded.
- PC-6 → PC-5 ping appears as **ICMP** only if PC-2 captures real frames.
- Dashboard says `UNCONFIGURED` or `NO MATCHING TUNNEL FRAMES` if missing.
- PC-2 host-wide packet counts are separate from PC-5 route-only counters.
- Suricata signature alerts survive high-volume benign EVE flow records.
- A new supported live signature opens the centered red alert once;
  acknowledge/investigate does not falsely claim a blocked attack.
- Suricata's service is actually active, its EVE path is readable,
  and its rule matches the authorized PC-5 training endpoint.
