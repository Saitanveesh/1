# MON Batch 1 — execute and verify (23 October 2026)

The repository patch does not automatically update your lab PCs.
This runbook is for the known V5.3 installation on PC-2, the fictional
training site on PC-5, and the authorized test source PC-6.

## 0. On PC-2 — first inspect, then recover in one guarded command

Use your existing PC-2 terminal and user `pc-2`:

```bash
cd ~/mon-three-code
git fetch --no-tags https://github.com/Saitanveesh/1.git refs/heads/feature/mon-batch1-live-security-alert-20261023
git show FETCH_HEAD:tools/mon-batch1-fix-pc2.sh > /tmp/mon-batch1-fix-pc2.sh
bash /tmp/mon-batch1-fix-pc2.sh --check
bash /tmp/mon-batch1-fix-pc2.sh --apply
```

The script intentionally stops before any change if it cannot validate the
known original database, original MON service names, two WireGuard peers,
a working console, Suricata rules, or stage build/tests. It will ask for
sudo authentication.

It creates a **local private backup** under
`/home/pc-2/mon-three/batch1-rollback.*` with original console source/build,
portal Python, changed units/environment, and a consistent PostgreSQL dump.
Do not upload this backup to GitHub.

The installer may add two narrowly scoped routes via `wg0` to
`10.77.0.50/32` (PC-5) and `10.77.0.60/32` (PC-6) after verifying
their WireGuard peer AllowedIPs. It never assigns a guessed local WG address,
rewrites keys, touches nftables rules or clears Docker volumes.

It then starts a separate **passive** MON Suricata on `wg0` with the
validated lab HTTP signature (Suricata's `-S` exclusive rules flag),
restarts the existing portal and V5.3 console, and enables the original
control-plane startup service if needed. The packaged, failed `eth0`
Suricata unit is left intact and disabled only after the new passive
sensor passes its startup/health checks.

**Important**: A PC-2 route selecting `wg0` is not proof that PC-6 and PC-5
actually traverse it. Verify that separately. No automatic blocking is
enabled, even if an IDS signature matches.

## 1. Transfer the fictional training site to PC-5

The PC-2 installer creates
`~/mon-three/mon-batch1-pc5-site.tar.gz`. On PC-2:

```bash
scp ~/mon-three/mon-batch1-pc5-site.tar.gz pc-5@10.5.114.47:~/
```

On PC-5 as `pc-5`:

```bash
mkdir -p ~/mon-training-site
tar -xzf ~/mon-batch1-pc5-site.tar.gz -C ~/mon-training-site --strip-components=1
bash ~/mon-training-site/install-pc5.sh
curl --max-time 5 http://10.77.0.50:8085/health
```

This binds a fake college-style demonstration site only to PC-5's confirmed
WireGuard IP. The deliberately vulnerable path reads only a fake lab canary
within the training directory. It does not access actual college logins,
student records, production services or private host files.

## 2. From PC-6 — confirm the actual route and run two bounded tests

On PC-6:

```bash
ip -4 route get 10.77.0.50
ping -c 5 10.77.0.50
curl --max-time 6 http://10.77.0.50:8085/health
curl --max-time 6 --path-as-is 'http://10.77.0.50:8085/download?file=../training-private/lab-only.txt'
```

These use the authorized test endpoint. The final response should show
`MON LAB CANARY`. Do not increase request volume for this test.

On PC-2, observe the actual path in a second terminal during the test:

```bash
sudo tcpdump -ni wg0 'host 10.77.0.50 and (icmp or tcp port 8085)'
```

No packets on PC-2 while PC-6 reaches PC-5 means the source may bypass
the intended gateway. Inspect PC-6/PC-5 peer configuration and their routes;
do not invent a detection or say the IPS blocked it.

## 3. Check the running IDS and browser

On PC-2:

```bash
sudo systemctl is-active mon-suricata-passive.service
sudo systemctl is-active mon-three-lab-portal.service
sudo systemctl is-active mon-three-console-v2.service
sudo journalctl -u mon-suricata-passive.service -n 20 --no-pager
tail -n 25 ~/mon-three/suricata/eve.json
```

Open:

`http://100.75.116.62:5174/?tenant=mon-lab&site=site-a`

Expected UI: three tabs (Overview, Incidents, Investigation); no
synthetic "Attack Pressure"; live PC-5 scoped IP/ICMP counts; actual
Suricata service health; alert modal if a **new** high- or medium-priority
Suricata rule match for PC-5 arrives while the dashboard is connected.

To confirm the IDS rule fired, find `signature_id=42000501` in EVE.
The alert is IDS-only until a separately audited enforcement action is
requested, permitted, executed and independently verified.

## 4. If anything fails

The PC-2 installer automatically rolls back affected local files and units
when an application step fails. The rollback directory is printed at startup
and completion. An explicit rollback procedure and architecture details
are in `docs/MON_BATCH1_GATEWAY_AND_ALERT_RUNBOOK.md`.

Do not use `docker compose down -v`, `wg-quick down`, or
`nft flush ruleset` to fix an unrelated startup error.

This installation has not been executed by ChatGPT on your PCs.
A green GitHub Actions run proves build/tests, **not** successful live
routing, detection, or IP blocking on PC-2/PC-5.
