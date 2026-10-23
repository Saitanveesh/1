# MON Batch 1 final acceptance — 23 October 2026

This page completes the already-running PC-2 + PC-5 deployment. **Do not rerun the
original Batch 1 gateway installer** or reset WireGuard, Docker, nftables,
credentials or MON's PostgreSQL data.

## Outcome and security boundaries

- Investigate opens the **specific Suricata signature evidence** (not an
  unrelated, empty historical case reconstruction), with corresponding
  frame observations only if PC-2 actually captured them.
- Acknowledge records a review against a fresh, evidence-matched PC-5 Suricata
  EVE signature in a private PC-2 JSONL journal. The server requires the
  operator session, a known browser Origin and a fresh actual signature.
  A missing/failed journal response is shown as a failure; the popup remains.
  A MON-stream-only alert can be acknowledged in this browser session but
  this explicitly **does not** close or update a MON incident.
- Every PC-5 frame/byte metric comes from AF_PACKET on the configured
  interface `wg0`, matched to destination/source IP `10.77.0.50`, and
  requires a fresh monotonic one-second sample series plus real PC-2 kernel
  route selection. Missing/invalid/stale readings are withheld. Counters
  count **observed IP frames**, not unique packets; forwarding can result in
  RX/TX duplicates. The 5-second rate is an arithmetic average of observed
  one-second counts, never synthetic.
- The PC-5 website is a **fictional college portal** with SQL injection in an
  ephemeral in-memory SQLite fixture, IDOR against four synthetic records,
  directory traversal limited to this lab site's fictional canary, and
  toy-only login success/failure traffic. Service is bound to
  `10.77.0.50:8085`, accepts only loopback and authorized `10.77.0.0/24`
  clients, and enforces a 90-requests/minute source bound.
- Suricata IDS rules 42000501 (traversal attempt), 42000502 (encoded quote
  in notice-search request), 42000503 (specific fake IDOR request) detect
  **network request patterns**. They do not prove successful exploitation,
  host identity or an IPS block. No automatic firewall action is introduced.

## Step 1 — On PC-2, apply the targeted frontend + IDS patch

Run as `pc-2` in an existing SSH terminal:

```bash
cd ~/mon-three-code
git fetch --no-tags https://github.com/Saitanveesh/1.git refs/heads/feature/mon-batch1-live-security-alert-20261023
git show FETCH_HEAD:tools/mon-batch1-complete-pc2.sh > /tmp/mon-batch1-complete-pc2.sh
bash /tmp/mon-batch1-complete-pc2.sh --check
bash /tmp/mon-batch1-complete-pc2.sh --apply
```

It validates the release and rule syntax **before** changing the live site,
creates a `batch1-final-rollback.*` restore point under `~/mon-three`,
restores on failure and does not modify the original database. The
operator journal lives at `~/mon-three/alerts/acknowledged.jsonl` (private
mode 0600). Do not upload the journal or JWT to GitHub.

Expected after success: active
`mon-three-console-v2.service`, `mon-three-lab-portal.service` and
`mon-suricata-passive.service`; browser frontend available at:

`http://100.75.116.62:5174/?tenant=mon-lab&site=site-a`

Open this URL and hard-refresh after completing both upgrades.

## Step 2 — Upgrade PC-5 fictional application

PC-2's success output creates:
`~/mon-three/mon-batch1-pc5-site-v2.tar.gz`

Copy from PC-2:

```bash
scp ~/mon-three/mon-batch1-pc5-site-v2.tar.gz pc-5@10.5.114.47:~/
```

On PC-5 over SSH as `pc-5`:

```bash
tar -xOzf ~/mon-batch1-pc5-site-v2.tar.gz pc5-training-site/upgrade-pc5.sh > /tmp/upgrade-pc5.sh
bash /tmp/upgrade-pc5.sh
curl --max-time 5 http://10.77.0.50:8085/health
```

Expected: `{"status":"READY","training":true,"version":2}`.

This upgrades only `~/mon-training-site` and restarts its existing
`mon-training-site.service`, with a `mon-training-v2-rollback.*`
backup and automatic rollback.

## Step 3 — Trigger precisely bounded, genuine lab requests on PC-6

Ensure the Windows browser has already loaded MON and logged in. Its
Suricata poller suppresses old baseline records on purpose.

On PC-6, check that the live WireGuard endpoint points to PC-2
`10.5.112.136:51820` and the website is reachable:

```bash
sudo wg show wg0
curl --max-time 5 http://10.77.0.50:8085/health
```

Then execute one request per demo vulnerability (no scanners or request
floods). Note HTTP body and timing.

```bash
# A. Training-only document traversal; never requests real host files.
curl --max-time 6 --path-as-is 'http://10.77.0.50:8085/download?file=../training-private/lab-only.txt'

# B. In-memory fictional notice SQL injection via URL-encoded apostrophe.
curl -G --max-time 6 --data-urlencode "q=' OR 1=1 -- " http://10.77.0.50:8085/api/notices

# C. Access another entirely fictitious student ID with a mismatched viewer.
curl --max-time 6 'http://10.77.0.50:8085/api/student?id=STU-1002&viewer=STU-1001'

# D. Toy authentication failure: produces a real HTTP 401 but NOT necessarily
# a Suricata signature. Never use real institutional usernames/passwords.
curl --max-time 6 -i -X POST http://10.77.0.50:8085/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo.student","password":"incorrect-lab-value"}'
```

After each of the first three requests, a **new** PC-5-targeted EVE signature
should appear, and MON may open a red alert. Click **Investigate**: it must
open the exact IDS signature in the Investigation page, not select an
unrelated historical case. Click **Acknowledge detection**: it must visibly
change to **ACKNOWLEDGED**, including a review timestamp.

## Step 4 — Corroborate packets independently (PC-2)

While PC-6 sends the tests, in a PC-2 SSH terminal:

```bash
sudo tcpdump -ni wg0 'host 10.77.0.50 and tcp port 8085'
```

After PC-6 sends a test, on PC-2 within the sensor's 90-second recent
frame window:

```bash
cd ~/mon-three-code
git show FETCH_HEAD:tools/mon-batch1-verify-evidence.py > /tmp/mon-batch1-verify-evidence.py
python3 /tmp/mon-batch1-verify-evidence.py
```

This checker does not manufacture data: it validates the live
`/portal/flows` target capture and `/portal/ids` Suricata EVE, and requires
at least one PC-6→PC-5 TCP/8085 header record within ±30 seconds of a
PC-5-targeted signature 42000501/2/3. It prints **NOT VERIFIED** and exits
nonzero on missing/old/unmatched evidence.

Note: PC-2's observed packet headers prove that frames appeared at PC-2;
a matching IDS log proves that the rule matched. Neither proves a successful
attack, the physical identity of a source, or IPS enforcement.

## Step 5 — Persist PC-6's working WireGuard endpoint

The command `wg set` changed only its live configuration. On PC-6:

```bash
sudo grep -n 'Endpoint' /etc/wireguard/wg0.conf
```

If it is still `10.5.112.94:51820` (the old non-working address), back up
the file and replace **only** that exact string:

```bash
sudo cp -a /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.mon-before-endpoint-fix
sudo sed -i 's/10\.5\.112\.94:51820/10.5.112.136:51820/' /etc/wireguard/wg0.conf
sudo grep -n 'Endpoint' /etc/wireguard/wg0.conf
```

Do not restart the running WG tunnel just to persist this known endpoint.

## Evidence required before calling Batch 1 complete

1. PC-2 upgrade exits successfully, no rollback.
2. PC-5 version 2 health is ready from PC-6.
3. The three controlled requests yield genuine Suricata signatures.
4. The independent evidence checker prints PASS and matching rule IDs.
5. Investigate opens the exact signature with source/target/timestamp.
6. Acknowledge persists the reviewed EVE alert, with visible timestamp.
7. MON’s protected packet rate rises for actual PC-6 traffic, then falls to
   measured zero when traffic stops; no unrelated PC-2 background packet
   counts are passed off as PC-5 traffic.

No automatic IPS response, host takeover or credential attack is asserted.
