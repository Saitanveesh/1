# MON Stage 4 — final blue-team containment and victim-impact runbook

**Release branch:** `release/mon-batch4-rc1`

**Prerequisite:** Existing Stage 3 MON console on PC-2, PC-5 fictional training website, and WireGuard peers PC-6 (`10.77.0.60`) and PC-7 (`10.77.0.70`). PC-2 gateway is `10.77.0.1`; PC-5 victim is `10.77.0.50:8085`.

Stage 4 is **implemented and CI-tested in version control**, not automatically installed on your real PCs. It requires the actions below and live verification. No background deployment occurs.

## What the operator will see

Open a **real**, recently triggered Suricata training signature in MON's **Alerts → Investigate**.

The **Protect the application** section has two independent perspectives:

- **Without intervention:** PC-5's own application journal reports how many requests it handled and which successful HTTP responses contained **fictional student records**, **fictional internal notices**, or the **fictional training canary**, including server-written response bytes and recorded times. No fabricated losses, mock historical traffic, invented secrets, or real university student data are used. The data is intentionally vulnerable, but restricted to training fixtures.
- **Operator response:** a trained operator can approve a **30-, 60-, 120-, or 180-second** block from the confirmed attacking WireGuard IP to the **single victim endpoint, TCP 8085**. A privileged helper enforces the source restriction in Linux **nftables FORWARD** on PC-2. The frontend reports kernel rule state, time remaining, actual cumulative dedicated-rule packet drops (shared across the two allowable sources) and the operator's block/release history. There is no silent automatic enforcement.

The **Restore access** control removes only the targeted source element. The kernel timeout removes it even if the user leaves the UI or the process exits. Repeated requests to block an already blocked source are rejected rather than extending the block without authorization.

A **Copy situation report** control assembles what the real firewall and application evidence support, including their limits. **Acknowledging** an alert still only records operator review; it is not equivalent to blocking, closing an incident, or proving a compromised victim.

## Security boundaries

1. Only **source `10.77.0.60` or `10.77.0.70` → destination `10.77.0.50` TCP port `8085`**, forwarded from `wg0` to `wg0`, can be dropped. Never SSH, UDP WireGuard 51820, the PC-2 dashboard, other victim ports, or other clients.
2. A block requires an authenticated MON portal session, known browser Origin, existing protected-route verification, active Suricata, a matching **real** recent signature ID `42000501`, `42000502` or `42000503`, and confirmation in the UI. A signature older than three minutes is ineligible.
3. An isolated, privileged helper speaks exclusively through a restricted local Unix socket. The web portal cannot execute arbitrary firewall commands and does not gain direct CAP_NET_ADMIN. Helper code runs from a **root-owned location outside pc-2's home directory**.
4. There is **no attempt to exploit a real application, no host file exfiltration, and no claim of real personal-data loss**. The application tracks server-side successful fictional responses. A server write is not the same as a client receiving data.
5. Kernel drop counters represent the **whole dedicated rule**, not attribution to one source. Additional direct attacker-side connectivity tests are required before claiming a block is effective.
6. Stage 4 does not alter the original MON incident-response or case database or the PC-5/PC-6/PC-7 WireGuard peer identities. It does not restart WireGuard or Suricata.

## Step 1 — Run PC-2 preflight and install the monitoring upgrade

Log in as `pc-2` on the existing PC-2 Ubuntu host:

```bash
cd ~/mon-three-code
git fetch --no-tags https://github.com/Saitanveesh/1.git \
  refs/heads/release/mon-batch4-rc1

git show FETCH_HEAD:tools/mon-stage4-pc2.sh > /tmp/mon-stage4-pc2.sh

# No live changes on --check:
bash /tmp/mon-stage4-pc2.sh --check

# Only if preflight passes:
bash /tmp/mon-stage4-pc2.sh --apply
```

The installer prechecks the existing portal, frontend, `wg0` route, npm dependencies and nftables. It stages the pinned GitHub files, runs Python tests, builds the frontend, and runs Vitest **before** modifying live files. After a full backup, it installs the narrow root-owned helper, modifies the operator portal and frontend, and restarts **only** the new helper, the MON portal and the MON frontend. It tests endpoint health and its actual authenticated mitigation status. On a failure, it attempts to restore the old console, portal and unit.

The final output creates `~/mon-three/mon-stage4-pc5.tar.gz`.

**Important:** If preflight fails, stop and inspect the printed error rather than rerunning legacy MON, WireGuard or IDS installers.

## Step 2 — Upgrade the victim on PC-5

From the **PC-2 terminal**, copy the generated training archive:

```bash
scp ~/mon-three/mon-stage4-pc5.tar.gz pc-5@10.5.114.47:~/
```

On **PC-5**, log in as `pc-5` and execute:

```bash
tar -xOzf ~/mon-stage4-pc5.tar.gz \
  pc5-training-site/stage4-upgrade-pc5.sh \
  > /tmp/stage4-upgrade-pc5.sh

bash /tmp/stage4-upgrade-pc5.sh --check

bash /tmp/stage4-upgrade-pc5.sh --apply

curl -fsS http://10.77.0.50:8085/health
```

The expected version is `4`. This modifies only the fictional Campus Gateway training site and restarts `mon-training-site.service`. It preserves a rollback archive and tests the new code before replacement. Its impact journal stores bounded **synthetic-data response metadata only**, not passwords or raw attack queries.

## Step 3 — No-response scenario (blue team observes without blocking)

Open the MON portal on the operator computer:

`http://100.75.116.62:5174/?tenant=mon-lab&site=site-a`

From **PC-7**, trigger the deliberate fake canary and student-record weaknesses using one HTTP request each:

```bash
curl --max-time 6 --path-as-is \
  'http://10.77.0.50:8085/download?file=../training-private/lab-only.txt'

curl --max-time 6 \
  'http://10.77.0.50:8085/api/student?id=STU-1002&viewer=STU-1001'
```

From **PC-6**, use the same controlled training cases if a second independent attacker is useful for the demo.

A qualifying real IDS alert should appear **only if** Suricata is actually working and recognizes the request. Click **Investigate → Protect the application**. With no mitigation, the PC-5 impact panel should show the exact observed request counts and fictional exposure responses; it must **not** manufacture losses before the requests are issued.

**Important:** The panel covers up to the last hour and a bounded journal window. Records predating deployment are not retroactively recoverable.

## Step 4 — Blue-team mitigation scenario

Generate a **fresh** detectable training request from PC-7. Open its new alert and select:

**Investigate → Protect the application → Block this source temporarily → 2 minutes → Approve → Apply timed block.**

The rule applies **only to the alert's source IP and the fictional victim's HTTP port**. The MON panel should report an **active kernel rule** and a timer.

While the block is active, from **PC-7**, attempt a **new connection**:

```bash
curl --connect-timeout 3 --max-time 5 -v \
  'http://10.77.0.50:8085/health'
```

A connection timeout supports that the block was effective along this path. It is **not sufficient alone** to establish that the firewall caused the timeout; corroborate the kernel drop counter, Suricata/packet capture and the successful connectivity test before blocking.

From **PC-2**, independently inspect only the dedicated firewall state:

```bash
sudo nft -a list chain inet mon_stage4_range training_forward
sudo nft -j list set inet mon_stage4_range blocked_sources
```

From **PC-6**, verify that its *separate* attacker path remains reachable:

```bash
curl --connect-timeout 3 --max-time 5 \
  'http://10.77.0.50:8085/health'
```

PC-6 should remain accessible if only PC-7 was blocked. If it is not, investigate unintended network effects before proceeding.

The victim journal should **stop recording new PC-7 responses after the block takes effect**. Old exposed fixture data is not retroactively withdrawn or deleted. In-flight responses may still have completed before enforcement; use timestamps to distinguish them.

Restore PC-7's web access with the **Restore access** button (or allow the short kernel timeout). Repeat the PC-7 health request to confirm recovery. No tunnel restart is necessary.

## Step 5 — Situation analysis

The operator can **Copy situation report**. Review:

- Detection time and which source IP was observed.
- Whether a matching rule was installed, and its expiration state.
- Whether the dedicated nftables counter incremented after the blocked probe.
- Whether PC-5 handled any new post-block requests from that specific source.
- Fictional response counts and bytes written before or after intervention.
- Whether the unaffected other attacker retained access.
- Whether manually restoring or allowing the timed rule to expire restored access.

A detection ≠ an exploit, a server-written response ≠ confirmed client receipt, and an installed firewall rule ≠ proven prevention until the independent connectivity checks agree.

## Final acceptance gate

Stage 4 may be called operational only when **all** of these are demonstrated on the actual PCs:

- PC-2 new portal/console/helper are healthy; PC-5 site reports version 4.
- An actual PC-7 training request generates a matching Suricata alert.
- Without a block, PC-5's real journal shows the fictional response that was returned.
- The operator can authorize a fresh alert's **timed** block; the kernel confirms it.
- A fresh PC-7 request fails while blocked; the dedicated rule drop count increases and PC-5 has no corresponding new successful response.
- PC-6's independent connection to the victim works throughout the PC-7 block.
- PC-7 access is restored by **Restore access** or timeout and verified from the attacker.
- The situation report and audit timeline match the events and do not claim actual student-data loss.

## Rollback and caution

Both upgrade installers create timestamped rollback archives under `~/mon-three` on PC-2 and `~/` on PC-5. No MON database migration or WireGuard peer key change is involved. If the new service health check fails, the relevant installer attempts rollback automatically.

Firewall helper failures must be treated conservatively: inspect `sudo nft list table inet mon_stage4_range` before repeating a block. The dedicated timed set may remain installed after a failed app deployment; its individual elements expire automatically. Do not flush global firewall tables to repair a Stage 4 issue.

**Release status:** GitHub code and automated checks complete; live lab installation and the specific packet/drop/effectiveness evidence must still be performed on the operator's machines.
