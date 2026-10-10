# Three-Ubuntu MON laboratory: Tailscale management, WireGuard evidence path

**Status:** implementation staged in a PR. Supports three Tailscale-managed hosts or a mixed Tailscale-MON/LAN-victim-and-attacker setup, with the orchestrator launched from the MON host when using LAN addresses. Do not claim successful deployment before the disposable-VM integration and an observed physical/remote lab acceptance run. No production tenants or real targets.

This consolidates the seven-PC proof into **three independent Ubuntu machines** without weakening core MON security boundaries.

**Resilience and evidence test gates:** [Three-host resilience acceptance](lab-three-resilience-acceptance.md). This describes the separate disposable-VM-only bounded resource-pressure harness and the real MON evidence-export stage. Neither creates synthetic SOC events.

| Role in `lab-three.json` | Purpose | WireGuard address |
| --- | --- | --- |
| `mon` | PostgreSQL, MON SaaS API (single lab tenant), Site Controller, site ingress, sensor ingress, Suricata, Suricata collector, router nftables adapter, SOC console | `10.77.0.1` |
| `victim` | SSH/journald/auditd, MON Linux endpoint collector, sensor mTLS to MON | `10.77.0.50` |
| `attacker` | Controlled authorized test traffic **only** to the victim overlay, no MON service | `10.77.0.60` |

```text
Operator's Ubuntu workstation
     | SSH over Tailscale (separate management channel)
     +----------+------------+
     |          |            |
  MON host   Victim host  Attacker host
  control    journal      controlled traffic
  site       collector    -> 10.77.0.50 only
  Suricata       |            |
  nft router  WireGuard     WireGuard
     \____________|____________/
        10.77.0.0/24
        hub: MON host
```

**Why WireGuard alongside Tailscale?** Tailscale gives each node a secure remote management address, but switched/Tailscale traffic does not automatically traverse a MON sensor. The MON node acts as the WireGuard hub; victim and attacker route **the lab-only 10.77.0.0/24 subnet** through it. Suricata inspects actual packets on `wg0`, and the Linux victim collector provides independent authenticated endpoint evidence. This does *not* observe arbitrary traffic outside the overlay. If the Tailscale ACL prevents UDP/51820 between the three machines, that is a deployment failure, not evidence of sensor health.

## Prerequisites: do this before running a deployment stage

All three hosts are authorized Ubuntu 24.04 or 26.04 instances, awake and managed by the user with explicit permission. In particular, this script **does not** configure Tailscale or SSH for you; those must already work. For an all-Tailscale inventory, run it from the operator's Ubuntu workstation. If the MON host has Tailscale but victim/attacker have only college LAN addresses, **SSH into MON first and run the orchestrator there**, so no campus subnet route is needed from home. In both cases independently verify machine identities. Verify each real Tailscale IPv4 address and username with `tailscale ip -4` and `whoami` locally on that node.

Configure the deployment controller's SSH key (do not put the shared password in inventory or scripts). For each of three known authorized addresses, verify the host-key fingerprint out-of-band, then manually install that controller's public key using `ssh-copy-id USER@IP`. If running inside MON, install its public key for its own Tailscale SSH identity too. Remote SSH public-key authentication must be operational. The script uses `StrictHostKeyChecking=yes` and `BatchMode=yes`; it will fail, not bypass either trust check, if key-based SSH is not ready. Sudo may prompt *interactively* for each privileged stage. **No unattended execution of privileged firewall stages.**

From an operator checkout of the PR branch:

```bash
git clone https://github.com/Saitanveesh/1.git ~/mon-operator
cd ~/mon-operator
git fetch origin feat/three-host-tailscale-lab
git switch --detach FETCH_HEAD
cp tools/lab-three.example.json ~/lab-three.json
nano ~/lab-three.json
python3 tools/lab_three_host.py --inventory ~/lab-three.json preflight
```

Confirm it prints the real host + user + Ubuntu version + matching Tailscale IP for **all three**, not a fictitious success report. `preflight` is read-only. Do not proceed when any identity does not match.

## Verified mixed-network example: PC2 + PC5 + PC6

These addresses were supplied during the lab discussion and **must be verified again** before use (DHCP can change addresses):

| Role | SSH login used by the script | Management address |
| --- | --- | --- |
| MON | `pc-2@100.75.116.62` (Tailscale); LAN underlay `10.5.112.94` | Tailscale |
| Victim | `pc-5@10.5.112.23` | College LAN, via PC2 |
| Attacker | `pc-6@10.5.112.4` | College LAN, via PC2 |

PC7 (`100.126.27.115` on Tailscale) is optional as an operator browser; the MON architecture needs only three hosts.

From your Ubuntu terminal at home:

```bash
ssh pc-2@100.75.116.62
```

Then **on PC2**, before installing MON, verify the two dedicated lab computers:

```bash
ssh pc-5@10.5.112.23 'hostname; whoami; ip -br -4 addr'
ssh pc-6@10.5.112.4 'hostname; whoami; ip -br -4 addr'
```

Do not continue if either IP resolves to an unexpected computer. Do not scan the college subnet. The script is intended for individually authorized hosts only.

Create `~/lab-three.json` **on PC2** (no passwords):

```json
{
  "mon": {
    "host": "100.75.116.62", "user": "pc-2",
    "network": "tailscale", "lan_ip": "10.5.112.94"
  },
  "victim": {"host": "10.5.112.23", "user": "pc-5", "network": "lan"},
  "attacker": {"host": "10.5.112.4", "user": "pc-6", "network": "lan"}
}
```

The `lan_ip` is used only as the WireGuard endpoint for victim and attacker; the operator console binds to MON's Tailscale IP. The preflight requires the configured management address to appear on each relevant network interface. This is separate from test-traffic addresses `10.77.0.1`, `10.77.0.50`, and `10.77.0.60`.

To run the **read-only** preflight from PC2 after checking out the PR branch:

```bash
python3 tools/lab_three_host.py --inventory ~/lab-three.json preflight
```

The script intentionally uses SSH `BatchMode=yes`, so set up trusted host keys and key-based access before starting. Do not run the privileged deployment or traffic-test stages while away from the computers until the mixed-network layout has been validated in disposable VMs and an onsite recovery route is available.

## Existing VPN and apt lock gate (PC5/PC6 legacy lab)

In the first verified physical lab, PC5 and PC6 already had active `wg0` addresses `10.77.0.50/32` and `10.77.0.60/32`. Both reported a WireGuard peer endpoint `10.5.115.5:51820`, which is **not** PC2's LAN address `10.5.112.94`. Consequently the existing overlay may be routed through the earlier PC3 lab hub. **Do not run the `overlay` stage in this state.** The orchestrator now refuses any active `wg0` before touching keys, routes, nftables or interfaces. Existing peer keys, identities and tunnel configuration must be backed up and an explicit, tested cutover/rollback plan approved before any migration. Do not delete an old config, kill an SSH session or flush nftables to force the setup.

The initial `bootstrap` also stopped on PC5 because another `apt` process held `/var/lib/dpkg/lock-frontend`. Never remove the lock file or kill the package manager. Wait until the process has finished. The installer now uses `DPkg::Lock::Timeout=600` for package installation, but **still stops** on a timeout or other apt error. Installation on PC2 may already have succeeded before PC5 failed, so reruns must stay idempotent and be verified independently.

Inspect package status from PC2 using:

```bash
ssh pc-5@10.5.112.23 'ps -p 53238 -o pid,ppid,etime,stat,args || true; systemctl is-active apt-daily.service apt-daily-upgrade.service || true'
```

After the apt lock is released, rerun `bootstrap` from the updated PR checkout and inspect its output before doing anything to the overlay. The existing active `wg0` state is a hard **migration gate**; the regular `overlay` stage is intended only for previously unused interfaces.

## Current PC2/PC5/PC6 observation — 2026-10-10

The latest real `doctor` output reported **zero APT/DPKG lock holders** across the three hosts. The `/usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal` process is not in itself an active package-lock owner; do not kill it just for existing. PC2 has no `wg0`; PC5 and PC6 have live `wg0` with addresses `10.77.0.50/32` and `10.77.0.60/32`, respectively. Both report a peer endpoint of `10.5.115.5:51820`, not MON PC2's LAN address `10.5.112.94`. They are therefore **not yet part of a PC2-hub telemetry path**. Do not claim Suricata on PC2 sees the current overlay until cutover and packet checks prove it.

The root filesystem reported by `df -h /` is **63 GiB** with about 48–49 GiB free, irrespective of larger physical drives. Never assume 1 TB can be used for tests.

### Stage A: verified read-only migration audit

On PC2 after updating the operator clone:

```bash
cd ~/mon-three-operator
git fetch origin feat/three-host-tailscale-lab
git checkout --detach FETCH_HEAD
python3 tools/lab_three_host.py --inventory ~/lab-three.json migration-audit
```

This checks host identities, PC2's absence of an existing `wg0` and `wg0.conf`, routes to the two named lab peers, UDP/51820 listener metadata, and PC5/PC6's active tunnel addresses, peer count, endpoints, route back to PC2's management address, existing configuration metadata and custom directive names. It **does not print private keys**. It does not change interface state, nftables, forwarding, old hub, or campus routing. If it reports unexpected routing or a custom WireGuard directive, stop for manual review before any cutover.

### Stage B: protected backup (only after Stage A succeeds)

```bash
python3 tools/lab_three_host.py --inventory ~/lab-three.json \
  --approve-migration-backup migration-backup
```

This repeats the audit, then stores a 0600 copy of each peer's live `/etc/wireguard/wg0.conf` and non-secret routing/peer metadata in a uniquely named **root-owned, mode-0700 directory** under `/root/mon-three-wg-backups/` **on PC5 and PC6 themselves**. Only the backup directory path is printed; private-key-containing files never leave their host or enter GitHub, logs, or the operator workstation. This is a backup, **not a cutover or a verified rollback**. Do not delete the old configs, stop wg0, or execute a replacement tunnel until an onsite or disposable VM rehearsed rollback can restore it.

Next required engineering step after backup: prepare the PC2 WireGuard hub with hub-only guard, validate handshake/allowed routes for one peer at a time, and restore the original configuration if health fails. The existing generic `overlay` stage is for virgin `wg0` only and intentionally rejects the active peer tunnels. Its output must not be treated as authority to override that protection.
## Current console improvements and next gated milestone (2026-10-10)

The live operator session was verified from a real laptop: authenticated `mon-lab-operator` and LIVE WebSocket. The old header's `LAST EVENT` timestamp actually reflected receipt of a heartbeat/initial snapshot, so it could stay unchanged for 15 seconds and misleadingly resemble an attack event. The revised console distinguishes **STREAM ACTIVITY** (age since a real received WebSocket frame, recalculated every second) from **LAST EVENT** (true application event; `NONE OBSERVED` if none). Missing WebSocket heartbeats for more than 45 seconds cause reconnect, rather than fake LIVE status. Before any actually ingested telemetry/findings/incidents, Attack Pressure shows `NO DATA` and severity displays `—`, not a fabricated healthy zero or INFO label. This is intentional and must not be overridden merely to make the professor's demonstration appear active. The decorative boxed `M`, operator role, tenant/site slug and internal sequence number are no longer visible in the sidebar. Tenant/site remain mandatory and enforced in APIs and authorization.

The login page now displays **MON — Monitoring, Orchestration, Neutralization**, with neutral operator instructions instead of computer identifiers. See [ADR 0038](adr/0038-mon-name-and-observable-console.md).

**Important deployment fix:** The earlier console script mounted `~/mon-three-code/console`, a pinned backend checkout. That means a refreshed `~/mon-three-operator` branch would **not** change dashboard contents. The new `console` stage mounts `~/mon-three-operator/console` exclusively for the UI and recreates only an out-of-date `mon-three-console` container. It preserves PostgreSQL, MON control-plane code and the existing JWT. No changes to the backend source or VPN follow from this UI restart. From PC2:

```bash
cd ~/mon-three-operator
git fetch origin feat/three-host-tailscale-lab
git checkout --detach FETCH_HEAD
python3 tools/lab_three_host.py --inventory ~/lab-three.json console
```

Refresh `http://100.75.116.62:5173/?tenant=mon-lab&site=site-a` on the authenticated tailnet laptop. UI live activity should tick every second; actual `LAST EVENT` must stay absent/unmodified when no real event is ingested. **Never send fake heartbeat or event traffic just to animate the interface.**

### Hub-only preparation after verified public-key migration plan

A successful `migration-plan` establishes only observed peer public keys and root-only backup integrity. It must return `PLAN_ONLY_NOT_APPLIED`. Do **not** treat that as an active PC2 tunnel.

The new hub staging script, `tools/lab_three_hub.py`, creates the **PC2 hub only**. It rejects conflicting WireGuard interfaces, configs, UDP listeners and nftables guards, installs a constrained MON-owned nftables guard *before* enabling `wg0`, and leaves PC5/PC6 pointed at the old hub. It does not enable forwarding, modify general campus routing, send attack traffic or enroll sensors. The new hub's MON guard is initially volatile, so `wg-quick@wg0` is **started but NOT enabled at boot**. If PC2 reboots or nftables is reloaded, stop and inspect the guard before using the tunnel again. Never enable automatic WireGuard startup without a persistent guard-first dependency and rollback test.

**Stop/go:** This stage affects PC2's local firewall and WireGuard service. Run it only from the authenticated PC2 terminal after verifying that PC2/PC5/PC6 are the intended authorized lab machines, the old backups remain on PC5/PC6, and you have SSH/Tailscale management access and a recovery console:

```bash
cd ~/mon-three-operator
git fetch origin feat/three-host-tailscale-lab
git checkout --detach FETCH_HEAD
python3 tools/lab_three_host.py --inventory ~/lab-three.json \
  --approve-hub-prepare hub-prepare
```

**Physical PC2 failure recorded (2026-10-10):** After an earlier `hub-prepare` attempt, the `hub-verify` stage reported `MON-owned WG0 configuration missing or unexpected`. A real read-only PC2 check confirmed `/etc/wireguard/wg0.conf` **ABSENT**, `wg0` **ABSENT**, `wg-quick@wg0` **inactive**, and `inet mon_three_guard` **ABSENT**. A subsequent explicitly approved `hub-prepare` returned only `CalledProcessError: OS/native command failure` with exit 1. The earlier implementation deliberately masked the native stage, which prevented diagnosis. Review found a likely parser regression: the staged temporary config used prefix `.mon-wg0-` and eight random characters, exceeding the 15-character WireGuard interface-name limit during `wg-quick strip`. Changed this to `wgmon-` plus eight characters (14 total), extended native CI to reproduce the original failure **and** prove the new name succeeds, and added sanitized native-phase diagnostics (no private key, argv or stderr). **Do not retry until these CI gates pass and the unchanged PC2 state is confirmed**. The word `HUB_PREPARED_GUARDED` is a success message from the program, **not** a terminal command. The old PC5/PC6 WireGuard tunnels remain on their previous hub until a separately supervised cutover.

**Expected stage signature:** `HUB_PREPARED_GUARDED`. This claims only the new PC2 hub and MON-owned guard were installed. It does not claim any peer migration or telemetry.

Then run the **read-only** confirmation:

```bash
python3 tools/lab_three_host.py --inventory ~/lab-three.json hub-verify
```

Expected: `HUB_GUARD_VERIFIED`, PC2 has `10.77.0.1/24`, WireGuard listens on UDP/51820 and two peer public keys are configured. Both latest handshakes should remain `0` until PC5/6 are migrated. Never paste private keys, JWTs, secret config contents or full logs with secrets into chat.

If the hub was installed but is not yet serving either peer and must be removed, run this **explicitly approved rollback**:

```bash
python3 tools/lab_three_host.py --inventory ~/lab-three.json \
  --approve-hub-rollback hub-rollback
```

Rollback refuses to stop a hub once *any* actual handshake has occurred. It removes only the MON-owned configuration/guard and does not change the old peer configurations. Once a peer migrates, a separate endpoint recovery stage must restore it safely. Do not use `overlay` to overwrite old `wg0` on PC5/6.

**Status:** PC2 physical installation, nftables service activation and peer cutover have not been observed from this chat. CI alone does not establish them. See [ADR 0039](adr/0039-existing-wireguard-hub-cutover.md).

### Next safe site-controller gate — real WireGuard path

PC5/PC6 still point to **old hub `10.5.115.5:51820`** and PC2 was observed without `wg0`. We must *not* launch MON site controller, Suricata or victim collector yet: doing so would create unreachable sensor ingress or claim false network visibility.

A new **`migration-plan`** stage repeats the existing WireGuard audit, verifies each root-only saved `wg0.conf` against its SHA-256 backup, extracts **public keys only** from the existing live interfaces and prepares a PC2 public-key preview, without starting interfaces or changing routes, forwarding or nftables:

```bash
cd ~/mon-three-operator
python3 tools/lab_three_host.py --inventory ~/lab-three.json migration-plan
```

The output must say `PLAN_ONLY_NOT_APPLIED`. This step requires access to the authorized three machines and sudo to inspect their backup metadata; it will never print an old private key. If an old backup is absent, tampered with, or the peer identity differs, the stage fails. The preview can then inform a separately approved and rehearsed PC2 hub cutover with one-peer-at-a-time verification and rollback.

After that cutover is actually performed, run the new **read-only** `site-preflight` stage:

```bash
python3 tools/lab_three_host.py --inventory ~/lab-three.json site-preflight
```

This enforces PC2 ownership of `10.77.0.1/24`, two recent verified hub WireGuard handshakes, port 51820, presence of the MON-owned nftables guard, authenticated control plane READY, PC5/PC6 tunnel endpoints equal to PC2, and independent SSH/management routes. **It is expected to fail today while the old hub remains in use.** The `site` and `victim` installation stages now invoke it before any local identity enrollment or sensor setup, so running them prematurely cannot silently build an apparently healthy but blind system.

Only after `site-preflight` succeeds should the operator proceed with `site`, `victim`, `ready`, and real evidence snapshots. No production readiness or physical end-to-end incident is claimed from code and CI alone.

## Deployment, one stage at a time

Use the same `--inventory ~/lab-three.json` argument in every command below. We intentionally require explicit flags before privileged installation or overlay routing.

```bash
python3 tools/lab_three_host.py --inventory ~/lab-three.json --approve-install bootstrap
python3 tools/lab_three_host.py --inventory ~/lab-three.json --approve-overlay overlay
python3 tools/lab_three_host.py --inventory ~/lab-three.json control
python3 tools/lab_three_host.py --inventory ~/lab-three.json console
python3 tools/lab_three_host.py --inventory ~/lab-three.json site
python3 tools/lab_three_host.py --inventory ~/lab-three.json victim
python3 tools/lab_three_host.py --inventory ~/lab-three.json ready
# Optional, only after the readiness gate and before an authorized recon demonstration:
python3 tools/lab_three_host.py --inventory ~/lab-three.json --approve-demo-setup demo-prepare
```

The stages are deliberately independent. **Stop on the first failed stage and inspect the full output.** Do not run the `site` stage before MON is `READY` or the `victim` stage before sensor ingress/trust synchronization.

- `bootstrap`: apt packages and identical, **pinned** existing MON revision `8f66baa9f8d287b8c05da379259b289c661c5828` on MON and victim. The orchestrator itself may be newer, but all backend components are pinned. No destructive `git reset` or `rm -rf` checkout.
- `overlay`: creates new per-node WireGuard private keys on the node itself (never on the operator workstation), refuses to replace an existing `wg0.conf`, configures the three peers and adds a MON-owned `mon_three_guard` table before enabling IPv4 forwarding. **Never runs an egress firewall on the attacker**, which would cut your remote Tailscale SSH access. This still must be tested in a disposable VM or with local recovery.
- `control`: persistent PostgreSQL Docker volume on MON host only; restricted `mon_app_lab` DB role, migrations, short-lived lab CA/JWT identities, real API on `127.0.0.1:8080`, and site ingress on `127.0.0.1:8443`. No default production credentials.
- `console`: real React SOC console using pinned Node 22 Docker image and API proxy; bound to **MON's Tailscale IP** on port 5173. Does not enable mock or seed data. The UI is an HTTP development server over the encrypted tailnet, not a public production web server.

  **Ubuntu 26.04 lab regression (2026-10-10):** The original installer ran `npm ci`, but the repository has `console/package.json` and **no `console/package-lock.json`**. The control plane had already reported `READY`; only the console-install stage failed. The operator script now uses `npm install --no-package-lock --no-audit --no-fund`, consistent with existing console CI, with `/app/node_modules` stored in a Docker volume. This avoids modifying the pinned source checkout. Retry **only** the console stage after fetching the fixed operator branch, not bootstrap or the database migration. This fixes the immediate lab boot path but does **not** provide reproducible frontend dependency resolution: production release must commit and enforce a reviewed dependency lockfile and immutable container digest. Verify actual console HTTP response and authentication before claiming live SOC access.
- `site`: local site identity enrollment + Suricata sensor enrollment, local Site Controller, sensor mTLS ingress on `10.77.0.1:9443`, Suricata on `wg0`, real collector and router enforcement-point registration. Do **not** approve containment against infrastructure or sensitive systems.
- `victim`: locally-generated private CSR/key, controlled certificate enrollment by MON (only CSR and signed public certificates transit the operator workstation), Linux journald/auditd endpoint collector. No SSH password policy change, common attack account creation, or permanent firewall isolation.
- `ready`: fails unless control-plane state is READY, both real sensor heartbeats are recent, and both WireGuard peers have recent handshakes. This does not yet establish containment or correlation. Even fresh heartbeats do not prove correlation/containment until verified with approved, real traffic and rollback.


### PC2 lab-only operator browser sign-in (no JWT in DevTools)

The console does **not** automatically authenticate just because its HTML loads. Without an authenticated browser session, its **AUTHENTICATION REQUIRED / LIVE TRANSPORT OFFLINE / 0 incidents** display is expected and cannot be used as proof of zero threats.

MON accepts the existing signed JWT in an `HttpOnly` `mon_session` cookie for HTTP and authenticated WebSockets. The previous seven-PC guide asked the operator to paste a full JWT into JavaScript-readable cookies in browser developer tools; this is **deprecated for the three-host lab**. We now use a one-time pairing bridge. The bridge requires the real MON `/api/v1/me` endpoint to validate the existing `tenant_admin` JWT; it does not mint identities or disable tenant RBAC.

**On PC2, after `control` and `console` succeed**, update the operator PR checkout and run the two stages:

```bash
cd ~/mon-three-operator
git fetch origin feat/three-host-tailscale-lab
git checkout --detach FETCH_HEAD
python3 tools/lab_three_host.py --inventory ~/lab-three.json console
python3 tools/lab_three_host.py --inventory ~/lab-three.json browser-login
```

The first command to run `console` after updating will replace **only MON's own console container** (reusing its existing `node_modules` Docker volume) with a read-only Vite overlay for `/lab-session` proxying to `127.0.0.1:8766`. PostgreSQL, the control-plane API, WireGuard, site controller and sensor services are not changed. The second stage launches `tools/lab_browser_login.py` as the unprivileged PC2 user on localhost, verifies the existing token against MON's RBAC-protected `/api/v1/me` endpoint, and prints a random one-use pairing code. Only the operator's protected PC2 log stores that code. **Never share the code or full operator JWT in chat, GitHub issues or screenshots.**

From the **operator laptop already connected to Tailscale**, open:

```text
http://100.75.116.62:5173/lab-session/
```

Enter the one-use code from your PC2 SSH terminal and select **Sign in**. The browser receives a `mon_session` JWT in an **HttpOnly; SameSite=Strict** cookie for the dashboard origin (1-hour cookie TTL; the signed token may expire sooner), then redirects to `/?tenant=mon-lab&site=site-a`. The pairing server binds to **127.0.0.1 only**, expires after ten minutes, accepts at most five incorrect attempts, and shuts down after successful redemption. No signing key, private WireGuard config or JWT is ever printed or copied into the operator command line. The signed session token **is** delivered to the browser in its cookie as expected; it is not JavaScript-readable.

**Security boundary:** This is a **disposable lab** bootstrap, not a production OIDC/SSO login. The browser is served over HTTP on the encrypted Tailscale-only overlay; this temporary flow cannot mark its cookie `Secure` without HTTPS. For any real tenant, use HTTPS, OIDC Authorization Code + PKCE, secure refresh/session handling, CSRF and session revocation, and proper operator account management. Do not expose port 5173 to the public Internet, college LAN, or untrusted peers.

**Browser login regression and resolution, observed 2026-10-10:** Operators repeatedly received `Pairing denied`, `Browser origin could not be verified`, then `Same-origin browser verification required`. These were genuine failures caused by treating `Origin` and `Sec-Fetch-Site` as stable inputs through the browser → Vite → localhost Python HTTP proxy path. Those headers may be absent or rewritten upstream. Since the Python pairing listener is bound to `127.0.0.1` and accessed via the Tailscale-bound Vite proxy, the **lab-only** login uses a stronger, proxy-independent pairing handshake: an independent high-entropy operator code from PC2 plus the unpredictable form nonce rendered by the login page. Both must match in constant time; the server enforces one-time use, a ten-minute pairing lifetime, at most five attempts, and re-verifies the existing signed `tenant_admin` JWT against the live MON `/api/v1/me` endpoint at redemption. No arbitrary browser-supplied origin, header, bearer JWT or site role is trusted for authentication. Requests without a correct code and current nonce cannot set `mon_session`. The UI now shows a plain MON operator sign-in rather than implementation details.

**Recovery:** Fetch the current PR in `~/mon-three-operator` on PC2 and rerun **only** `browser-login`. Open a fresh login page to get the new nonce and submit the freshly printed code. Previously shown codes were exposed in chat screenshots and must be discarded. The Vite console container and backend need not restart. Do not send codes, JWT, cookies or private signing keys in chat.

This minimal one-time pairing is acceptable **only as lab bootstrap** under the present private tailnet trust model. Before production SaaS use, replace it with HTTPS and federated OIDC/PKCE, secure sessions, CSRF protection, revocation and explicit account lifecycle. It is not a claim of production identity readiness, nor proof that sensors or the investigation workflow are online.

**Troubleshooting:** If `/lab-session/` returns 502, verify `browser-login` is running and `console` was restarted from the updated PR. If the pairing server prints `MON refused the operator credential`, the 12-hour lab token may have expired; stop and renew it through the signed-identity process rather than bypassing validation. A successful login proves authenticated access only, **not** sensor coverage. LIVE WebSocket traffic and real sensor heartbeats must be observed separately before claiming monitoring operational.

**Operator UI:** browse `http://MON_TAILSCALE_IP:5173/?tenant=mon-lab&site=site-a` from a machine in the same tailnet. Signed `operator.jwt` remains private on the MON host under `~/mon-three/identity/`. It expires after 12 hours; subsequent sessions require an explicitly documented identity refresh, not a forged auth bypass. Use the existing test-day operator login procedure only in this disposable lab. No operator token is copied into the code, inventory, console build or reports.

- `demo-prepare`: optional victim-only nftables rule for 100 filtered TCP ports (20000-20099), strictly from the attacker overlay IP and on `wg0`. It enables the detector's unanswered SYN test shape without running any probes. Remove only `mon_three_victim` to revert. No broad firewall changes.

**Scope:** Because the third computer is Linux, we can demonstrate Suricata network evidence, Linux endpoint evidence, correlation, site-policy approval, MON-owned nftables router BLOCK_IP, rollback, and auditing *if* observed end-to-end. We **cannot claim a live Windows collector**, multi-site isolation, real volumetric upstream DDoS protection, or production-grade HA from this topology.

## Acceptance and safe cleanup

The earlier seven-system [live test-day command sheet](lab-seven-system-command-sheet.md) provides the evidence requirements and investigator workflow. Adapt the *targets* to `10.77.0.50`, `10.77.0.60` and enforcement point `mon-three-router`. Before any approved test: prove the attacker can reach **only** the victim's intended overlay path, the normal management/Tailscale sessions stay up, the sensor ingests observed flows, and the policy approval/TTL/rollback path exists. Do not scan the campus LAN, run unbounded flood attacks, or launch tests automatically with the installer.

If the WireGuard/guard stage fails, stop. A privileged local operator can inspect and remove **only MON-owned** configuration as appropriate (not `nft flush ruleset`):

```bash
sudo nft list table inet mon_three_guard
sudo nft delete table inet mon_three_guard
# On the victim only, if the optional demonstration rule was installed:
sudo nft delete table inet mon_three_victim
sudo systemctl disable --now wg-quick@wg0
```

Only remove `wg0` if it was created by this lab; the script refuses to overwrite existing `wg0.conf`. The MON site adapter creates its own `mon_router` table; never blindly delete or flush non-MON firewall tables. Stop Docker `mon-three-console` or `mon-three-postgres` only when you intend to stop those lab services. Database volume and credential files are retained, not destroyed.

**Known constraints:** The monolithic three-host node has a single failure domain and higher CPU/RAM cost. Ubuntu 26.04 compatibility, Suricata AF_PACKET against WireGuard, CI/repo dependencies and real Tailscale ACL/SSH behavior must be confirmed in a disposable environment. Command success alone is not proof of health. Recorded failures, stale sensor heartbeats, expired JWTs, or missing mTLS identities must never be presented as live telemetry.
