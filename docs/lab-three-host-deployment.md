# Three-Ubuntu MON laboratory: Tailscale management, WireGuard evidence path

**Status:** implementation staged in a PR. Do not claim successful deployment before the disposable-VM integration and an observed physical/remote lab acceptance run. No production tenants or real targets.

This consolidates the seven-PC proof into **three independent Ubuntu machines** without weakening core MON security boundaries.

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

All three hosts are dedicated, disposable Ubuntu 24.04 or 26.04 instances, awake and managed by the user with explicit permission. In particular, this script **does not** configure Tailscale or SSH for you; those must already work. Run it from the operator's Ubuntu workstation, **not necessarily PC2**, because all three nodes are now on Tailscale. Verify each real Tailscale IPv4 address and username with `tailscale ip -4` and `whoami` locally on that node.

Configure the operator workstation's SSH key (do not put the shared password in inventory or scripts). For each of three known authorized addresses, verify the host-key fingerprint out-of-band, then manually install the operator public key using `ssh-copy-id USER@TAILSCALE_IP`. The script uses `StrictHostKeyChecking=yes` and `BatchMode=yes`; it will fail, not bypass either trust check, if key-based SSH is not ready. Sudo may prompt *interactively* for each privileged stage. **No unattended execution of privileged firewall stages.**

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
- `site`: local site identity enrollment + Suricata sensor enrollment, local Site Controller, sensor mTLS ingress on `10.77.0.1:9443`, Suricata on `wg0`, real collector and router enforcement-point registration. Do **not** approve containment against infrastructure or sensitive systems.
- `victim`: locally-generated private CSR/key, controlled certificate enrollment by MON (only CSR and signed public certificates transit the operator workstation), Linux journald/auditd endpoint collector. No SSH password policy change, common attack account creation, or permanent firewall isolation.
- `ready`: fails unless control-plane state is READY, both real sensor heartbeats are recent, and both WireGuard peers have recent handshakes. This does not yet establish containment or correlation. Even fresh heartbeats do not prove correlation/containment until verified with approved, real traffic and rollback.

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
