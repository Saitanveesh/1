# MON three-PC lab: restart, snapshot, verify, upgrade

## Purpose and scope

This runbook describes the **existing working 28 October 2026 lab**, not a fresh install or an assertion that every release gate has been run. The goal is a reproducible operator experience while retaining the deployed security boundaries, original identity material, PostgreSQL data, and rollback artifacts.

| Node | Ubuntu account | WireGuard | Runtime that must survive VM restart |
| --- | --- | --- | --- |
| PC-2, Blue Team/gateway | `pc-2` | `10.77.0.1` | `mon-three-postgres` Docker container, MON API at `127.0.0.1:8080`, `mon-three-lab-portal`, `mon-three-console-v2`, `mon-suricata-passive`, `mon-stage4-gate`, `wg-quick@wg0` |
| PC-5, fictional victim | `pc-5` | `10.77.0.50` | `mon-training-site`, `wg-quick@wg0`; `/health` expected to return version 4 |
| PC-7, Red Team UI | `pc-7` | `10.77.0.70` | `mon-batch2-attack-console`, `wg-quick@wg0`; UI at `127.0.0.1:8766` |

PC-7 has a **separate, older** Docker Compose stack (`mon-3pc-control-plane-1`, `mon-3pc-postgres-1`) observed in an unhealthy state. This runbook does not automatically start or replace that stack: the local attack console was confirmed to work independently, and a database replacement risks data loss. Inspect and retire it separately only after dependencies are verified.

**Do not containerize the host's WireGuard routing, Suricata packet capture, or nftables enforcement simply to make the demo start faster.** They need host networking, narrow privileges, and a verifiable enforcement point. Use Ubuntu VMs as the sandbox boundary and Docker for the existing PostgreSQL/application containers. Do not clone VMs onto the connected lab LAN while the originals are running: duplicated overlay IPs, private keys, and endpoint identities would collide.

## One-time preparation, after CI and a VM checkpoint

1. From the Hyper-V/VMware/VirtualBox GUI used on each Windows host, **take a named VM snapshot/checkpoint** for PC-2, PC-5, and PC-7 (and record host, VM name, timestamp, network mode, snapshot ID). If the hypervisor requires powered-off snapshots for consistency, shut down the guest cleanly first. The VM checkpoints cover root-owned firewall configuration, SSH/WireGuard keys, Python environments, services, and application files that a PostgreSQL dump alone cannot cover. Store export backups encrypted and off the college shared LAN; don't commit them to GitHub.
2. On PC-2, create and verify a PostgreSQL logical backup **before** a risky upgrade: `bash ~/mon-labctl.sh backup`. It is intentionally a local, private file under `~/mon-lab-backups/`, not an automated cloud upload; restore must be rehearsed in a disposable VM.
3. Fetch the release-verified operations script from the repo onto PC-2, PC-5, and PC-7. Use an exact reviewed commit when promoting this PR, not a mutable moving branch, and verify `bash -n` before execution. On each Ubuntu VM, as its normal `pc-2`, `pc-5`, or `pc-7` account:

   ```bash
   # Replace RELEASED_COMMIT with the tested/approved GitHub commit SHA.
   curl -fL --retry 2 --max-time 20 \
     "https://raw.githubusercontent.com/Saitanveesh/1/RELEASED_COMMIT/tools/mon-three-labctl.sh" \
     -o "$HOME/mon-labctl.sh"
   chmod 700 "$HOME/mon-labctl.sh"
   bash -n "$HOME/mon-labctl.sh"
   bash "$HOME/mon-labctl.sh" status
   ```

   If guests cannot access GitHub, fetch the pinned script **on PC-2** using its existing Git checkout and `git show <commit>:tools/mon-three-labctl.sh > ~/mon-labctl.sh`; copy it by SSH/SCP over WireGuard only after verifying target host keys. Never feed an unreviewed URL directly into `bash`.
4. Once the services already installed on each VM have been confirmed, run `bash ~/mon-labctl.sh enable` **once on each VM**. This explicitly enables only known installed units (`wg-quick@wg0`, the correct role-specific MON units) and, on PC-2, configures the existing `mon-three-postgres` container with the Docker `unless-stopped` restart policy. It doesn't install or launch an attack, create a database, or rekey the WireGuard network.
5. Verify PC-2's control plane on port `8080` is **itself supervised after reboot**. In the 28 October live session an `uvicorn` listener existed but there was no `tmux` session; its parent service/launcher has **not yet been identified**. The script checks it rather than guessing a `systemctl` unit or launching a second database-dependent API process. If it is not persistent, use `systemctl status <PID>`/`ps -o pid,ppid,cmd -p <PID>` to identify the true launcher and add a tested, existing-environment systemd unit in a separate PR. This is the remaining blocker to guaranteeing one-click startup after *every* reboot.
6. Ask the LAN administrator for a **DHCP reservation or approved stable endpoint** for PC-2's LAN IP `10.5.112.136`. PC-5 previously had stale endpoint `10.5.112.94:51820`, which caused the tunnel outage; the startup script intentionally never changes peers, routes, or host addressing. If the IP changes, fix and audit the VPN endpoint explicitly, not by reinstalling WireGuard.

## Next lab day

Power on all three Ubuntu VMs on their intended Windows hosts. Their enabled services should start independently. On PC-2:

```bash
bash ~/mon-labctl.sh start-all
bash ~/mon-labctl.sh status-all
```

`start-all` first starts the **existing** PC-2 PostgreSQL container and role-specific services, then uses SSH through the existing WireGuard addresses to invoke the same script on PC-5 and PC-7. This requires VM networking and `wg0` to have come up, SSH running on both guests, installed script at each user's home, and ability to enter SSH and sudo credentials when prompted; do not silently disable host-key checks or put passwords in scripts. If SSH is unavailable, run `bash ~/mon-labctl.sh start` locally on PC-5 and PC-7 and then `status` on each. Failure is reported rather than faked as `READY`.

At the end of `status-all`, verify from a laptop (on approved Tailscale access) that the PC-2 console `http://100.75.116.62:5174/?tenant=mon-lab&site=site-a` is usable; sign in using the existing MON login. `status` tests the signed operator JWT and the authenticated live snapshot; an HTTP `401` means the operator token needs renewal with existing signing keys. Run `bash ~/mon-labctl.sh renew-token` **only on PC-2**, confirm the new token passes the real local MON API check, then delete the old browser `mon_session` cookie and sign in normally. An HTTP `500` requires backend/database logs instead of a cookie change. Do not bypass auth, invent new signing keys, or paste tokens into reports. PC-5 must report `{"status":"READY","training":true,"version":4}` and PC-7's *own browser* opens `http://127.0.0.1:8766/`.

**Startup passes do not prove a true end-to-end detection, safe containment, blast radius, audit, TTL rollback, or VM recovery.** Run the separately approved Batch 4 acceptance scenarios on lab fixtures before claiming them.

## Before leaving today

- Stop all training traffic from PC-7; do not leave attack-generating processes running unattended. The management UI alone is not a traffic generator.
- Record a no-attack baseline and use `status` on each VM. On PC-2 run the PostgreSQL `backup` command; validate it completed and retain the SHA-256 checksum. Check free storage and external encrypted backup retention.
- Take a VM checkpoint of each guest using the actual hypervisor after recording the current Git revision, time, deployment inventory, and known-good health. Name them, e.g. `MON-B4-working-2026-10-28-PC2`, `...PC5`, `...PC7`. A checkpoint is not a substitute for off-host export or a tested restore.
- Do not manually delete Docker volumes, `docker compose down -v`, run old one-shot reinstallation scripts, disable WireGuard, or flush nftables. The active Stage 4 timed block set already has a narrow timeout. Store existing private keys and passwords only inside secured snapshots, never the git repo.
- If campus equipment policies require powering down, shut down Ubuntu VMs cleanly and then the Windows hosts after the backups/checkpoints. Never leave a public listener or an active testing campaign running on the college LAN.

## Upgrade and rollback policy

1. The GitHub repo is canonical; use a feature branch, reviewable PR, tests/CI, documented upgrade impact and commit pin. `main` stays stable. Changes to UI, services, schema, and enforcement are separately staged. Never use `git pull` against a running application directory or blindly update Docker images to `latest`.
2. Before applying an approved change: `bash ~/mon-labctl.sh status` and (PC-2) `bash ~/mon-labctl.sh backup`. Create a VM checkpoint of each affected guest and log the old commit and service configuration.
3. Use the **specific verified installer for that change** with `--check` first, followed by `--apply` only after preflight success. For example, the already reviewed Batch 5 UI-only installer is `tools/mon-batch5-pc2.sh`, and the Batch 4 Stage 4 installer is `tools/mon-stage4-pc2.sh`; neither should be blindly rerun against unknown revisions. The operations script does not mutate source code or automatically apply unreviewed upgrades.
4. Run unit/integration/security regression tests; after applying, use `status-all` and the narrow training canary scenario. If any acceptance criterion fails, use the installer's saved rollback archive or a tested VM snapshot restore in a **disconnected disposable VM** first. For PostgreSQL rollback, use a separately verified logical backup and compatible schema, not an ad hoc `docker rm`.
5. Record results (incident, scope, confidence, evidence, timestamp, affected services, TTL/blast radius for response actions, rollback, and verified recovery) back to the repository runbook/ADR. Never equate an installed nftables rule with proof of a successful block without an attacker-side fresh connection test and kernel counter corroboration.

## Diagnostics if startup gate fails

- PC-2 database: `sudo docker ps -a --format 'table {{.Names}}\t{{.Status}}'`; `sudo docker logs --tail 40 mon-three-postgres`; do **not** use the different `mon-postgres` container name.
- PC-2 JWT: `bash ~/mon-labctl.sh status` checks the real API without printing secrets. If it reports HTTP 401, `bash ~/mon-labctl.sh renew-token` signs a **new 8-hour** JWT using the already trusted private key, verifies the backend accepts it, then atomically replaces the operator token with a private backup. This changes no site-controller tokens, certificates or trust material. Do not share any token value.
- PC-2 backend: `sudo ss -lntp '( sport = :8080 )'`; inspect the actual supervisor/daemon logs; `HTTP 500` on live snapshot requires DB or backend investigation rather than a new cookie.
- PC-5: `sudo wg show wg0`; `systemctl is-active mon-training-site`; `curl --noproxy '*' -s http://10.77.0.50:8085/health`.
- PC-7: `systemctl is-active mon-batch2-attack-console`; `sudo ss -lntp '( sport = :8766 )'`; `sudo journalctl -u mon-batch2-attack-console -n 30 --no-pager`.
- Network: PC-7 and PC-5 must independently ping PC-2 `10.77.0.1`. A WireGuard interface showing `UP` does not prove a handshake or end-to-end forwarding.
