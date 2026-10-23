# MON three-host lab — safe PC2 access recovery

**Date:** 2026-10-23  
**Status:** Remote access failure reported; PC2's current power, Tailscale and SSH states have **not** been verified. Do not treat historical `HUB_GUARD_VERIFIED` or peer commits as proof of current availability.  
**Lab scope:** PC2 Ubuntu 26.04 (MON) `pc-2@100.75.116.62` via Tailscale, LAN `10.5.112.94`; PC5 `10.5.112.23`; PC6 `10.5.112.4`. College LAN is shared: no campus-wide firewall/router changes.

## Recovery safety boundary

**Goal:** regain management connectivity. **Not:** rebuild MON, rekey WireGuard, clear nftables, restart all machines, recreate PostgreSQL data or generate attack traffic. The PR #90 lab source is separate from the live site; GitHub status cannot establish current PC2 health.

PC5 and PC6 were reported to have committed their original peer migration to PC2 on 2026-10-10, and a real PC6→PC2 packet capture existed; PC6→PC5 packet forwarding remained unproven. The hub's `mon_three_guard` nftables table is **volatile**, and the hub `wg-quick@wg0` was **not enabled at boot**. After an intervening PC2 reboot, **never** start `wg0` alone before restoring and verifying the owned guard-first dependencies. Do not auto-run `hub-prepare` either: it intentionally refuses an existing `wg0.conf` or interface. Once management access is restored, handle hub reactivation as a separate reviewed change.

## 1 — Test from the operator's laptop

On **Windows PowerShell** if Tailscale is installed on Windows, use:

```powershell
tailscale status
tailscale ping 100.75.116.62
Test-NetConnection 100.75.116.62 -Port 22
ssh -o ConnectTimeout=10 pc-2@100.75.116.62
```

If the executable is not in PATH, use `& "$env:ProgramFiles\Tailscale\tailscale.exe" status` and `ping` instead. Do not assume that an Ubuntu/WSL instance can access a tailnet connected only to its Windows host; test SSH from Windows PowerShell first. A successful browser login or accessible dashboard proves some reachability but **not** that SSH/22 accepts connections.

**Interpretation:** Node offline in `tailscale status` → physical host, site LAN connectivity, or tailscaled/login status; node responds to `tailscale ping` but TCP/22 fails → SSH daemon/host filter/ACL, not a missing GitHub repo; SSH works from PowerShell but not WSL → Windows/WSL routing and host Tailscale interoperability, not a PC2 reinstall.

## 2 — Alternative access from an already authorized campus LAN host

At PC5's or PC6's local console (or existing SSH session inside the college LAN), use:

```bash
ssh -o ConnectTimeout=10 pc-2@10.5.112.94
```

This **does not** work from an ordinary off-campus Internet connection. If both the Tailscale and the college LAN paths fail, obtain physical PC2 console access to inspect power and networking. Do not try random ports, scan the campus subnet or bypass host-key verification.

## 3 — Check from the PHYSICAL PC2 console (read-only)

```bash
hostname
whoami
ip -br -4 addr
ip -4 route
systemctl is-active ssh tailscaled
systemctl is-enabled ssh tailscaled
sudo ss -ltnp '( sport = :22 )'
sudo tailscale ip -4
sudo tailscale status
sudo systemctl --no-pager --full status ssh tailscaled
sudo journalctl -u ssh -u tailscaled -n 35 --no-pager
```

Do **not** paste private keys, authentication URLs, machine-key material, JWTs or detailed sensitive logs into chat. If the host was disconnected for days, check power, cable, DHCP/LAN route and local `tailscaled` state instead of restarting MON containers.

## 4 — Minimal supervised service recovery, only at the PC2 local console

If `ssh` is stopped and its config passes validation:

```bash
sudo /usr/sbin/sshd -t && sudo systemctl start ssh
sudo systemctl is-active ssh
```

If `tailscaled` is stopped, start only that service:

```bash
sudo systemctl start tailscaled
sudo systemctl is-active tailscaled
sudo tailscale ip -4
```

If Tailscale shows **NeedsLogin** or its address is different, perform the Tailscale account/device reauthentication interactively and verify the expected device identity. Do not blindly use `tailscale up --reset`, delete node state or overwrite the inventory. If SSH service is healthy but port 22 is blocked, inspect host firewall policy **without flushing it**; do not expose PC2's MON API to the public Internet.

After either service is restored, repeat the laptop's `tailscale ping` and the strict SSH connection attempt. Keep the local console available until remote access is stable.

## 5 — Restore services incrementally after SSH is back

On PC2:

```bash
cd ~/mon-three-operator
git status --short
git branch --show-current
git rev-parse --short HEAD
sudo systemctl is-active wg-quick@wg0
sudo nft list table inet mon_three_guard
sudo wg show wg0 latest-handshakes
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
curl --max-time 5 -fsS http://127.0.0.1:8080/health
```

**Do not output `/etc/wireguard/wg0.conf`, `wg.key`, client cert private keys or `operator.jwt`.** Since the hub guard is volatile, any missing guard or downed `wg0` is a stop condition before sensor/attack tests. Never call `overlay` to overwrite committed peer configs; `hub-prepare` also rejects existing hub files. If the API is healthy, preserve PostgreSQL and JWT identity; check only the failing service. Once the working copy and local source are identified, an operator may explicitly fetch the feature branch, but a `git fetch` is **not** a PC2 access fix.

## Acceptance evidence

Record PC2 physical power/console available, Tailscale backend state/address, sshd state/listener, strict SSH success over Tailscale, LAN alternative if used, PC2 guard and wg0 state, API/console status and whether real sensor handshakes/events are current. Never label absent sensors as healthy; never auto-run a wide service reset as proof of recovery.
