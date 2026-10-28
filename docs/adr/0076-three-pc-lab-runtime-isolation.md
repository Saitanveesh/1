# ADR 0076: Three-PC lab restart and sandbox boundaries

Status: Proposed (operator-site verification and VM restore rehearsal required)

Date: 2026-10-28

## Context

The working MON three-PC lab has experienced restart-specific failures: a PC-5 WireGuard peer pointed at an obsolete PC-2 LAN address, PC-2's PostgreSQL container `mon-three-postgres` stayed stopped after a reboot and caused HTTP 500, the existing operator JWT expired, and the PC-7 training web console at `127.0.0.1:8766` did not have an active listener until its local service was restarted. The security operator needs repeatable daily startup and isolated upgrades without turning disposable demonstration software into a single-host security bypass.

## Decision

Use the **existing Ubuntu VM per role as the sandbox/recovery boundary**; prefer named, encrypted VM checkpoints and rehearsed restores. Maintain the existing database container and controlled application containers, but keep WireGuard, Suricata raw packet capture, and nftables enforcement on their current privileged host boundary. Introduce a versioned, role-specific lab operations script that (a) performs **read-only** health checking by default, (b) starts installed, known-good components but does not create or replace them, (c) opts into boot service enablement separately, (d) backs up the existing PostgreSQL database into a restricted local file with archive verification, and (e) optionally orchestrates remote startup over already-working SSH/WireGuard links. Unknown or stale stacks are never automatically revived.

Automatic detection and logging may operate unattended, but **attack generation, forceful containment, privileged upgrades, operator-token renewal, and snapshots are not automatic**. Enforcement requires explicit evidence, policy authorization, TTL, audit, blast-radius assessment, rollback and recovery verification. The script must never alter peer keys, network routes or address assignment; it must not flush firewall rules, recreate DB containers or synthesize healthy sensor values.

CI must run Bash syntax and isolated mock-based safety tests before promoting an exact git revision. The deployment remains unverified on the live three-PC environment until a user performs the documented startup and reboot gates. The currently unknown supervision of the PC-2 `uvicorn` listener is recorded as a gap: health is checked, but a new service manager definition must not be invented without observing the running environment and dependencies.

## Consequences

- **Benefit:** A consistent operator command across nodes, safe DB restoration on PC-2, precise failure reporting, stable rollback, fewer fragile manual steps, and no one-firewall/container vendor lock-in.
- **Cost:** Three host VMs and one management gateway still need to be powered on; remote `start-all` depends on SSH access and already-booted WireGuard peers. VM checkpoints consume storage and contain privileged secrets; they must remain encrypted and access controlled.
- **Risk remaining:** No demonstrated off-site backup restore, no stable DHCP reservation for the PC-2 endpoint, no known boot supervisor for PC-2's port 8080 process, finite IDS retention, and possible JWT expiry. Status probes cannot substitute for end-to-end security/recovery acceptance tests.

See `docs/MON_THREE_LAB_OPERATIONS.md` and `tools/mon-three-labctl.sh`.
