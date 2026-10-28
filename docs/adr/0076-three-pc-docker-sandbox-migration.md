# ADR 0076: Staged Docker Compose migration for the three-PC MON lab

Status: Proposed — **no live deployment authorized by this ADR**.
Date: 2026-10-28.

## Verified context

PC-2 (WireGuard 10.77.0.1) hosts MON gateway, detection, console and existing Docker PostgreSQL container **mon-three-postgres**. PC-5 (10.77.0.50) runs the version-4 *fictional* training site on TCP/8085. PC-7 (10.77.0.70) runs the existing local attack console at 127.0.0.1:8766 with host service **mon-batch2-attack-console.service**. PC-7's attack-console files were located at `~/mon-batch2/lab/pc6-console/` and are not part of the inspected canonical branch. Existing network and narrow containment depend on PC-2's host WireGuard and nftables.

Observed failures: PC-5 pointed to an outdated physical LAN endpoint, PC-2's **mon-three-postgres** failed to restart and the snapshot API returned HTTP 500, and PC-7's attack console stopped listening. A browser JWT was renewed, but authentication alone did not restore a broken database. Docker alone cannot resolve all those failure modes.

## Decision

Use Docker Compose for repeatable application builds, dependency-aware startup, pinned versions, durable state and rollback. **Do not replace the actual host security boundary with containers.** Keep WireGuard, restricted nftables response and host-visible Suricata on PC-2 until an equivalent packet path is proved under namespace/VM tests. Keep the three physical machines as distinct trust and operational boundaries; Docker shares the host kernel.

Migrating a live lab is staged:

1. Preserve the working deployment, inspect Docker mounts and image digests, capture service units, test database/evidence backups, and freeze any shared-LAN target changes. Never recreate a missing database container under a guessed name. Ensure host service auto-start and physical LAN/WireGuard endpoint stability.
2. PC-2: migrate control-plane API, frontend, PostgreSQL and observability into a versioned Compose project with `service_healthy` dependencies, encrypted/separated credentials, hardened containers, healthchecks and **verified preservation** of the original database volume. Do not use generic development credentials or `docker compose down -v`.
3. PC-5: migrate the synthetic victim application and impact metadata journal side-by-side on a non-conflicting port, validate version-4 health, host-observable packets, persistence and rollback, then change the live listener only after acceptance. Never mount real university data into deliberately vulnerable exercises.
4. PC-7: first import, audit, test and version its existing attack console. Run separately from bounded training actors with restricted destinations, concurrency, request rate, duration, memory, CPU and PID counts. No `--privileged`, Docker socket, broad host mounts, host networking or `NET_ADMIN` granted to attack actors.
5. Many-to-many: 2+ attack actors and 2+ synthetic victim services may run as separate containers, but ordinary Docker source NAT may collapse all actor IPs to PC-7's 10.77.0.70, and same-host bridge traffic will bypass PC-2's `wg0` capture. Allocate nonoverlapping routed sandbox subnets with explicit WireGuard routes and nftables policies only after disposable VM/netns validation, or deploy a proven independent sensor with original workload identity. Never claim distinct attacker attribution without real evidence.
6. CI and live release gates: deterministic images, API/tenant-isolation tests, measured resource ceilings, untrusted traffic controls, restart/retry/partial-failure tests, real source/target packet visibility, human-approved TTL containment and rollback, truthful time-stamped evidence, backup/restore checks, and service recovery tests. Test in disposable VMs before cutover; don't use the shared physical LAN for high-volume DoS tests.

## Operational contract

After acceptance, a **future** `mon lab up|status|upgrade|backup|rollback` entry point will orchestrate all powered-on hosts over authenticated management transport. `up` must distinguish readiness from service-start success; `upgrade` backs up state, applies pinned images, validates health and reverts only affected services; `rollback` cannot erase incident evidence or authorized containment. Docker Compose is host-scoped by default; it does not power on PCs or automatically join their private networks.

Until migration, `tools/mon-three-lab-operator.sh` addresses only the **existing**, partially Dockerized lab with cautious startup/status and optional remote systemd checks. No database creation, VPN rekey, firewall flush or unreviewed attack launch is permitted. Monitor evidence retention and disclose unavailable coverage rather than inventing historical events.

## Consequences

Container namespaces/cgroups provide isolation against accidental process interference, **not** the stronger boundary of a VM for arbitrary untrusted exploit execution. An internal Compose network limits egress only if all network attachments and host firewall controls are also reviewed. Image rollout is separate from schema migration, signed identity renewal, DHCP endpoint management, and data backup. Avoid automatic attack execution on boot.