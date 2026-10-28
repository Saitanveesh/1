# MON three-PC lab: current recovery versus future Docker migration

**As of 2026-10-28:** the current lab is working but is **not** fully Dockerized. Never run the repository's generic development `compose.yaml` on the live machines. Do not execute `docker compose down -v` or recreate the existing database.

## Preserve current working services before leaving

**PC-2** (`pc-2@lab-pc2`):
```bash
sudo systemctl enable docker wg-quick@wg0.service \
  mon-three-lab-portal.service mon-three-console-v2.service \
  mon-suricata-passive.service mon-stage4-gate.service
sudo docker update --restart unless-stopped mon-three-postgres
sudo docker inspect mon-three-postgres --format '{{.Name}} {{.Image}} {{json .Mounts}}'
```

**PC-5** (`pc-5@lab-pc5`):
```bash
sudo systemctl enable wg-quick@wg0.service mon-training-site.service
```

**PC-7** (`pc-7@lab-pc7`):
```bash
sudo systemctl enable wg-quick@wg0.service mon-batch2-attack-console.service
```

These enable startup of existing services, not backups or a complete migration. **Check verified backups before database changes.** The historical PC-5 WireGuard endpoint must also be stabilized; Docker cannot fix stale DHCP peer endpoints. The control-plane API process on PC-2 port 8080 has not yet been mapped to a verified boot unit, so it must be audited before claiming fully unattended startup.

## Existing-PC startup helper on PC-2

From the branch containing this runbook:

```bash
bash tools/mon-three-lab-operator.sh arm-reboot
bash tools/mon-three-lab-operator.sh status
bash tools/mon-three-lab-operator.sh up
```

`up` starts only the **existing** PC-2 PostgreSQL container and installed local units, then checks real health endpoints. It will not replace data, generate secrets, alter peers, simulate telemetry, or silently claim the other PCs are ready. For cross-PC `up --remote` or `status --remote`, first set up trusted key-based SSH and narrowly scoped noninteractive sudo for PC-5/PC-7's known units; otherwise use the above local `systemctl` commands on those machines. Do not grant unrestricted passwordless sudo.

## Desired final component placement

| PC | Future Compose-managed | Host-managed until demonstrated safe |
| --- | --- | --- |
| PC-2 — Blue Team | PostgreSQL, API, console, observability, event services | WireGuard hub, scoped nftables, Suricata capture |
| PC-5 — Victims | Multiple synthetic victim sites, persistent impact journals | WireGuard and endpoint collector |
| PC-7 — Red Team | Reviewed attack console, bounded synthetic actors | WireGuard and tightly restricted actor egress |

## Many-to-many limitations

More containers does **not** automatically mean independent visible attackers. Container bridge NAT may collapse identity to one PC-7 overlay address, and same-PC traffic may bypass the `wg0` monitored path. Before showcasing a true many-to-many attack graph, verify each source/target pair, route, evidence trail, permitted destination, and rollback. Training traffic must target only invented data/services; impose low rate and resource ceilings; never transmit volumetric tests on the shared LAN.

## Upgrade workflow after actual Compose migration

1. Freeze and record running image digests, Docker mounts, live service definitions, configuration and schema revision; back up database, evidence and credentials; verify restoration offline.
2. Build and test changed images from the canonical GitHub release branch on disposable VMs.
3. Run Compose healthchecks and real API/packet-path tests with isolated staging project names/ports.
4. Upgrade one host/role at a time with pinned images and preserved volumes; validate tenant/site scope, identity, IDS evidence, containment TTL, rollback and recovery.
5. Retire old systemd services **only** after side-by-side cross-host acceptance; keep explicit rollback artifacts.

The final one-command fleet launcher and Docker images are **not yet implemented or deployed**. This operator helper is a safe interim recovery tool, not a claim that MON is already sandboxed.