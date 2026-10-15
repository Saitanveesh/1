# Read-only MON topology inventory collector

Status: implemented first adapter and transport; physical switch integration not certified.

This collector reuses MON's existing PostgreSQL-backed, tenant/site-scoped
`/api/v1/topology/observations` ingestion and `/api/v1/topology` retrieval.
It **does not scan the campus**, infer physical location, reconfigure a switch,
control the red team, or claim that all physically connected devices are visible.

## Inputs supported

1. `linux-neighbors`: reads `ip -j neigh show` without privileged flags or
   active probing. The strict adapter accepts only NUD REACHABLE entries with
   valid IP/MAC and records unverified IP neighbor nodes, **not cable links**.
   Linux may retain or omit neighbor-cache entries; this is not a live device census.
2. `switch-export`: imports a normalized, timestamped, **read-only** snapshot
   obtained separately from an authorized managed switch. MAC forwarding
   observations become FDB edges, not verified physical hops. LLDP neighbor
   observations become LLDP edges, and their credibility depends on trusted
   device management and actual neighboring devices. The exporter must never
   invent absent MACs/LLDP neighbors.

The normalized exporter contract is **not** a raw SNMP response format.
A vendor-specific, least-privilege SNMPv3/REST/NETCONF poller remains a
separate hardware-dependent task. Operators must first verify switch support,
uplinks, visibility, credentials, and institutional approval.

## Prerequisites

- Install the same MON checkout across services: `python -m pip install -e .`.
- Configure the MON API with an actual authenticated `INGEST` principal scoped
  to the intended tenant/site. Use a controlled principal and HTTPS.
- Store its bearer token as a dedicated regular file accessible only to the
  collector account. Do not commit the token or store it in a command argument.
- Configure the normal MON PostgreSQL backend and migrations, including
  `0013_topology_observations`, before enabling ingestion.
- Keep time synchronized. Read-only polling has finite TTL and timestamps.
- **Do not** run LLDP or forwarding-table commands with write privileges.

### View Linux neighbor evidence offline first

```bash
mon-topology-collect \
  --source linux-neighbors \
  --tenant-id YOUR_TENANT \
  --site-id YOUR_SITE \
  --sensor-id local-neighbors
```

The output contains **actual kernel neighbor-cache data only**. An empty
observation list is a valid result and is not evidence of zero connected hosts.

### Upload Linux neighbor evidence to the MON control plane

```bash
umask 077
# Place the already-issued, tenant/site-scoped bearer token in /etc/mon/topology.token
# using approved secret provisioning; do not paste secrets into shell history.
chmod 600 /etc/mon/topology.token
mon-topology-collect \
  --source linux-neighbors \
  --tenant-id YOUR_TENANT \
  --site-id YOUR_SITE \
  --sensor-id local-neighbors \
  --api-url https://YOUR_MON_API_HOST \
  --token-file /etc/mon/topology.token
```

This command performs **one** observation pass and exits. The operator may
later schedule the command using a low-rate systemd timer after reviewing its
load, privacy, and failure behavior. It has no hidden background daemon.
Unencrypted HTTP is refused unless `--allow-local-http` is explicitly set
and the destination is loopback; redirects are disabled to protect tokens.

### Import a switch's normalized read-only export

Example **format only** (not a real discovered network, not campus data):

```json
{
  "switch_id": "example-distribution-switch",
  "collected_at": "2026-10-15T12:00:00+00:00",
  "ttl_seconds": 120,
  "ports": [
    {
      "name": "example-ethernet1",
      "learned_macs": [
        { "mac": "02:11:22:33:44:55", "vlan": 101 }
      ]
    }
  ],
  "lldp_neighbors": [
    {
      "local_port": "example-uplink",
      "remote_node_id": "example-access-switch"
    }
  ]
}
```

Save a **real** normalized export outside source control to a protected path,
then preview or upload:

```bash
mon-topology-collect \
  --source switch-export --switch-file /path/to/observed-switch.json \
  --tenant-id YOUR_TENANT --site-id YOUR_SITE --sensor-id switch-exporter
```

Add `--api-url https://YOUR_MON_API_HOST --token-file /etc/mon/topology.token`
to upload. The collector posts up to 250 observations per authenticated
batch, with a 10-second request timeout. Each batch is idempotent within the
provided collection timestamp, and the PostgreSQL store retains the source
evidence. Partial multi-batch success is possible: on failure, preserve the
original snapshot/timestamp and retry instead of altering evidence.

## Operator and security interpretation

- Network nodes are **observed records**, not independently verified machines.
  One device may have multiple interfaces, or one address may be reassigned.
- FDB learning means a MAC was learned on a switch interface; the interface may
  be an uplink, AP, bridge, or a hypervisor. It is not a verified endpoint port
  or physical location.
- Only current LLDP adjacency contributes to the UI's observed LLDP hop depth.
  LLDP itself is not cryptographically authenticated; treat untrusted or
  contradictory LLDP as insufficient for disruptive enforcement.
- One switch export cannot cover the rest of the network. The topology response
  deliberately reports `coverage: UNKNOWN`. Counts are observations, not
  total inventory or complete segment visibility.
- A normal campus asset must never be attacked because it appears on the map.
  Intentional MITM/load tests still require the authorized isolated range.
- The bearer token is an API identity, **not** proof that the source's asserted
  `sensor_id` or `switch_id` is cryptographically bound to a real switch.
  Do not use this observation stream as sufficient authorization for a
  switch-port block. A hardware-bound collector identity is still required.

## Validation gates

```bash
pytest -q tests/test_topology.py tests/test_network_topology.py \
  tests/test_topology_inventory.py tests/test_topology_neighbor_collector.py
ruff check src/mon/topology_inventory.py src/mon/topology_inventory_cli.py \
  tests/test_topology_inventory.py
```

Until a real managed switch and capture path are configured and tested,
**campus-wide discovery, physical source attribution, and coverage remain
unverified.** Do not replace missing observations with demonstration data.
