# MON Network Map — first implementation slice

Status: **implemented in branch for integration testing; not campus deployed or certified**
Date: 2026-10-15
ADR: [0078](adr/0078-evidence-backed-topology-and-network-distance.md)

## What this commit actually does

1. Adds immutable, site/tenant-scoped topology observations with evidence IDs, sensor identity, timestamps, TTL, validated IPv4/IPv6 and MACs, and strictly typed relationships.
2. Adds PostgreSQL append-only observation persistence and Alembic migration `0013_topology_observations` with forced tenant/site RLS. It does not destroy/overwrite prior observations. SQLite/in-memory variants support tests.
3. Adds `POST /api/v1/topology/observations` (requires `INGEST` permission) and `GET /api/v1/topology?tenant_id=...&site_id=...&root_node_id=...` (requires `VIEW` permission). Ingestion is bounded to 250 observations per batch; conflicting observation IDs return 409; scope mismatch returns 422; RLS protects PostgreSQL rows under a non-bypass runtime DB role.
4. Adds an operator **Network Map** with node search, separate L2/L3/communications links, selectable network root, LLDP-observed hop depths, click-to-inspect provenance, staleness, and honest unknown links/distances. WebSocket topology updates trigger refresh via the existing live-sequence state; periodic refresh handles expiry.
5. Adds **passive Linux kernel-neighbor ingestion**. This observes only neighbors known on one host, never probes unknown devices and never claims that an IP or MAC means a verified physical system.
6. Adds regression tests for validation, stale hops, no physical links from flows, scope isolation, idempotence and persisted query API.

## Running the first slice on a disposable lab instance

Run migrations with repository dependencies and a dedicated application account with RLS:

```bash
python -m pip install -e '.[dev]'
alembic upgrade head
```

Run the MON control plane by the already documented dev/test service procedure. Use a valid site-scoped bearer token. On a **Linux host authorized to observe its own kernel neighbor cache**, run:

```bash
mon-topology-neighbors --tenant-id demo --site-id lab --sensor-id neighbor-pc1
```

This prints an authenticated-ingest-shaped JSON batch; it **does not send** anything without the operator choosing `--ingest-url`. A node appears only if that host's neighbor table actually contains a valid resolved address and MAC. No special root is assumed.

To submit over authenticated HTTPS:

```bash
export MON_TOPOLOGY_TOKEN='<short-lived-authorized-ingest-token>'
mon-topology-neighbors --tenant-id demo --site-id lab \
  --sensor-id neighbor-pc1 --ingest-url https://mon.example.edu
unset MON_TOPOLOGY_TOKEN
```

**Do not use the example hostname or token as real values.** The authentication issuer, certificates and site IDs must match the actual MON installation. No bypass of TLS or RLS should be introduced to make a demo work. Host-only HTTP is permitted by the CLI only for loopback development.

Open the existing operator console, select **Network Map**, and filter by observed IP/MAC. If you have only the kernel neighbor collector, the map will show isolated observed IP neighbor nodes, **not fabricated physical cables**. Distances will correctly be Unknown until switch LLDP evidence is ingested.

## Collector contract for next milestone

The next safe adapters to implement after a switch/capability inventory:
- read-only SNMPv3 or vendor API exports: LLDP neighbor endpoints and freshness;
- read-only switch FDB learned MAC/interface/VLAN bindings: depict *learned attachment*, not verified cable;
- DHCP lease and timestamp correlation: do not treat current lease as historical proof;
- optional limited endpoint agent identity, only for authorized systems;
- switch-port and VLAN coverage, topology-port join, root selection, deduplication and asset identities.

For a typed LLDP link, collectors submit a `TopologyObservation` with `kind=LINK`, `node_id` and `peer_node_id`, `layer=L2` and `relationship=LLDP_NEIGHBOR`, actual observation timestamp, sensor and evidence ID. For traffic-only observation the layer is `COMMUNICATION` and relationship `FLOW_OBSERVED`: the graph will not convert it into an LLDP hop.

## Honest limitations / open engineering work

- The first collector reads only Linux's *existing neighbor cache*. It cannot enumerate all campus devices, discover remote switches or locate physical ports. It doesn't run continuously or buffer failed posts yet.
- The source/sensor label is currently site-scoped API-authenticated, not cryptographically bound to a specific topology collector identity. Add collector-scoped identity enrollment and origin-signing before trusting switch claims for enforcement decisions.
- The UI currently draws up to 160 nodes per scene, shows the true matching count and flags partial view; build virtualized clusters/pagination and high-density graph rendering before calling it a whole-campus explorer.
- The snapshot GET reads the most recent 10,000 immutable observations and explicitly declares truncation. Replace with indexed current materialization and paged historical snapshots to support long-term telemetry at campus scale.
- Topology-specific collection coverage records, direct endpoint-victim health, switch port enforcement, packet capture retention and automated threat-to-topology correlation are next slices.
- The in-process WebSocket fan-out is not a cross-replica broker; topology refresh is near-real-time, with honest stale/error states rather than guaranteed millisecond rendering.
- RLS and history exist, but operational backup/restore and retention limits still need rollout tests.
- Security actions must **not** infer control of a host from these observations. No auto switch-port shutdown/response is linked to this new graph yet.
- No real college-network data, hostnames, port inventories or performance metrics were invented or seeded.

## Acceptance gates for this slice

- `ruff check .` and `pytest -q tests/test_topology.py tests/test_topology_neighbor_collector.py`
- `npm run build` and `npm test` in console
- `alembic upgrade head` against PostgreSQL (non-bypass runtime role) and application integration tests
- upload actual authorized neighbor readings and verify displayed source, TTL, scope and evidence; repeat with updated neighbors and confirm graph changes.
- failure must display stale/unavailable, not fabricated healthy data.

The four-PC deployed demo and larger network-discovery capability remain separate acceptance milestones. Earlier seven-PC documentation is a legacy regression fixture, not the new deployment shape.
