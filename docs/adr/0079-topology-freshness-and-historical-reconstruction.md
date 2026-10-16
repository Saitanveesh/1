# ADR 0079 — Sensor freshness and time-scoped topology reconstruction

Status: Implemented in the MON development branch; campus deployment not verified
Date: 2026-10-15
Depends on: ADR 0076, ADR 0077, ADR 0078

## Reason

The live network map initially accumulated all known IP and MAC addresses of a
node. After an address changed or a source stopped reporting, an old address
could still be matched to a recent security finding as if it were current. This
could point the SOC operator at the wrong computer.

The graph also lacked an operator-readable distinction between what sensors had
recently observed and what historical reconstruction could actually prove.

## Contract

### 1. Address provenance is time-scoped

Each `TopologyNode` returns two distinct perspectives:
- `ip_addresses` and `mac_addresses`: **historical sightings** from the
  bounded observation window, never sufficient on their own for live incident
  matching;
- `active_ip_addresses` and `active_mac_addresses`: evidence whose
  `observed_at <= snapshot_at < observed_at + ttl_seconds` is still valid
  at the exact reconstruction instant.

The console's recent-finding markers use only `active_ip_addresses`, and
only when an address belongs to exactly one observed node in the returned graph.
If an observed source IP is missing or ambiguous, MON reports unresolved
matching; it does not infer person, device ownership, physical location, or
a complete attack path.

This still does not certify source identity: lease history, anti-spoofing,
network-port corroboration and a trusted sensor binding are separate
prerequisites to automatic physical-port isolation.

### 2. Explicit coverage and missing information

`TopologySnapshot.coverage` remains `UNKNOWN`, because counting recently
reported sensors does not prove visibility into all network segments.
`coverage_details` contains:
- seen, active and stale sensor counts based on source TTLs;
- observed/stale graph-node and link counts;
- unresolved node counts and last observation time;
- `complete_network_visibility = null` unless an independently audited
  expected inventory and segment instrumentation standard exists.

Never convert a failed, absent or expired sensor into a green system-health
value or 100% network coverage. The sensor count itself comes from
`sensor_id` asserted in observations through the current authenticated
ingest path; the claimed hardware identity is not yet attested to the
individual physical sensor.

### 3. Exact historical reconstruction

`GET /api/v1/topology?tenant_id=...&site_id=...&at=<RFC3339>` returns
a reconstructed graph for the specified timezone-aware past instant. The
durable store filters `observed_at <= at` **before** applying the bounded
10,000-observation query limit, so a historical query cannot be displaced
entirely by newer evidence. Responses indicate `truncated = true` when
the selected time-scope exceeds that bound.

The operator console offers a read-only local-date/time picker, a visible
historical-mode label and a return-to-live control. Historical mode does not
overlay present-day security findings as if they existed at that earlier time.
The snapshot is reconstructed from retained observations; this is not yet a
cryptographically sealed, independently archived snapshot of the entire
network or incident state at that time.

Future and timezone-naive timestamps are refused at the API boundary.
Tenant/site authorization remains mandatory for both live and historical views.

## Limitations / next dependency gates

- The current collector samples local neighbor cache and separately provided
  managed-switch exports; this does not prove full network discovery.
- A topology node's active addresses are *fresh observations*, not confirmed
  host identity, and TTL does not prove a host is still connected now.
- Current console incident markers are observed IP matches, not forensic
  reconstruction of a complete MITM/DDoS or network route.
- Real switch integration, sensor mTLS identity binding, bounded packet
  evidence, critical-asset enforcement certification and victim health remain
  separate implementation and physical-hardware acceptance tasks.
- Recovery/audit history exists elsewhere in MON, but the topology time picker
  does not yet couple directly to an incident's evidence timeline.
- Evidence retention is still bounded by the database and 10,000-row response
  limit; expiration/retention policies and archive/restore validation remain
  operational prerequisites.

## Regression gates

- Old IP no longer appears in live matching after its TTL expires, while
  historical views still show when it was observed.
- At a pre-change instant, the snapshot excludes observations from the future.
- One source can be stale while another is fresh, without claiming complete
  network coverage.
- Live finding matching rejects stale/ambiguous IPs.
- Store cutoff occurs before limit with the same behavior in in-memory and SQL.
- A future/naive `at` fails, and tenant/site results remain separated.
- CI runs topology-history regression, the full Python checks, console unit
  tests and TypeScript production build.

No campus telemetry, switch attachment or actual containment is claimed by
passing these software-only tests.
