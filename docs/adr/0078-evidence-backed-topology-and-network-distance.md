# ADR 0078: Evidence-backed whole-network topology, discovery and distance

Status: Accepted as design direction; hardware support and implementation not verified
Date: 2026-10-15
Related: ADR 0076 (dynamic multi-lab attribution), ADR 0077 (four-computer SOC consolidation)
Supersedes: any lab-count or lab-membership-driven network map mockup

## Why this exists

The campus contains an **unknown and changing set of networked devices**. The historical example of five labs with approximately 25 PCs per lab is merely context. It is not a cardinality limit, discovery seed, reliable location source or UI grouping requirement. Other networked equipment, access points, student-managed/authorized devices, hypervisor guests, switches, printers, cameras and infrastructure may also exist.

The primary MON map must be a dynamically constructed **network graph with provenance**, not an illustrative set of labelled Lab A/B/C boxes and counts. It must establish how each observed device relates to the instrumented network, and show the evidence, time and uncertainty behind every claimed link or path.

## Decision

### 1. Inventory is open-ended, not hard-coded

No static number of nodes, lab bins, fixed IP ranges, attacker aliases, victim aliases or campus-specific port mapping in the runtime data model. The same engine handles dozens to thousands of potential assets, limited only by measured capacity and authorized coverage. Imported lab/room/seat metadata is optional enrichment attached *only when verified*. A device whose physical room cannot be proven must display **Location unknown**, not an inferred lab.

Inventory states are independently tracked: **observed recently**, **known from inventory but currently not observed**, **stale**, and **unresolved**. "Not seen" is not the same as "not connected." DHCP leases, observed MACs and active responders are not automatically one-to-one with physical devices; identity de-duplication is evidence-backed, time-scoped and supports changing IPs, multiple NICs, randomized MACs, NAT and virtual interfaces.

### 2. Multi-source discovery with a visible coverage frontier

Primary evidence adapters where authorized and available:

- managed switch/controller interface and MAC-forwarding/FDB tables, port/VLAN configuration, LLDP/CDP neighbor data, link/interface state, SNMPv3 or vendor APIs;
- router/interface inventories, connected routes and ARP/ND neighbors;
- DHCP allocation and history, DNS records, 802.1X/RADIUS/NAC binding histories;
- Wi-Fi controller association/BSSID/client data and AP uplinks;
- hypervisor/virtual-switch inventory and VM-to-vNIC relations;
- SPAN/TAP packet/flow metadata (Suricata/Zeek, IPFIX/sFlow/NetFlow as supported);
- registered endpoint agents, authenticated host inventory and optional low-impact **explicitly approved** probes.

No single feed is complete. MAC tables age out, wireless clients roam, silent/offline/firewalled devices cannot be guaranteed visible, inter-VLAN paths are segmented, and SPAN from one switch does not show unmirrored same-switch or other-switch east-west traffic.

Track per-source last_success, polling period, observed interfaces/VLANs, collection privileges, stale-after TTL, packet/sample/drop conditions where available, clock skew and known blind spots. **Never declare full coverage without an independently established expected inventory and visibility proof.** If inventory cardinality is unknown, present "N currently observed; total unknown" rather than "N of N devices discovered."

### 3. Separate topology layers; do not invent physical links

Maintain distinct, cross-referenced graphs:
- **Physical/L2 connectivity graph:** switch, router, bridge, port, AP, host interface and learned adjacency; port-specific where supported.
- **L3 routing graph:** routed prefixes, next hops and hop evidence; traceroute hop observations are not physical adjacency, and ICMP probes may be blocked/asymmetric.
- **Communication graph:** observed source/destination connections and flow direction in a time window; a flow edge is **not** a direct physical cable.
- **Service/dependency graph:** instrumented application-to-service/database dependencies; observations vs configured architecture clearly labelled.
- **Enforcement/coverage graph:** which segment and traffic direction a given sensor can observe and which verified enforcement controls can actually affect the observed path.

Use RFC 8345's graph concepts of nodes, links and termination points (including layered overlays) as a design reference, without treating it as proof of discovered data. Persist evidence IDs and derived-from relations per edge, with lifecycle timestamps and certainty category **observed / corroborated / inferred / unknown**.

A device cannot be placed on a particular switch port solely from its IP, a ping, traceroute output or a single MAC claim. Contradictory sources are preserved and flagged instead of overwritten.

### 4. "Distance from MON" must be defined and honestly computed

The SOC host is **an observer/controller, not necessarily a transit switch or the packet-path root**. The map may place the MON observer visually in the center for navigation, but should not draw fictitious direct MON-to-device cables.

Support selectable roots:
- **Monitoring perspective:** central MON node connected with visibly styled *observation/control* relationships; network-path distance is **not calculated** across these virtual observation edges.
- **Network-topology perspective:** choose the verified core/distribution switch, router or any known device as graph root and compute L2 *verified link hop count* using shortest path over applicable physical/logical graph edges.
- **Routed perspective:** separately show measured/observed L3 hop-count and round-trip-time metrics (ms) with timestamps, explicitly not equated with switch-hop count or metres.
- **Physical location:** metres or a building map **only if** surveyed geographic/floorplan coordinates are authorized and known; never infer metres from hop count or RTT.

Nodes unreachable in an evidence-backed graph show **Distance unknown** (not a guessed outer ring). Topology loops, redundant links, link aggregation, VLAN and VRF scope, WLAN stations behind APs, firewalls and tunnels must not be reduced to an invented single cable route. Show alternatives and timestamped best-known paths when appropriate.

### 5. Realtime user experience (no fixed Lab A/B/C tiles)

Initial view:
- A bounded **graph overview** rooted at the selected switch/router or MON observation perspective, with a live total of *observed devices* and coverage/last-updated information;
- interaction to zoom/pan, expand groups, search by observed device identity/IP/MAC, filter device type/VLAN/segment/health/threat, and toggle physical/L2, routed/L3, communications and dependency layers;
- optional grouping by **discovered adjacency, VLAN/segment, device role or connected component**, not assumed laboratory membership;
- for large graphs cluster, lazy-load, sample render and virtualize labels rather than drawing an unreadable hairball;
- each node click displays source of observation, first/last-seen, addresses, location only if verified, attachment port if proven, distance type/value/time or unknown, observed flows, events, service health level and response capabilities;
- each link click shows endpoints and interface evidence, current/stale status, confidence and whether physical, routed, flow, service, or observation relation;
- incidents highlight both observed attacker and victim plus confirmed/inferred path. Unknown hops remain dashed and explicitly labelled, never animated as facts.

Display latency uses measured transport performance; source timestamp precision is preserved if provided but **no every-millisecond refresh or complete instant topology guarantee**.

### 6. Persistence, scale and API design

Use the existing typed, tenant/site-scoped MON backend and PostgreSQL durability before adding any new graph database:
- `ObservedAsset`: stable scoped ID, observed properties, asset type candidates, first_seen, last_seen, state, source evidence, confidence and TTL.
- `InterfaceObservation`: node ID, MAC(s), IP(s), observed VLAN/VRF, role, source, valid_from/valid_until.
- `TopologyNode` and `TopologyEdge`: graph layer, endpoints, termination points/ports, evidence IDs, timestamps, derived status and confidence.
- `SensorCoverage`: collector, reachable/observed domain, directions and gaps, freshness and telemetry quality.
- `TopologySnapshot`: immutable version/time reference used to reconstruct a historical attack path.
- `NetworkDistance`: root node, layer, algorithm, derived hop count or measured RTT, computed_at, path edge IDs, and **unknown reason** where not resolvable.

Persist binding/evidence transitions and graph snapshot references sufficient for historical reconstruction; avoid losing old source/port mappings as leases move. Expose paginated typed APIs for nodes/edges/coverage/snapshots and incremental authenticated push events to all SOC screens. Keep analysis and storage scale objectives benchmark-driven.

### 7. Containment implications

Source-to-switch-port evidence can be wrong, stale or ambiguous. A proposed action against a physical switch port is blocked by default until binding confidence, last-seen, tenant/site scope, port ownership (not an uplink/trunk/AP), endpoint criticality, expected blast radius, independent verification and rollback are evaluated. If attachment cannot be established, prefer a less disruptive approved L3/host action or alert-only.

All intentional attack exercises remain in isolated, preauthorized range networks; network-wide discovery does not authorize network-wide attacks.

## Acceptance criteria

1. Start with no fixed device count and observe discovery from actual network inventory feeds; newly visible and removed devices change the graph automatically.
2. Validate mismatched DHCP/ARP/FDB data, aging, MAC relocation, virtualization and a physically unlocatable endpoint; do not assign a false lab/port.
3. Demonstrate that two different topology layers give different graph edges/hop meanings; MON observation edges are not transit connections.
4. Display verified hop counts for proven paths and **Unknown** for unproven paths, including under partial sensor failure.
5. With live events, dynamically highlight a previously unselected source and affected victim, and link every asserted path segment to evidence.
6. Demonstrate performance via measured p50/p95 display latencies and graph rendering benchmarks at at least 125 **synthetic asset graph records**, alongside a separately validated physical-inventory pilot. Synthetic scale tests must never be presented as discovered campus devices.
7. Prove tenant/site access isolation, sensitive inventory redaction, graph-history retention, audit and safe rollback on wrong-port/uncertain-identity cases.

## Standard reference

- RFC 8345, *A YANG Data Model for Network Topologies*: https://www.rfc-editor.org/rfc/rfc8345
