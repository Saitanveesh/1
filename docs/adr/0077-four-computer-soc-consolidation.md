# ADR 0077: Consolidated MON SOC with runtime-selected attacker and victim

Status: Accepted as target architecture; implementation not yet demonstrated
Date: 2026-10-15
Supersedes: the seven-dedicated-physical-computer requirement for new demo deployments
Complements: ADR 0076 on network-wide attribution, observation and isolated exercises

## Scope and intent

Use **at most four dedicated physical lab computers** to operate the MON cyber-range demonstration; existing network switches and the institution's computers are assets to be discovered, not MON server roles that must each be dedicated to a single purpose. A four-computer consolidation does not imply one sensor or one mirror port can see all segments. Additional virtual sensors, switch exports, endpoint collectors and approved network instrumentation may be necessary; capacity and coverage must be tested.

The primary device graph must be derived from observed network adjacency, independent of lab labels, and have layer-specific verified hop counts and an honest distance-unknown state, per [ADR 0078](0078-evidence-backed-topology-and-network-distance.md). No attacker or victim identity is preselected in MON's detection/attribution schema. For initial acceptance, a red-team exercise launcher and disposable victim workload can live on two named computers, but their addresses must be runtime-discovered. Authorized alternatives among monitored network hosts or VMs may assume those roles during later exercises without code changes.

## Resource footprint: roles are NOT assigned to physical PC numbers

**The previous PC3=attacker and PC4=victim mappings are withdrawn.** A
workload may run on **any explicitly authorized, enrolled and instrumented**
host/VM in the isolated exercise network. Attacker and victim selections are
runtime roles, not source-code constants, physical labels or known IP addresses.
This also applies if a visitor chooses a different enrolled workload before a
scenario. The SOC's source/target claims still require observed flow/host
evidence, not the exercise plan's assertion.

A minimal demonstration may use **one consolidated MON server** and an
arbitrary number of enrolled disposable workloads, colocated in VMs or
spread across machines. A blue-team console is any authenticated browser,
not a mandatory dedicated PC. Four physical computers are an optional
**capacity ceiling for the initial demonstration**, not a requirement and
not a topology model.

| Runtime role | Can run where? | Safety boundary |
| --- | --- | --- |
| MON controller / evidence store | Prefer one controlled workstation/VM with PostgreSQL and sensors | Traffic from other switches requires real SPAN/flow/agent feeds |
| Blue-team console | Any authenticated workstation/browser | Identity, RBAC, audit |
| Exercise source(s) | Any authorized participant namespace/VM; multiple separate sources for bounded multi-origin testing | Hardware-enforced isolated test fabric |
| Instrumented victim(s) | Any enrolled disposable PC/VM running synthetic workload and health agent | No ordinary campus devices or production ERP |
| Optional sensors / enforcers | Hosts/ports that actually observe/control the tested path | Confirm the control lies on the real forwarding path |

The `deploy/four-pc/` directory is retained for compatibility but its
name is **historical**. Its ERP Compose manifest is now **host-agnostic**.
Unknown and uninstrumented campus devices remain graph nodes when observed,
not automatically eligible destructive exercise targets. Enrolling a station
requires proof of physical isolation and the planned service/monitor route.


## Dynamic network inventory and live map

A map is not an unqualified claim of 'every device' simply because a scan completes. Combine, where authorized:
- DHCP lease history, DNS inventory, ARP/neighbor and route records;
- SNMPv3/REST/NETCONF or approved switch exports for bridge/MAC forwarding table, VLAN, switch port, LLDP and interface health;
- sampled flow records and/or SPAN/TAP network telemetry;
- optional endpoint identity/process/system-health agent observations;
- low-impact scoped discovery probes at safe cadence, not on sensitive hosts by default.

Maintain `asset_id`, observed IP/MAC/VLAN, switch+port, site/lab physical mapping, first_seen/last_seen, source, freshness expiry, confidence and identity evidence. Display observed endpoints, expected-but-unobserved inventory and blind spots separately. A shutdown, firewalled, wireless-roaming, virtualized or unmanaged endpoint may not have enough evidence for physical attribution. Never label the source/target as a verified person if only an IP appears.

The user-facing default must be one dynamic network graph with optional verified location properties, not lab-count cards. It must support verifiable L2/L3 distance and unknown paths, zoom/pan/search and graph clustering driven by observed connectivity. The inventory must support join/leave, DHCP reassignments, multiple IPs, MAC move, virtualization, NAT, L2 trunk and wireless AP exceptions. Do not assume packet path from visual topology alone; label inferred vs directly observed hops.

## Backend ownership and storage

Reuse the existing PostgreSQL schema/migrations, tenant/site RLS, durable site state, identity, audit and response receipts; do not falsely describe the current project as lacking a backend. Add the missing **operational data retention and retrieval contracts**:

1. PostgreSQL: durable asset history, topology binding history, incidents/findings, exercise authorization, enforcement actions and acknowledgements, audit trails, artifact manifests and relevant normalized event indexes.
2. Metrics backend: time-stamped victim CPU, memory, process, interface and service telemetry when consented/installed; separate independently measured HTTP/TCP/DNS availability and response latency; Prometheus-compatible collection initially, with recording/retention tuned by measurements.
3. Evidence archive: encrypted storage for selectively retained raw Zeek/Suricata events, logs and **bounded opt-in PCAP** with SHA-256 and provenance metadata in PostgreSQL. Avoid bulk indefinite packet capture or student personal data, set retention/quotas and access restrictions.
4. ClickHouse/OpenSearch only after an ingest/search benchmark justifies adding them. Do not run three databases by default on a single host for a 125-endpoint pilot.
5. Scheduled verified DB backup, snapshot/evidence retention, restore exercise, clock synchronization, encryption and disk capacity alarms. Disk full, stale sensor and broken backups show DEGRADED, not HEALTHY.

Provide historical incident retrieval, search by asset/time/exercise ID, timeline reconstruction with evidence IDs, response rollback and independent post-action health. Choose a recorded p95 query target after benchmarking rather than assuming capacity.

## Dynamic victim health and service dependency map

An arbitrary **authorized** network endpoint can become an observed potential victim. Available health tiers:
- T0 external observations: reachability, HTTP/TCP response code, response time and error rate from approved probes; no host CPU/RAM.
- T1 installed endpoint telemetry: OS health including CPU/RAM/network/process and authentication/security events with authenticated provenance.
- T2 instrumented application: application transactions, DB connection availability, request latency and request-to-DB dependencies using application logs/traces, with personally identifiable data redacted.

State each tier explicitly. Never fill an unavailable metric with zero or a guessed value. Keep collection scopes and privacy controls appropriate to institutional systems.

The flagship demonstrator should be **synthetic university ERP**: a purpose-built front-end, API/service and database with generated fictitious student records in isolated disposable VMs/containers. Model Engineer Workstation -> ERP app -> Database as verified service dependencies. No testing against real campus ERP, student data, login credentials, attendance, grading or production services without a separate institutional authorization and assessment plan.

## Real-time wall and operator workflow

One backend event stream, correlated by evidence/incident/exercise IDs, drives six panes (using the school's HDMI matrix/decoder without six server PCs):
1. Network map and its coverage/freshness;
2. Live suspicious activity and directly observed/inferred path;
3. Victim service and host health;
4. Red-team approved exercise state (including STOP);
5. Blue-team investigation and reversible action;
6. Historical reconstruction/recovery timeline and audit.

Default visitor language is plain English; analyst click-through reveals sensor records and confidence. Historical and synthetic displays must be clearly labeled and never silently overlaid on live events. Preserve source millisecond timestamps when supplied, report measured end-to-end latency and stale flags; no every-millisecond rendering guarantee.

## Safety and enforcement

Normal campus monitoring is passive/permissioned and never implies attacking any discovered device. Intentional MITM, flooding, password tests or degradation occur only on designated participant VMs, isolated exercise VLANs or air-gapped test fabrics; the selected physical red-team station may change but traffic stays constrained to the authorized exercise subnet through independently enforced switch/VM controls. No forwarding/bridging to the main college LAN.

Use confirmed path-appropriate controls: approved switch/NAC for same-L2 where available, endpoint protection when enrolled, router/firewall for traversed L3, upstream only where contracted. Require evidence, confidence, blast radius, actor, policy approval, TTL, verification, audit and rollback. No single weak sensor may permanently isolate a critical asset.

## Acceptance gates

1. Boot the four physical PCs and container/VM workload; verify services, persistent storage and durable health/restart behavior. Record resource utilization and data loss.
2. Across at least two authorized exercise source hosts/VMs, dynamically identify source and victim without editing MON source code or fixed-IP attacker labels.
3. Enumerate observed devices from available DHCP/switch sources and show at least one intentionally unobservable endpoint as unknown, not absent/healthy. Validate move/renewal/TTL.
4. Independently verify two data feeds: actual network evidence and victim-side host/app or service-probe metrics.
5. Exercise one bounded attack: normal service -> degradation/detection -> source attribution -> policy/approval -> real effective block -> restored service -> rollback -> audit replay.
6. Rehearse source reassignment and victim reassignment, including a target without an endpoint agent, and show the appropriate T0/T1/T2 data limitation.
7. Refuse/disallow traffic or containment that reaches beyond approved disposable participants. Preserve management connectivity during tests.
8. Perform restart, recovery, retention and restore tests; measure timestamps, ingest/display lag, coverage and missing data.

## Migration

The seven-PC and fixed four-PC diagrams are historical regression/deployment layouts, **not assignments of attacker or victim roles**. Deploy host-agnostic workload/sensor adapters on enrolled isolated PCs or VMs and choose participants at scenario runtime. Maintain one MON codebase and a stable main branch through PR review.
