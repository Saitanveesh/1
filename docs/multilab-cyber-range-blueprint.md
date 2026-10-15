# Multi-lab Cyber Defense Range: deployment and demonstration blueprint

Status: Planned architecture, not a tested deployment
Source decision: [ADR 0076](adr/0076-dynamic-multilab-attribution-and-range.md)
Updated: 2026-10-15

## Objective

A red-team participant can use **any authorized enrolled exercise station** among five laboratories (planning assumption: ~25 endpoints each). MON identifies that station and the affected target **from live evidence**, rather than by assigning PC6 or a fixed IP as the attacker. The blue team chooses a containment point effective on the real path. An audience sees the story and the independently measured victim impact in near real time.

This is two related but distinct deployments:
- **Campus observation**: permissioned, passive, privacy-aware detection and attribution across instruments we actually control. Default alert-only or human-approved actions; no unbounded test traffic.
- **Controlled exercise**: dedicated disposable VMs/services or isolated test VLANs in different physical labs, with explicit runtime allowlists, protective controls, and no bridge/route to nonparticipants. Only here may red-team traffic intentionally degrade a test service.

## Superseding physical deployment: exactly four dedicated computers

**ADR 0077 supersedes the earlier seven-dedicated-PC presentation layout.** Use PC1 as the consolidated MON backend/database/metrics/evidence/UI and possible sensor only where mirrored traffic is actually delivered; PC2 for blue-team operators; PC3 for the red-team exercise launcher and isolated generators; PC4 for disposable service/victim VMs. The red/blue team roles are initial operator workstations: MON must discover source and victim dynamically from observed data, including other **authorized** exercise hosts. The HDMI matrix can render six live views from these computers; do not allocate one computer per panel.

The five-lab network may contain any number of endpoints; do not assume 125 as a configured constant. Auto-discovery combines approved DHCP/DNS records, SNMPv3 switch FDB/port/VLAN and LLDP observations, ARP/neighbor evidence, network sensors and optional endpoint agents, with source timestamps, confidence, freshness, deduplication and gaps. "All devices" is a **coverage objective**, not a guarantee of absolute visibility: report observed, expected-but-unobserved and unknown endpoints. A single gateway sensor does not see arbitrary same-VLAN traffic. Resource sizing and per-switch capture/export feasibility require a hardware survey.

**Backend and retention:** the repository already has PostgreSQL state, migrations, durable audit and response receipts. Add explicit historical asset/link/incident indexes, bounded raw evidence archive with hashes, Prometheus-compatible time-series health, independent HTTP/TCP probes, encryption/retention/backup-restore and disk quotas; introduce ClickHouse/OpenSearch only if testing requires it. OS CPU/RAM/process health for an arbitrary victim requires an agent or authorized OS management source; without it show only evidenced network or service availability, never imagined measurements.

**First flagship service:** an isolated synthetic college ERP composed of an engineer/student workstation, application/API and PostgreSQL database populated **only with fabricated student records**. Model observed dependencies and show real service latency/error and host metrics during a bounded attack against that disposable system. Do not target or copy the college production ERP, credentials or real student database. For L2 MITM tests use a dedicated isolated L2 segment; for multi-origin availability tests use rate-limited isolated generators with automatic abort. For the demo, source and authorized victim can change without changing code or hard-coded detection targets.

Detailed acceptance gates, storage tiers, health collection levels and rollback policy: [ADR 0077](adr/0077-four-computer-soc-consolidation.md).

## Proposed physical/logical layout (subject to hardware survey)

```text
LAB A (25 stations) -- Access switch A --+
LAB B (25 stations) -- Access switch B --+
LAB C (25 stations) -- Access switch C --+-- Distribution/Core -- Authorized upstream
LAB D (25 stations) -- Access switch D --+
LAB E (25 stations) -- Access switch E --+
      |                 |                          |
   endpoint logs   MAC/port/DHCP/RADIUS       flow/SPAN/tap
      +-----------------+--------------------------+
                        v
                MON collectors / sensors
                        |
                Local Site Controller
                        |
         MON events + evidence + asset/topology mapping
                        |
          correlate -> investigate -> policy decision
                        |
            chosen real enforcement adapter
                        |
         verify blocking + service health + rollback

Exercise test VLANs/VM networks are isolated from ordinary campus traffic.
```

A one-gateway packet sensor sees only what passes through that point. Per-switch telemetry and additional sensors may be needed to see same-LAN east-west traffic. Sensor placement is finalized after evaluating switch topology and mirror availability.

## Runtime attribution (do not preselect an attacker)

For each suspicious event:
1. Capture the actual event source/destination/timestamp and preserve evidence reference.
2. Resolve IP-to-MAC for that *time*, not only today's current lease.
3. Join MAC+VLAN to switching-table and port observations for that time.
4. Join port to physical lab/seat or access point only if authenticated inventory supports it.
5. Join logged-in user/process only when endpoint or NAC evidence supports it.
6. Record identity confidence, alternatives and gaps. Display the full chain with a verification flag per hop.
7. Resolve an enforcement option based on whether the traffic is same-VLAN, routed, host-local or upstream.

Example **illustrative only**, not observed:
```
Suspicious requests -> IP 10.40.2.18 -> observed MAC -> Lab B switch/port 14
     -> possible Lab B seat 14 -> test web service in Lab D
MON: suspected source; identity and location confidence explained
Blue team: approved limited block on applicable access switch or gateway
Victim monitor: requests/latency before and after; allowed traffic unaffected
```

## Operator experience: six-screen large-wall composition

1. **Visitor story** (largest): actual source, victim, visible traffic path, current situation, outcome in plain English.
2. **Victim pulse**: service success, response latency, CPU/RAM, network rates; chart points from measured probes/agents.
3. **Blue-team response**: detection evidence, plan, approver, target, containment status, effect and remaining TTL.
4. **Red-team stage**: operator-authorized scenario type, elapsed time, exercise ID and emergency STOP; redact secrets.
5. **Lab topology**: five labs and switch/port map; explicitly mark unobserved segments and inferred hops.
6. **Evidence timeline**: alert receipt, correlation, command dispatched, rule verified, service recovered, rollback and audit.

Three display modes: visitor (plain English), analyst (technical evidence) and replay (clearly labeled historical data, never marked live). Wall tiles subscribe to the same authenticated live event stream and event IDs.

## First delivery slice

Use one real dynamically selected source and one disposable victim service in the isolated range; relocate the source VM or choose another authorized station for a repeat exercise **without changing hard-coded rules**. Use bounded reconnaissance and failed-logon test records that existing MON collectors/detectors are expected to support, then validate the actual source-to-victim route, enforce a short-TTL BLOCK_IP at the certified lab router, verify connection refusal and unaffected management, rollback and restore access. This tests the full lifecycle with measured data.

Then develop (not merely label) further scenarios:
- **MITM/ARP scenario**: a separate Layer-2 exercise segment, switch or endpoint ARP evidence, test-only plaintext traffic, spoofed-binding detection and certified DAI/switch containment where available. Capture false-positive controls.
- **Multi-source availability scenario**: isolated bounded load generators, actual service response-time / error metrics and explicit traffic ceilings. The word DDoS is reserved for multiple generators. Demonstrate a gateway/switch action only for paths it actually controls.
- **Lateral movement exercise**: controlled, harmless credential and connection simulation on dedicated disposable identities/assets; correlate endpoint and network evidence without claiming compromise absent proof.

## Required site survey before implementation

Record for all five access switches and distribution path: vendor/model/firmware; L2/L3 uplinks; VLANs and subnets; routing boundaries; managed credentials/RBAC; SPAN/TAP availability and mirror oversubscription; sFlow/NetFlow/IPFIX support; DHCP server/log access; 802.1X/RADIUS/NAC support; MAC-address table / LLDP / SNMPv3 support; DAI/DHCP-snooping/IPSG availability; programmable ACL/quarantine facilities; and physical port-to-seat documentation.

Record host OS, hypervisor capacity, available spare switch ports, expected traffic peaks, administrator approvals, red/blue team scopes, campus privacy and change controls. Do not enable switch security features on production without reviewing trusted-port placement and the impact on existing static IP devices.

## Measurement and safety gates

- Report event timestamp precision, sensor clock skew, measured ingestion/display lag (p50/p95/p99), and dropped/sampled observations. Aim for responsive sub-few-second display *as a target*, not a deployment claim. Do not promise every millisecond of full-stack response.
- Exercise controllers enforce source and destination allowlists, bounded packet/request rate and duration, permitted scenarios, emergency stop, and automatic expiry; hardware ACLs and isolation enforce boundaries independently of attacker cooperation.
- Campus observation and demo VLANs must not be confused. Exercise must stop on a boundary check failure, missing coverage, absent rollback or unexpected service impact.
- Disruptive production controls require separate change approval and certification of the exact switch model, privileges, lease/port associations, verification and rollback.
- No fallback synthetic incidents or synthetic health allowed in live views; loss of telemetry is displayed as **unknown/stale**, never healthy.
- Red and blue teams rehearse once with noncritical disposable services, once with a dynamically moved source, and once with a forced network/collector failure.

## Test gates for the first live acceptance

- a participant can select any of at least two **authorized** source stations at runtime;
- MON identifies a source from observed data, with evidence-backed binding to an actual port or an honest unknown;
- sensor observes actual packets and victim agent/probe corroborates service change;
- the visitor screen and health screen agree on incident ID and chronological sequence;
- blue-team approval executes at a verified control point, stops the permitted attack path without blocking unrelated management;
- rollback restores allowed access and is audited;
- a misrouted or outside-scope test and an uncertain source attribution cannot auto-block a production endpoint;
- performance data and gaps are recorded, not invented.

The existing seven-PC runbook remains valid as a *smaller routed lab regression test*; it is not proof of five-lab campus coverage.
