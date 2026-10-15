# ADR 0076: Dynamic multi-lab attribution and controlled cyber-range response

Status: Accepted as architectural direction; implementation and campus capabilities not verified
Date: 2026-10-15

## Context

MON's existing seven-PC runbook is a **bounded demonstration topology**, not the target discovery model. The intended environment may contain five laboratories with approximately 25 computers each, and any enrolled/visible computer may become an observed source or target. Operators must not need to assign a fixed attacker IP, victim IP, or physical location before monitoring begins.

A separate, professor-facing cyber-range demonstration must show a real action from an operator-selected eligible station or disposable VM, network/endpoint evidence, actual victim impact where applicable, a defensible source-to-port attribution, safe containment, independent verification, and recovery. A campus LAN is not an unrestricted attack sandbox.

## Decision

1. Retain MON's existing typed evidence, incident, tenant/site, local-controller, enforcement and rollback foundations; implement a **dynamic identity and topology resolution layer** over them. Rebranding/presentation changes must not fork the underlying incident truth.
2. Discover assets and traffic sources at runtime from authorized observations: network taps/SPAN or approved flow exports; DHCP leases and snooping bindings; switch MAC forwarding tables; ARP/neighbor observations; switch-port/VLAN inventory; RADIUS/802.1X identities where available; and Windows/Linux endpoint evidence where installed. Store the observation timestamp, origin, expiry and confidence for each association.
3. Attribute using the time-scoped chain: packet/flow source -> IP lease or static binding -> MAC -> VLAN -> switch -> port -> location -> enrolled asset/user (if independently supported). Do not equate IP or MAC with a verified human/device identity. Respect NAT, virtualization, wireless APs, multihomed hosts, spoofing, asymmetric capture, trunk ports, MAC movement, and stale bindings. If the chain cannot be verified, display **source observed, physical system unknown** instead of inventing a location.
4. Maintain explicit sensor coverage by VLAN, switch, direction, visibility mechanism and freshness. Do not claim campus-wide east-west or Layer-2 visibility from a gateway or one monitor port. Aggregate per-lab taps/SPAN or flow data and endpoint/switch evidence as hardware supports. Report sensor health, packet/drop counts when available, blind spots, timestamp skew and last observation.
5. Separate **observation domain** from **exercise domain**. Institution-authorized campus systems may be monitored passively under a documented privacy and access policy. Deliberate disruptive exercises (MITM/ARP interference, service flooding, authentication testing) run only between explicitly approved disposable participants on isolated exercise VLANs or virtual networks, with no forwarding to normal campus systems and with bounded traffic/abort controls. The red team may select a different authorized physical station in any lab; participation and target eligibility are enforced at runtime. Ordinary campus endpoints are not automatically authorized targets.
6. Select enforcement by observed actual path and certified capability, not a fixed gateway assumption. Routed path: vetted gateway/router/firewall; same-VLAN source: capable access switch/NAC or endpoint, where approved; ARP spoofing: validated switch DAI/DHCP-snooping/IP-source-guard mechanisms where supported and safely prepared; external volumetric traffic: upstream mitigation required where the incoming link is saturated. The existing PC3 Linux router nftables adapter cannot intercept arbitrary same-VLAN traffic on other switches.
7. Every disruptive action requires evidence, confidence, explicit affected asset(s), policy decision/approval, enforcement binding, risk and blast-radius estimate, TTL, operator/actor, independent verification, audit and deterministic rollback. Default campus policy is alert/investigate/approval-only; lab automation is limited to preauthorized disposable scope.
8. Add separate views for (A) visitor-readable *What happened / From where / To whom / By which observed path / What MON did / Did it work?*, and (B) independent victim health (service availability, latency, CPU, memory, traffic). Add an analyst drill-down for raw evidence, provenance, timestamps and confidence. Display all views from operational data, never synthetic narration in the live mode.
9. Retain millisecond-resolution timestamps when source data actually provides them; do not promise millisecond end-to-end detection or rendering. Track p50/p95/p99 ingest-to-display and decision-to-enforcement latencies, data loss, clock skew, and status freshness. Set realistic objectives only after on-site measurements.
10. Keep the MON Security Fabric repo and lifecycle coherent during this transition. The original seven-system runbook remains an isolated regression scenario, not a claim that the 125-PC distributed deployment exists.

## Minimal typed observation contracts (direction, not implemented)

- `NetworkObservation`: event_id, tenant_id, site_id, sensor_id, observed_at, received_at, src/dst IP and port, protocol, VLAN, switch/interface if observed, packet/flow evidence refs, sampling/drops, origin and retention.
- `AssetLocationBinding`: tenant_id, site_id, asset_id if known, IP, MAC, VLAN, switch_id, port_id, building/lab/seat if verified, identity source, valid_from, valid_until, confidence, corroborating evidence IDs.
- `CoverageRecord`: site_id, sensor_id, observed VLAN/segment, capture mechanism, direction, last_success, limitations, drop rate if measured, operational status.
- `ExerciseAuthorization`: exercise_id, scope, allowed assets or disposable segment, approved red-team stations, scenario, start/end, traffic ceiling, stop control, assigned operator, approval and audit IDs.
- `ResponsePlan`: incident, observed/verified target identity, enforcement point and capability, action, policy/approval, evidence IDs, confidence, TTL, blast radius, rollback, actor, timestamps and verification results.

Schema details need implementation ADRs, migration strategy, tenant boundary tests and hardware-adapter certification before release.

## Explicit limitations and dependency gates

- A managed switch's actual model, firmware and access rights determine whether SPAN, sFlow/NetFlow, 802.1X, DHCP snooping, DAI, ACLs or port quarantine can be used; do not infer support from having Ethernet ports.
- A passive sensor cannot see all unmirrored same-switch flows; a network map must distinguish inferred links from measured paths.
- Disabling the wrong physical switch port can interrupt several downstream devices; default-deny such actions without verified single-endpoint binding and approved rollback.
- MITM exercises need an isolated shared Layer-2 domain and measurable proof of interception/defense. A routed WireGuard-only lab is not proof of local ARP attack visibility.
- DoS-like demonstrations should use resource-bounded lab services and multiple authorized generators if described as distributed. Blocking at a local gateway does not clear an already saturated upstream connection.
- No campus-wide response, production deployment, hardware integration or live attack is claimed complete by acceptance of this ADR.

## Acceptance gates

1. Discover changing endpoints with no preconfigured attacker/victim identity and identify source asset or explicitly mark attribution unknown.
2. Validate DHCP/MAC/VLAN/port time coherence and anti-spoofing cases; show location confidence and evidence.
3. Prove per-segment visibility, including at least one blind spot deliberately reported rather than hidden.
4. On an isolated exercise VLAN, switch which eligible workstation originates a scenario; MON adjusts attribution without an application restart.
5. In a permitted lab scenario, observe the event, correlate remote endpoint evidence, show independent service effect, apply approved actual-path containment, then prove it works and rolls back.
6. Verify host and sensor operation with SaaS/control-plane temporarily unavailable and reconcile audit state later.
7. Demonstrate that out-of-scope attack requests and unsafe/unverified enforcement actions fail closed.
8. Evaluate the visitor view with a nontechnical reviewer and preserve an analyst evidence drill-down.

## References

- Existing `docs/lab-seven-system-test-day.md` and ADR 0075 (controlled routed lab).
- https://docs.zeek.org/en/master/about/monitoring.html (tap/SPAN coverage and visibility placement).
- https://www.cisco.com/c/en/us/support/docs/switches/lan/lan-switch-software/222274-troubleshoot-dynamic-arp-inspection-dai.html (DHCP/DAI/IPSG examples; capability is vendor/model-specific).
- https://csrc.nist.gov/pubs/sp/800/115/final (assessment scope and testing precautions).
