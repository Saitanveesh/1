# MON Security Fabric — Project Instructions

## Mission
Build MON as a production-grade, multi-tenant critical-network detection, investigation, containment, and recovery platform. This is not a college demo, not a packet viewer, and not a single-machine Windows monitor.

MON must answer:
1. What is happening on the network?
2. Which asset/user/service is involved?
3. Is the activity internal, external, or lateral?
4. What evidence supports the conclusion?
5. What is affected and what path did the activity take?
6. Where can the threat be contained most safely?
7. How can the action be rolled back and service health verified?

## Product principles
- Evidence first. Never fabricate metrics, hostnames, attack verdicts, or confidence.
- Passive observation by default. Active probing is a separately controlled capability.
- Detection and enforcement are separate subsystems.
- There is no single trusted perimeter. Treat inside/outside as context, not trust.
- Response follows the threat to the safest enforcement point.
- Local site protection must continue if cloud/SaaS connectivity is lost.
- Every automated response requires a reason, confidence, TTL, blast-radius estimate, audit record, and rollback path.
- Critical infrastructure actions require stricter policy/approval than ordinary endpoints.
- Prefer mature engines and open standards over rewriting solved problems.
- Security controls must fail safely.
- No untested binary may be delivered to a user's production workstation.

## Target architecture
MON is composed of:
- SaaS Control Plane: tenants, users/RBAC, sites, policy, fleet, incidents, reports, audit, updates.
- Local Site Controller: local autonomy, buffering, correlation, policy execution, connector management.
- Network Sensors: Zeek-style metadata, Suricata IDS, flow telemetry, packet evidence, optional Arkime-style retention.
- Endpoint Sensors/Connectors: Windows/Linux telemetry, host identity, process/network evidence.
- Infrastructure Connectors: firewalls, routers, switches, NAC, cloud security groups, WAF/reverse proxies.
- Event Fabric: durable asynchronous event bus.
- Normalization: OCSF-inspired common event model.
- Asset/Identity Graph: hosts, users, IPs, MACs, services, interfaces, VLANs, switches, ports, cloud identities.
- Detection: signatures, behavior, statistical baselines, threat intelligence, correlation.
- Attack Graph: reconstruct relationships and likely attack progression from evidence.
- Policy Decision Engine: OPA-like decision model.
- Response Orchestrator: OpenC2-style action abstraction.
- Enforcement Graph: maps each asset to available control points.
- Evidence Store: alerts, flows, packet references, endpoint evidence, audit history.
- Recovery Engine: rollback, reconnect, verify service health, close incident.

## Preferred technologies
Technology choices are not frozen by language.
Use the best component for each subsystem. Expected stack may include:
- Go or Rust for high-performance agents/sensors/connectors.
- Python for analytics, detection research, integrations, and orchestration where appropriate.
- TypeScript/React for the operator console.
- PostgreSQL for transactional/control-plane data.
- ClickHouse and/or OpenSearch for high-volume telemetry/search where justified.
- Redpanda/Kafka-compatible event streaming for durable event transport.
- Redis only when it adds clear operational value.
- gRPC and/or well-defined REST APIs.
- mTLS for site-to-control-plane communications.
- Docker/Compose for local development; Kubernetes only when scale warrants it.
- Zeek, Suricata, Arkime, Sigma, OCSF, STIX/TAXII, OPA concepts, OpenC2 concepts, MITRE ATT&CK/D3FEND mapping where useful.

Do not force every technology into the product. Each dependency must have a specific architectural reason.

## Detection requirements
Support evidence-backed detection/correlation for at least:
- volumetric and protocol-level DoS/DDoS indicators
- TCP/UDP/ICMP flooding
- scanning and reconnaissance
- brute-force/authentication abuse indicators
- lateral movement
- DNS abuse and tunneling-shaped activity
- ARP/MAC anomalies
- suspicious beaconing/C2-like periodicity
- unusual east-west communication
- service exposure changes
- abnormal traffic-rate and protocol baselines
- known network IDS signatures
- threat-intelligence matches
- cross-source network + endpoint correlation

Do not call an observation a compromise unless evidence supports that statement.

## Response requirements
Actions may include:
- temporary IP/network deny
- rate limiting
- endpoint host-firewall isolation
- switch/NAC quarantine
- VLAN reassignment
- port shutdown where policy permits
- firewall/router ACL changes
- WAF/reverse-proxy action
- cloud security-group action
- upstream DDoS escalation where supported
- restore/unblock/reconnect

Every response object must include:
- incident id
- target
- requested action
- selected enforcement point
- evidence/reason
- confidence
- policy decision
- TTL
- rollback operation
- actor (automatic/operator)
- timestamps
- outcome
- audit record

Never permanently block or isolate critical assets automatically from a single weak detector.

## Operator console
The primary console should feel like an operational SOC/critical-network command center.

Core views:
- global/site health
- network health
- attack pressure
- DDoS pressure
- east-west threat
- asset exposure
- enforcement coverage
- critical services at risk
- live incidents
- topology/asset graph
- attack graph
- affected systems
- flow/session evidence
- packet/evidence references
- endpoint evidence
- containment status
- response controls
- recovery status
- policy/audit history
- fleet/sensor health

Metrics must explain their source and calculation. A score without transparent evidence is not acceptable.

## SaaS/multi-tenancy
Design tenant isolation from the beginning:
- tenant_id and site_id are first-class identifiers.
- authentication and RBAC must be explicit.
- tenant data must never mix.
- secrets/credentials for enforcement connectors must be protected.
- audit trails must be immutable enough for incident review.
- local site operation must tolerate temporary cloud loss.

## Safety and testing
All potentially disruptive behavior must be tested in disposable infrastructure first.

Release gates must include:
- unit tests
- integration tests
- API contract tests
- static/lint/type checks
- security tests
- migration tests
- load/resource tests
- failure/retry tests
- sandbox/VM tests for OS-native components
- child-process/resource budgets for endpoint agents
- rollback tests for containment actions

Do not deliver an executable merely because it compiles or starts.

## Engineering discipline
- Use trunk/main as stable; develop changes on feature branches/PRs.
- Keep architecture decisions in docs/adr/.
- Keep APIs versioned and documented.
- Add tests with every bug fix.
- Treat retries, backpressure, idempotency, timeouts, and partial failure as normal distributed-system conditions.
- Do not hide errors by returning fake healthy values.
- Avoid giant modules and tightly coupled components.
- Make integrations adapter-based.
- Prefer explicit schemas and typed models.
- Record assumptions and unresolved risks.

## Working style for ChatGPT
Act as technical lead/architect/implementer, not merely an adviser.
When enough information exists, make a defensible engineering decision instead of repeatedly asking for confirmation.
Ask the user only when a decision materially changes product scope, safety, cost, deployment assumptions, or external infrastructure.
Use web research for current architecture/product comparisons and official documentation.
Use the connected GitHub repository as the implementation source of truth.
Commit meaningful changes with clear messages.
Before claiming something is complete, verify it through tests or CI.
Do not claim background work or completion that has not actually happened.
When a design changes, update repository documentation so future project chats inherit the current architecture.

## Current repository
Canonical repo: https://github.com/Saitanveesh/1

## Current product name
Working name: MON Security Fabric.
The name can change later; architecture and interfaces must not depend on branding.
