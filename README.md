# MON Security Fabric

MON is a critical-network detection, investigation, containment, recovery, and multi-tenant
security platform.

It is built as a distributed security fabric rather than a single-host or single-firewall
monitor. Detection, investigation, policy, enforcement, rollback, and recovery are separate
concerns connected by typed, tenant/site-scoped state.

## Product direction

MON combines:

- distributed network and endpoint telemetry;
- asset and identity graphing;
- signature, behavioral, statistical, and correlation detection;
- attack-path reconstruction;
- policy-driven response decisions;
- multi-point enforcement;
- containment rollback and recovery;
- a multi-tenant SaaS control plane with locally autonomous site controllers.

There is no single perimeter device that defines trust. Enforcement may occur at an endpoint,
switch/NAC, network firewall/router, cloud control, WAF, or upstream mitigation point,
depending on evidence and the enforcement graph.

## Current implementation status

MON is an active production-foundation implementation, not a finished production release.

Implemented foundations include:

- typed tenant/site-scoped domain models and APIs;
- PostgreSQL control-plane persistence and migrations;
- forced PostgreSQL tenant/site row-level security under a non-bypass runtime role;
- RBAC/authentication boundaries and site enrollment identities;
- rotatable RS256 JWKS trust sets with fail-closed hot reload;
- mTLS site ingress;
- durable at-least-once site command delivery and result receipts;
- durable site response state, audit, TTL recovery, and autonomous recovery reporting;
- append-only SHA-256-sealed audit records with PostgreSQL mutation guards;
- execution-plane dispatch between site-local and control-plane enforcement;
- evidence-based reconciliation of crash-interrupted enforcement;
- late response-state convergence after site command expiry;
- disposable Linux network-namespace/nftables enforcement validation;
- local event buffering and a production site-controller service composition;
- Zeek JSON and Suricata EVE normalization into scoped, deterministic MON evidence;
- mTLS-authenticated sensor ingress plus durable Zeek/Suricata file collectors;
- managed sensor enrollment, renewal/revocation, durable site trust, and fleet heartbeats;
- crash-safe managed sensor credential generations with proactive certificate rotation;
- typed tenant/site event-fabric envelopes with durable local consumer idempotency;
- durable exact-envelope producer outbox with ordered retry and crash reconciliation;
- verified site-mTLS fabric ingress with durable control-plane processing receipts;
- network detection, correlation, asset enrichment, attack/investigation graph foundations;
- push/live operator updates and a React operator console foundation;
- PostgreSQL, Python, container, console, and disposable Linux enforcement CI gates.

Known boundaries are reported explicitly rather than hidden. Local evidence objects
(events, assets, findings, and incidents) are durable; detector/correlation/graph windows are
warm-restored after restart; and one event plus its derived durable state is committed as an
atomic local analysis unit before the event becomes cloud-deliverable. The remaining local
scale boundary is retained-history growth and linear warm-restore cost. The nftables adapter
in this repository remains disposable-sandbox-only rather than a production host firewall
connector.

See:

- `PROJECT_INSTRUCTIONS.md` for the product and engineering charter;
- `docs/ARCHITECTURE.md` for the architecture baseline;
- `docs/adr/` for accepted architecture decisions;
- `docs/site-controller.md` for Site Controller runtime configuration.

No binary or deployment is considered production-ready merely because it compiles or starts.
Release claims require the repository release gates and appropriate disposable/VM validation.
