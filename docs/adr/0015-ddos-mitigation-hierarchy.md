# ADR 0015: Evidence-gated DDoS mitigation hierarchy

Status: Accepted

## Decision

MON treats DDoS response as location-aware escalation, not a single automatic block.
The planner consumes an already-confirmed detection/investigation outcome, measured
traffic observations and an explicit impact scope. It does not classify an attack or
infer upstream-link saturation from a hard-coded packet-rate threshold.

For local service pressure, the mitigation order is:

1. endpoint;
2. switch/NAC;
3. firewall/router;
4. cloud/WAF;
5. upstream mitigation.

Within each location tier, healthy enforcement points are preferred over degraded
points and unavailable points are excluded.

For an impact classified as UPSTREAM_LINK, MON skips controls that only see traffic
after the saturated link. It may use a router only when that router exposes an
UPSTREAM_MITIGATION capability, followed by cloud/WAF or explicit upstream controls.
A local endpoint or firewall rate limit is not represented as a solution to upstream
link exhaustion.

An UNKNOWN impact scope fails closed. Investigation must establish whether the
observed impact is local/service-level or upstream-link-level before a mitigation ladder
is proposed.

Every proposed step contains only measured rate, observation window, source count and
baseline multiplier when a non-zero measured baseline exists. Execution remains the
responsibility of the response orchestrator from ADR 0014, preserving approval policy,
finite TTL, durable audit, idempotency and rollback.

## Action semantics

The DDoS planner does not propose per-source IP blocking without source-specific evidence.
It uses rate limiting where supported, application/cloud controls where explicitly
registered, and upstream mitigation capabilities for saturated-link scenarios.

## Safety boundary

This planner does not call a firewall, switch, WAF, cloud or ISP API. Real adapters remain
disabled until validated in disposable infrastructure. A deployment must not test
unvalidated network-control binaries or vendor integrations on an operator workstation.
