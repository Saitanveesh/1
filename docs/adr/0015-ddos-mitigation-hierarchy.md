# ADR 0015: Evidence-gated DDoS mitigation hierarchy

Status: Accepted

## Decision

MON treats DDoS mitigation as an escalation ladder, not a single automatic block.
The planner consumes an already-confirmed detection/investigation outcome plus measured
traffic observations. It does not classify an attack from a hard-coded packets-per-second
threshold and does not manufacture a baseline when none was measured.

The mitigation order is:

1. rate limiting at the closest available enforcement layer;
2. application/cloud filtering when that capability is actually registered;
3. IP blocking;
4. upstream mitigation as the final escalation tier.

Within a tier, healthy enforcement points are preferred over degraded points. Unavailable
points are never selected. If a confirmed event has no usable DDoS enforcement capability,
planning fails closed instead of reporting a mitigation that cannot be executed.

Every proposed step carries only measured evidence (rate, observation window, source count,
and baseline multiplier when a non-zero measured baseline exists). Execution remains the
responsibility of the response orchestrator from ADR 0014, preserving approval policy,
finite TTL, durable audit, idempotency and rollback.

## Safety boundary

This planner does not call a firewall, WAF, cloud or ISP API. Real adapters remain disabled
until validated in disposable infrastructure. A deployment must not test unvalidated
network-control binaries or vendor integrations on an operator workstation.
