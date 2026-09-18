# ADR 0001: Platform foundation and trust boundaries

Status: Accepted

## Decision

MON starts as a modular control-plane foundation with explicit domain contracts before
adding packet sensors, dashboards, or vendor enforcement implementations.

The first contracts are:

- tenant/site-scoped security events
- evidence references with provenance and confidence
- assets with criticality
- incidents with independent evidence
- enforcement points with declared capabilities and health
- response requests with finite TTL for disruptive actions
- policy decisions of ALLOW, REQUIRE_APPROVAL, or DENY
- vendor-neutral enforcement adapters

## Why

The prior prototype coupled monitoring behavior directly to one Windows runtime. A
critical-network SaaS product requires stronger separation between observation,
correlation, policy, and enforcement.

The policy engine intentionally requires multiple evidence classes and high confidence
before autonomous disruptive action. Critical assets require approval even when
confidence is high.

## Consequences

- Sensors can be implemented independently of the control plane.
- Firewall/NAC/cloud integrations implement adapters rather than changing incident logic.
- Tenant/site scope is present in core contracts from the beginning.
- In-memory persistence is development-only and must be replaced before production.
- Authentication, durable storage, event streaming, and signed site identity are the
  next infrastructure milestones.
