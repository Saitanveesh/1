# ADR 0038 — MON name and observable SOC status

- **Status:** Accepted for three-host lab operator UI; production readiness separate
- **Date:** 2026-10-10

## Context

Until now the durable repository used the MON Security Fabric brand without an explicit expansion. The operator requested a readable full form in the sign-in page and removal of lab identifiers and decorative single-letter marks from the SOC console. The WebSocket UI conflated the last received heartbeat (or initial HTTP snapshot) with the time of an actual security event, causing an apparently frozen `LAST EVENT` time even when the transport remained live.

## Decision

**MON = Monitoring, Orchestration, Neutralization.** Monitoring is evidence-backed detection; Orchestration is correlation, investigation, enforcement-point selection and policy decisions; Neutralization is **bounded, approved and reversible** containment followed by verification and recovery. Neutralization does *not* authorize permanent isolation or uncontrolled attack traffic. Product branding remains `MON Security Fabric`.

Show the expansion in the login page instead of topology-specific labels such as `PC2`. The operator console uses the MON wordmark without a boxed initial, and removes identity/role, tenant/site and low-level sequence counters from the sidebar chrome. These fields remain first-class in APIs, audit and authorization; visual omission is not a loss of tenant isolation.

Display (1) actual transport state, (2) a **live elapsed age** since the last genuine server WebSocket frame, updated once per second by the browser clock, and (3) a separate timestamp of the last actual security event, only advanced upon a non-control event. A mere HTTP snapshot, `stream.ready` or `stream.heartbeat` must never be counted as an attack/detection event. When none has been observed, display `NONE OBSERVED`. If heartbeat frames stop for over 45 seconds, reconnect rather than claim a healthy stream indefinitely. The backend emits heartbeat envelopes at 15-second idle intervals.

## Consequences and verification

- The operator can see stream freshness ticking without fake event activity.
- The static security-event timestamp remains evidence-derived and is allowed to remain unchanged when no events occur.
- The dashboard is deliberately less cluttered without hiding sensor health, RBAC checks or audit state in API and dedicated views.
- CI covers elapsed formatter, true last-event semantics, visible chrome and live staleness behavior; actual browser/site acceptance is still required.
- The next site deployment stage must remain gated on an authenticated, guarded PC2 network path; an active old WireGuard hub at `10.5.115.5:51820` is **not** proof that the PC2 sensor observes traffic.
