# ADR 0002: Enforcement graph and evidence-bounded streaming detection

Status: Accepted

## Decision

MON selects containment from an Enforcement Graph instead of assuming one perimeter
firewall. Assets can be bound to endpoint, NAC, switch, router, firewall, WAF, cloud,
or upstream controls. Selection filters by tenant/site, health and action capability,
then prefers the control type and path closest to the requested action.

The initial streaming detector core produces Findings for traffic shapes. It explicitly
avoids claiming successful compromise from network-rate evidence alone.

## Safety properties

- An enforcement point outside the tenant/site cannot be selected.
- Unavailable or incapable controls cannot be selected.
- Explicit operator selection is still validated.
- Asset bindings constrain automatic selection when topology evidence is available.
- Critical-asset and confidence/evidence approval policy remains a separate gate.
- Disruptive actions still require finite TTLs.
