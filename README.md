# MON Security Fabric

MON is a critical-network detection, investigation, containment, and recovery platform.

The project is being rebuilt cleanly as a distributed security fabric rather than extending the previous single-host Windows monitoring prototype.

## Product direction

MON combines:
- distributed network and endpoint telemetry
- asset and identity graphing
- signature, behavioral, statistical, and correlation detection
- attack-path reconstruction
- policy-driven response decisions
- multi-point enforcement
- containment rollback and recovery
- a multi-tenant SaaS control plane with locally autonomous site controllers

The system is designed so that there is no single "firewall" that defines trust. Enforcement can occur at the endpoint, switch/NAC, network firewall/router, cloud, WAF, or upstream DDoS layer depending on the incident.

## Status

Architecture bootstrap.

See:
- `PROJECT_INSTRUCTIONS.md` for the product/engineering charter.
- `docs/ARCHITECTURE.md` for the evolving technical architecture.

No binary or production deployment is considered ready until it passes the repository's release gates.
