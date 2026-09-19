# MON Security Fabric — Architecture Baseline

## High-level topology

```text
                         MON SaaS Control Plane
        tenants / RBAC / fleet / incidents / policy / audit / reports
                                  |
                                 mTLS
                                  |
                         Local Site Controller
             local autonomy / buffering / policy / orchestration
                                  |
          +-----------------------+-----------------------+
          |                       |                       |
     Network sensors        Endpoint telemetry      Infra connectors
     Zeek / Suricata        Windows / Linux         FW / Router / NAC
     Flow / PCAP refs       identity/process        Switch / Cloud / WAF
          |                       |                       |
   sensor mTLS ingress            |                       |
          |                       |                       |
          +-----------------------+-----------------------+
                                  |
                            Event Fabric
                                  |
                           OCSF-style model
                                  |
             +--------------------+--------------------+
             |                    |                    |
        Detection          Asset/Identity Graph   Evidence Store
             |                    |                    |
             +--------------------+--------------------+
                                  |
                              Correlation
                                  |
                              Attack Graph
                                  |
                          Policy Decision Engine
                                  |
                         Response Orchestrator
                                  |
                          Enforcement Graph
                                  |
              endpoint / NAC / FW / router / cloud / WAF
                                  |
                              Recovery
```

## Architectural position

MON is not intended to replace every specialized security engine. Mature systems should be integrated where they provide strong primitives:
- Zeek for rich network metadata
- Suricata for IDS signatures/protocol awareness
- Arkime-style packet evidence/retention where needed
- Sigma-compatible detection content
- OCSF-inspired normalization
- STIX/TAXII threat intelligence
- OPA-style policy decisions
- OpenC2-style response semantics
- MITRE ATT&CK/D3FEND mappings

MON's differentiating layer is correlation, asset/enforcement graphing, attack-path reconstruction, policy-safe multi-point containment, recovery, and a unified operator experience.

## Non-negotiable properties

- multi-tenant isolation
- local autonomy during SaaS loss
- evidence provenance
- cryptographically scoped remote sensor identity
- explicit confidence
- safe rollback
- idempotent response actions
- auditable policy decisions
- no fabricated telemetry
- no single-perimeter trust assumption
- disposable-environment validation before production release

This document will evolve through architecture decision records under `docs/adr/`.
