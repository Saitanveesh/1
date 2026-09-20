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

## Endpoint and identity foundation

Endpoint telemetry enters MON as typed evidence, not as an implicit trust source. The
current foundation normalizes process starts, authentication success/failure, and
process-network connections into tenant/site-scoped `SecurityEvent` records. Derived
identity and process records are persisted separately from forensic events, and the attack
graph links identities, assets, processes, process parents, and endpoint network peers.

Identity confidence is explicit. Source-provided Windows SIDs and Linux UIDs with a
namespace are strong identities. Username-only observations are weak and scoped to the
observed asset. Process confidence is also explicit: source process GUIDs are strong;
PID-only observations are scoped to asset, session, and event time to avoid unsafe merges.

The first Windows collector adapter reads Windows Event Log XML for Security logon and
process-creation records, plus optional Sysmon process/process-network records when Sysmon is
actually present. It feeds the same endpoint normalization and `SecurityEvent` pipeline
rather than creating a second event path. The current collector has a durable record cursor
and bounded local buffer, but it is not a production-complete EDR agent, installer, signed
Windows service, or Linux collector.

A separate Linux collector adapter (`mon-linux-endpoint-collector`) reads systemd journal
`sshd` authentication messages and Linux audit `execve` records, feeding the same endpoint
normalization and `SecurityEvent` pipeline. It has its own durable per-source cursor, bounded
local buffer, and cancellation-aware systemd-managed foreground runtime, but it is not a
production-complete Linux EDR agent, DEB/RPM package, or eBPF/kernel-level collector, and it
does not implement rotation-safe audit log tracking yet.

## Enforcement adapter capability contract

`EnforcementRegistry` pairs each registered adapter with a typed
`EnforcementAdapterCapabilities` declaration (supported actions, execution plane, verify/
rollback/reconcile support, idempotency, credential requirement, timeout bound, local-vs-remote
execution, target types). Response planning checks a selected enforcement point's *configured*
`EnforcementPoint.capabilities` against what the *registered adapter* actually declares, and
denies the plan with an explicit reason on mismatch rather than downgrading silently. A reusable
`certify_enforcement_adapter()` harness exercises apply/verify/idempotent-reapply/reconcile/
rollback/idempotent-rollback plus negative cases for any adapter meeting the contract, intended
for future firewall/NAC/cloud connectors as well as the current nftables adapters.
`LinuxNftablesEndpointAdapter` (BLOCK_IP only, MON-owned `inet mon_endpoint` table) is the first
adapter built against this contract for eventual endpoint-host use; it is certified only in
disposable network namespaces so far, gated behind
`MON_ENABLE_ENDPOINT_NFTABLES_ENFORCEMENT=1` (disabled by default), and is separate from the
pre-existing `DisposableNftablesAdapter`, which remains netns-only.

## Non-negotiable properties

- multi-tenant isolation
- connector credentials referenced by ID and encrypted outside generic control-plane JSON
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
