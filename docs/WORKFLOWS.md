# System flows and response safety

These diagrams depict the **target architecture and current implemented foundations**, not guarantees of production certification. The authoritative capability status is in [the readiness ledger](production-readiness.md). The `main` baseline and newer lab branches are intentionally not conflated.

## 1. Distributed site-to-control-plane architecture

![RIFTWARD architectural boundaries](brand/system-boundaries.svg)

```mermaid
flowchart LR
  N["Zeek / Suricata network sources"] --> S["Local Site Controller"]
  E["Linux / Windows endpoint evidence"] --> S
  S --> P["Local normalization, durable evidence and correlation"]
  P --> L["Local policy, action execution and TTL recovery"]
  S <-->|"Site identity + mTLS"| C["SaaS Control Plane"]
  C --> O["Operator RBAC, incidents, policy, audit"]
  L --> X["Supported enforcement adapters"]
```

**Key boundary:** offline delivery cannot remove local event buffering, allowed local analysis, or recovery duties. Existing adapters are not a blanket claim that every firewall or NAC is certified.

## 2. Incident lifecycle

![RIFTWARD detection to recovery lifecycle](brand/lifecycle.svg)

```mermaid
flowchart LR
  A["DISCOVER"] --> B["DETECT"]
  B --> C["CORRELATE"]
  C --> D["TRACE"]
  D --> E{"Policy gate"}
  E -->|"Approved and safe"| F["CONTAIN"]
  E -->|"Denied / insufficient evidence"| H["Record + escalate"]
  F --> G["VERIFY"]
  G --> I["RECOVER"]
```

Each finding and incident must retain **source evidence**, tenant/site scope, observed facts versus inferences, confidence and timestamps. Tracing is a provenance-bound graph operation, not a fictional story about the attacker.

## 3. Controlled response and rollback

![Response safety and rollback](brand/response-safety.svg)

```mermaid
flowchart TD
  I["Incident evidence + requested action"] --> P{"Evidence, policy, approval?"}
  P -->|"No"| DENY["Deny / escalate / audit"]
  P -->|"Yes"| CAP{"Adapter, scope, TTL, blast radius safe?"}
  CAP -->|"No"| DENY
  CAP -->|"Yes"| APPLY["Apply with idempotency and audit"]
  APPLY --> VERIFY{"Actual result verified?"}
  VERIFY -->|"No"| RECON["Reconcile / rollback if required"]
  VERIFY -->|"Yes"| TTL["Continue scoped monitoring until TTL or operator rollback"]
  TTL --> REC["Rollback + verify service recovery"]
  RECON --> REC
```

No permanent critical-asset isolation from a single weak detector. Every response object must have a defined rollback operation and explicit outcome. The right enforcement point can be endpoint, network, cloud or upstream only when a suitable adapter/integration is truly present and policy permits its use.

## 4. Failure-mode principles

| Condition | Intended safe behavior |
|---|---|
| SaaS unavailable | Local site buffering/analysis and permitted recovery continue; cloud state is marked unavailable |
| Sensor disconnected | Report missing data, sensor status and last-known evidence; do not fabricate normal traffic |
| Detector weak or ambiguous | Preserve observations and uncertainty; escalate instead of claiming compromise |
| Enforcement point unavailable | Fail closed or choose another policy-authorized verified point; never mark action as successful |
| TTL expires | Reconcile state, rollback and verify service condition; preserve audit record |
| Site identity or tenant mismatch | Reject cross-scope ingestion or command execution |
| Upstream volumetric DDoS saturates link | Local host firewall is insufficient; coordinate upstream mitigation where supported |

For code and acceptance evidence consult [the architecture baseline](ARCHITECTURE.md), [release gates](production-readiness.md) and [project engineering charter](../PROJECT_INSTRUCTIONS.md).
