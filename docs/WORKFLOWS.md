# GAUNT — technical flows

**Editable Mermaid diagrams, not AI artwork or telemetry screenshots.** These are engineering processes with coverage limitations: [readiness](production-readiness.md), [lab scope](RED_BLUE_RANGE.md).

## 1. Red/blue test boundary

```mermaid
flowchart TB
  O["Written permission + target inventory"] --> I{"Segmentation, rates, rollback verified?"}
  I -->|"No"| STOP["STOP: do not generate traffic"]
  I -->|"Yes"| RED["RED: controlled lab scenario"]
  RED --> T["Test victim service"]
  T --> SENSOR["Network + endpoint telemetry"]
  SENSOR --> BLUE["BLUE: incident, asset, path"]
  BLUE --> POLICY{"Policy + evidence sufficient?"}
  POLICY -->|"No"| GAP["Record coverage gap"]
  POLICY -->|"Yes"| ACTION["Time-bound authorized containment"]
  ACTION --> REC["Verify, rollback, observe recovery"]
  REC --> REPORT["Exercise evidence report"]
  GAP --> REPORT
```

## 2. Telemetry to incident

```mermaid
flowchart LR
  Z["Zeek / Suricata"] --> N["Normalize + scope"]
  E["Endpoint evidence"] --> N
  N --> F["Durable Site Controller event fabric"]
  F --> V["Evidence with provenance"]
  V --> D["Detection + correlation"]
  D --> G["Asset / identity / attack graph"]
  G --> I["Finding or incident"]
  I --> UI["SOC UI + audit trail"]
```

## 3. Cloud outage while a site continues

```mermaid
flowchart TB
  S["Sensors"] --> L["Site Controller"]
  L --> B["Durable event buffer"]
  B --> C{"mTLS to cloud available?"}
  C -->|"Yes"| CP["Cloud receipt / incidents"]
  C -->|"No"| BACK["Retry with backoff, report degraded"]
  BACK --> B
  L --> A["Local evidence + permitted policy"]
  A --> R["TTL recovery and audit"]
```

## 4. Containment must be rollback-ready

```mermaid
flowchart TD
  INC["Incident + evidence + confidence"] --> P{"Policy, tenant/site, criticality, approval?"}
  P -->|"No"| DENY["Deny / escalate / audit"]
  P -->|"Yes"| CAP{"Adapter, target, scope, TTL?"}
  CAP -->|"No"| DENY
  CAP -->|"Yes"| BL["Estimate blast radius + rollback"]
  BL --> APPLY["Idempotent apply"]
  APPLY --> V{"Verified effect?"}
  V -->|"No"| RC["Reconcile / revert"]
  V -->|"Yes"| TIMER["Observe until TTL"]
  RC --> REC["Restore + verify service"]
  TIMER --> REC
  REC --> AUDIT["Audit actual outcome"]
```

## 5. Safe lab-branch integration

```mermaid
flowchart LR
  LAB["Recorded deployed commit + backup"] --> DIFF["Compare lab feature branch to main"]
  DIFF --> CHECK["Review schema, auth, policy, APIs"]
  CHECK --> CI["Tests + disposable rollback"]
  CI --> PR["Review PR against main"]
  PR --> STAGE["Staged cutover and recoverability"]
```

**Failure contract:** no false sensor-health claims; weak signals remain uncertain; no unverified enforcement success; no attack exercise without explicit isolation; no permanent containment on a single detector. See [architecture](ARCHITECTURE.md).
