# SERRATE — architecture, lab flow and response gates

This page is deliberately **diagram-led**. These are explanatory flows built from repository architecture and lab runbooks, not a claim that every possible attack or connector is supported or independently certified.

## 1. What the sandbox demonstrates

```mermaid
flowchart LR
  R["Red-team operator<br/>authorized test actions"] --> L["Isolated lab segment"]
  L --> V["Victim / protected service"]
  V --> N["Network + endpoint observations"]
  N --> B["Blue-team investigation<br/>MON / SERRATE"]
  B --> G{"Evidence sufficient<br/>and action safe?"}
  G -->|No| D["Keep observing / escalate"]
  G -->|Yes| C["Time-bounded containment"]
  C --> Q["Verify impact and recovery"]
```

**Control:** attacker tooling and test traffic are **not** the same as MON's detector. Test activity must only occur inside authorized segments, with verified isolation, consent, a stop condition and restoration procedure. Current lab history spans seven-host and three-host plans; do not claim any one topology is permanently active.

## 2. Where telemetry travels

![SERRATE lab and security-fabric structure](brand/system-boundaries.svg)

```mermaid
flowchart TB
  subgraph LAB["Authorized exercise boundary"]
    RED["Red team"] --> VICTIM["Victim service"]
    VICTIM --> SENSORS["Zeek / Suricata / endpoint evidence"]
  end
  SENSORS --> LOCAL["Local Site Controller<br/>buffer, normalize, correlate"]
  LOCAL -->|"mTLS, site identity"| SAAS["SaaS Control Plane<br/>tenants, incidents, policy, audit"]
  LOCAL --> POLICY["Local policy + recovery"]
  POLICY --> EP["Certified enforcement capability"]
  EP --> RESTORE["Verify + rollback + recovery"]
```

Local protection cannot depend on uninterrupted cloud connectivity. A local firewall cannot mitigate upstream congestion after the upstream link is saturated.

## 3. Detection to verified recovery

```mermaid
flowchart LR
 A["DISCOVER"] --> B["DETECT"] --> C["CORRELATE"] --> D["TRACE"] --> E{"Policy"}
 E -->|Approve| F["CONTAIN"] --> G["VERIFY"] --> H["RECOVER"]
 E -->|Reject| I["Audit / investigate"]
```

Source evidence, identity scope, confidence, decision rationale, TTL, blast radius, audit and rollback are required for a defensible action.

## 4. Containment is a decision, not a button

```mermaid
flowchart TD
  EV["Incident + evidence + confidence"] --> PA{"Policy / approval / criticality"}
  PA -->|No| STOP["Deny or escalate + audit"]
  PA -->|Yes| CAP{"Enforcement point capable?<br/>Scope, TTL, blast radius safe?"}
  CAP -->|No| STOP
  CAP -->|Yes| ACT["Apply bounded action + durable receipt"]
  ACT --> VER{"Verified effect?"}
  VER -->|No| REC["Reconcile / rollback"]
  VER -->|Yes| TTL["Audit + monitor until TTL"]
  TTL --> REC
  REC --> HEALTH["Check service recovery"]
```

## 5. Which claim is justified?

| Observable | What we can say | What we cannot infer |
|---|---|---|
| A Suricata IDS alert with raw evidence | Signature matched in a scoped event | Host definitely compromised |
| A failed authentication burst | Authentication-abuse indicator exists | Successful privilege escalation |
| A test incident from synthetic seeded data | Test pipeline functions in its declared environment | Real attacker was present |
| An adapter's successful disposable-namespace test | Adapter exercised in that test kernel/network namespace | All enterprise networks supported |
| A cloud/SaaS disconnect | Local delivery failure/offline state should be reported | Entire local sensor network is healthy |
| A rollback receipt + service check | Observed recovery for tested scope | Every production outage is prevented |

Supporting materials: [architecture](ARCHITECTURE.md), [readiness evidence](production-readiness.md), [lab walkthrough](lab-seven-system-test-day.md) and [repository reconciliation](repository-maintenance/README.md).
