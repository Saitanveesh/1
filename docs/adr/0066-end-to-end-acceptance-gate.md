# ADR 0066: End-to-end acceptance gate

## Status

Accepted.

## Context

MON has extensive unit and focused integration test coverage per subsystem (detection,
correlation, investigation, response orchestration, enforcement adapters, PostgreSQL RLS,
Site Controller durability, backup/restore), but nothing exercised the full
`DISCOVER -> DETECT -> CORRELATE -> TRACE -> CONTAIN -> VERIFY -> RECOVER` lifecycle across
real components in one run. This is not a feature milestone: it adds no new product capability
and only fixes genuine integration defects the acceptance test itself exposes.

## Decision

### Scenario

`tests/test_e2e_acceptance.py` drives one deterministic scenario: eight synthetic SSH
authentication-failure `EndpointTelemetryEvent`s from the same source IP against one asset,
normalized through the real `mon.endpoint.normalize_endpoint_event()` path, which the existing
`endpoint-auth-failure-pressure` detector (`mon.detection`, threshold 8 within 300s) is already
built to recognize. No attack conclusion is fabricated: the finding, incident, and subsequent
containment are all produced by MON's real detection/correlation/response code, not injected
directly into a store.

### Infrastructure

The test only runs with real disposable infrastructure and skips (never fabricates a pass)
otherwise:

- a real PostgreSQL database (`MON_TEST_DATABASE_URL`) backing the control plane's
  `DatabaseStore`, including row-level security;
- Linux, `MON_ENABLE_ENDPOINT_NFTABLES_ENFORCEMENT=1`, and a disposable network namespace
  (`MON_TEST_NETNS`) for real `nft`/`ip netns` containment via
  `LinuxNftablesEndpointAdapter` (added in the prior enforcement-adapter milestone).

Two boundaries are intentionally not real infrastructure, because they cannot safely exist in
CI: the site<->control-plane HTTP/mTLS transport is replaced by FastAPI's `TestClient` (the
same in-process ASGI transport every other API test in this repository already uses instead of
a live server), and a genuine process crash mid-execution is simulated by directly writing a
durable `EXECUTING` response-execution record rather than actually killing the test process --
both are standard, narrowly-scoped test techniques, not a mock of the pipeline itself.

### Proven lifecycle stages

All nineteen `DISCOVER -> ... -> RECOVER` stages listed in the milestone are exercised against
real code:

1. **DISCOVER (1-5):** synthetic telemetry -> `normalize_endpoint_event()` -> the site's durable
   `SQLiteEventSpool`/`DurableFabricOutbox` -> `ingest_fabric_envelope()` into the control
   plane's real `DatabaseStore` + `SecurityPipeline` (the same function
   `test_postgres_fabric_receipt_survives_restart_and_deduplicates` already exercises).
2. **DETECT/CORRELATE/TRACE (6-10):** the real `DetectionEngine`, `CorrelationEngine`,
   `AssetEngine`, `IdentityProcessEngine`, and `AttackGraphEngine` produce one finding, one
   incident with IDENTITY evidence, a resolvable asset and identity, and an investigation graph
   (via the real `/api/v1/incidents/{id}/investigation` endpoint) containing the asset node
   reachable from the incident.
3. **CONTAIN/VERIFY (11-16):** `/api/v1/responses/plan` and `/api/v1/responses/execute` (real
   `ResponseOrchestrator`/`ResponseDispatcher`) select the registered `FIREWALL` enforcement
   point, record a policy decision, and dispatch a durable `SiteCommand`; the site pulls it via
   `/api/v1/site-commands/pending`, applies it through `SiteResponseExecutor` against the real
   nftables adapter in the disposable namespace, and an independent `adapter.verify()` call
   (not the apply path's own return value) reports `PRESENT`.
4. **RECOVER (17-19):** an explicit rollback dispatched through
   `/api/v1/responses/{id}/rollback` is executed the same way, an independent `verify()` call
   reports `ABSENT`, and the control plane's audit trail (`/api/v1/audit`) and
   `ResponseExecution` both show `ROLLED_BACK` honestly after the site posts its result back.

### Sub-gates

- **Tenant isolation:** Tenant B's principal is denied the incident investigation (404, not a
  raw error), does not see Tenant A's response execution in a scoped list, is refused rollback
  of Tenant A's execution (409, because `DatabaseStore.get_response_execution` scoped to Tenant
  B finds nothing), and a cross-tenant query is denied at the auth layer (403) -- all through
  production-scoped API/store paths, plus one direct unscoped-raw-SQL check against the real
  PostgreSQL RLS policy (mirroring `test_postgres_rls_blocks_unscoped_raw_access`).
- **Offline/restart:** an event is queued into the real `DurableFabricOutbox` while "delivery is
  unavailable" (simply not yet delivered), the SQLite connection is closed and reopened
  (simulating a Site Controller restart), delivery resumes and the event reaches the control
  plane, and replaying the same envelope a second time is proven to be a no-op duplicate rather
  than a second event. A second, narrower proof re-executes the already-`APPLIED` containment
  command and confirms it does not create a second nftables rule.
- **Response failure:** a deliberately-failing adapter and a directly-written `EXECUTING`
  execution (simulating an interrupted apply) are reconciled through the real
  `SiteResponseExecutor.reconcile_execution()` boundary; the outcome is `FAILED` (never
  fabricated success), durably persisted, with an observable `VERIFY`/`ABSENT` audit entry.
- **Backup/restore:** reuses the existing tooling only -- `mon.site_state_snapshot`
  (snapshot/restore of the site's SQLite state, all seven databases present) and
  `mon.control_plane_backup` (`pg_dump`/`pg_restore` into a freshly created disposable
  PostgreSQL database) -- and reopens the restored state through the real MON store classes to
  confirm the incident, audit records, queued events, and the rolled-back response execution
  actually survived.

### Report

`e2e-acceptance-report.json` (uploaded as a CI artifact even on failure) records only measured
facts: scenario/tenant/site IDs, a `PROVEN`/`NOT_PROVEN` status with duration per stage (never
fabricated on failure -- a stage that raises is recorded `NOT_PROVEN` with the real exception
before the test itself still fails), evidence/incident/execution IDs, enforcement verification
states before and after rollback, and the isolation/restart/backup-restore sub-results. No
confidence or health value is invented anywhere in the report.

### CI

A dedicated workflow, `.github/workflows/e2e-acceptance.yml`, separate from the general `ci.yml`
workflow, runs a real PostgreSQL service container, installs `iproute2`/`nftables`/
`postgresql-client`, creates one disposable network namespace (cleaned up in a trap that runs
even on failure, never touching the runner's own host firewall), and runs only this one test
file under a strict job- and step-level timeout.

## Limitations

- This is an acceptance gate for one scenario, not a certification that MON is production-ready
  or that every detector/correlation path behaves identically for other event shapes.
- The site<->control-plane transport itself (mTLS handshake, real network partition/retry
  behavior) is not exercised here; that is covered separately by `test_mtls_ingress.py` and
  `test_fabric_ingress.py`, not duplicated in this gate.
- A real process crash is simulated by directly writing durable state, not by actually killing
  the process; this proves the reconciliation logic, not process-supervisor behavior.
- The nftables containment path is certified only in a disposable network namespace, per ADR
  0063's existing limitations -- this gate does not newly certify arbitrary production hosts.
