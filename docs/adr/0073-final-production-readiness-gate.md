# ADR 0073: Final production-readiness gate

## Status

Accepted.

## Context

Individual subsystems have separate acceptance gates (ADRs 0064-0072). There was
no single place that states, per subsystem, what is proven, by which evidence, in
which environment, and what is not. Without one, "the repository is complete"
and "MON is production-certified" are easy to confuse.

## Decision

1. **SOC operator acceptance.** The console gains only what the acceptance
   scenario genuinely needed: an authenticated-operator indicator (`/api/v1/me`),
   an explicit authentication-required / access-denied state, an incident
   investigation view (evidence, affected assets, identity evidence, investigation
   path, containment capability, response/policy/approval/rollback state, audit
   history) and a fleet view. Every value comes from an existing API; no
   placeholder numbers were added. `e2e/soc` (Playwright, Chromium) runs against
   the real console and the real control plane. The deterministic incident is
   produced by `tools/soc_acceptance_seed.py` through the real fabric-ingest,
   response, site-command and Site Controller executor paths with real nftables
   in a disposable namespace. The browser authenticates with a real signed
   session cookie; authentication is not bypassed. Proven: unauthenticated
   refusal, operator context, incident open, evidence, asset and identity
   evidence, investigation path, containment capability, response (`ROLLED_BACK`),
   policy outcome and approval, rollback result, audit history, and tenant B
   being unreachable from a tenant A session (UI and API).
2. **Bounded load/resource gate.** `tools/load_resource_gate.py` reuses
   `tools/fabric_load_probe.py` in soak mode over TLS with a per-interval
   resource sampler (`tools/resource_sample.py`), records p50/p95/p99, counts,
   process CPU and RSS, stored-versus-offered unique events, then `SIGKILL`s the
   control plane, restarts it and verifies no acknowledged event was lost. It
   asserts correctness only, never a throughput target. Queue depth is reported
   `NOT_APPLICABLE` because ingest is synchronous.
3. **Evidence ledger.** `docs/production-readiness.json` is the source of truth;
   `docs/production-readiness.md` is rendered from it and a test fails if it
   drifts. `src/mon/production_readiness.py` refuses a ledger that references a
   missing evidence file, marks an external item `PROVEN`, drops a mandatory
   `NOT_PROVEN` item, uses an unknown status, or contains a percentage figure.
4. **Final report.** `tools/final_readiness_report.py --report` writes a
   machine-readable report with evidence paths and SHA-256 digests, the required
   gates and (in CI) the latest completed run of each on `main`. It states two
   separate conclusions: `repository_engineering` and
   `external_production_certification`, the latter never complete.

## Honest limits recorded in the ledger

The browser scenario enrolls no sensor, so fleet health is proven only as an
honest empty state; there is no Network Health metric with a documented source and
none was invented; independent verification state is proven in the seeder and E2E
gates but is not shown in the console.

## Consequences

Repository completion is a checkable statement. It is not production
certification: production signing, enterprise appliances, cloud enforcement,
firewalld/ufw combinations, broad OS matrices, PostgreSQL HA, multi-region
disaster recovery, ISP/DDoS integration and real customer networks stay
`NOT_PROVEN` until exercised for real.
