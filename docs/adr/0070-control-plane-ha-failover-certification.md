# ADR 0070: Control-plane HA / multi-instance failover certification

## Status

Accepted.

## Context

Earlier gates proved the lifecycle against a single control-plane process.
Nothing showed that two control-plane processes could share PostgreSQL without
duplicating events, incidents or responses, or survive loss of one instance.

## Decision

Add `tests/test_control_plane_ha.py` and the dedicated workflow
`.github/workflows/control-plane-ha.yml`. Topology, all over real TCP on a
disposable Ubuntu runner:

`client -> nginx (test-only) -> uvicorn mon.api:app A | B -> shared PostgreSQL`

Both instances start from the same migrated schema and the same JWKS file. The
application connects as a non-superuser, NOBYPASSRLS role so RLS is real.
nginx uses bounded passive failover (`max_fails=1 fail_timeout=2s`,
`proxy_next_upstream ... non_idempotent`, two tries). Retrying non-idempotent
requests is acceptable only because the fabric and response paths are
idempotent, which the test asserts.

Proven (measured facts recorded in `control-plane-ha-report.json`):

- both instances share one schema revision and authenticate identically;
- fabric events ingested through A produce a finding and incident visible,
  equally, through B;
- one envelope raced through both instances by eight concurrent requests is
  stored exactly once with exactly one non-duplicate acknowledgement;
- one idempotent response request raced through both instances yields one
  execution and one APPLY_RESPONSE site command;
- response state and the hash-verified audit trail read identically through
  both instances; tenant B cannot read tenant A through either instance;
- `SIGKILL` of instance A under three-thread continuous traffic: zero failed
  attempts, first success after the kill within milliseconds, no acknowledged
  event missing, no duplicate rows; A restarts and rejoins; B can then be lost
  and A serves all state.

## Defect found and fixed

Racing the same event through two instances made both pass the duplicate check
in `SecurityPipeline.process_event`; the loser failed on the `security_events`
primary key and returned HTTP 500. `DatabaseStore` now provides
`scope_lock(tenant, site)`, a per-scope PostgreSQL session advisory lock
(released automatically if its holder dies, bounded by a 20 s lock timeout that
surfaces as `PipelineStateError`/503). It is per tenant/site, not global.
A second instance of the same race existed in `ResponseDispatcher`: two
instances executing the same idempotent request both created the execution and
the loser raised "command_id already exists with different content" (HTTP 500,
duplicate audit). `dispatch` and `rollback` now run under the same per-scope lock,
acquired on a worker thread so waiting never blocks the event loop.
Regression: the HA gate plus `tests/test_pipeline_scope_lock.py`.

## Known limitation (reported, not hidden)

Detector, graph and correlator windows are per-instance memory. A burst split
across instances can fail to reach a detector threshold on either. The gate
records `split_burst_triggered_detection` from a measured run and reports
`PARTIALLY_PROVEN` if it does not fire. Shared analysis state would require a
larger design change and is out of scope. Set-derived list fields such as
`entities` serialize in per-process hash order; they are compared
order-insensitively.

## NOT_PROVEN

PostgreSQL automatic failover, multi-region replication, Kubernetes,
distributed consensus, zero-downtime database migration. This is
application-layer HA only.
