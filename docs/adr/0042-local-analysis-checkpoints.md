# ADR 0042: Durable local analysis checkpoints

## Status

Accepted

## Context

ADR 0028 made local analysis evidence durable and restart-restorable by replaying all
retained events. ADR 0029 made one event plus its derived evidence mutations atomic.

That left a scale problem: warm restore cost grew linearly with retained forensic event
history. Deleting old events to make restart faster was rejected because local events,
findings, incidents, assets, and evidence are investigation records, not disposable engine
cache.

## Decision

MON now persists a separate tenant/site-scoped analysis checkpoint in the local analysis
SQLite database. The checkpoint is derived working state only. It does not replace, compact,
or delete forensic evidence.

Checkpoint schema version 1 contains:

- checkpoint metadata: schema version, tenant_id, site_id, checkpoint_id, created_at,
  boundary_observed_at, and boundary_event_id;
- detector state: rule windows, beacon samples, emit cooldowns, and threshold values;
- telemetry state: the bounded operational telemetry window;
- correlation state: active actor-to-incident pointers;
- attack graph working state: graph nodes and edges using the public attack graph snapshot
  model;
- asset-analysis marker: assets remain durable authoritative evidence records, so no mutable
  asset cache is serialized in version 1.

Checkpoint payloads are JSON validated by explicit Pydantic models. Engine internals are
converted into those models rather than serializing Python objects directly.

## Restore algorithm

At Site Controller startup, `SecurityPipeline.restore_scope`:

1. verifies there are no durable events missing processing receipts;
2. reads complete checkpoints for the tenant/site in newest-boundary order;
3. skips incomplete rows, hash-invalid rows, schema-incompatible rows, and payloads that fail
   validation or tenant/site checks;
4. restores the newest valid compatible checkpoint when one exists;
5. replays only events whose `(observed_at, event_id)` are strictly after the checkpoint
   boundary;
6. attaches persisted findings to the graph and rebuilds correlation pointers from persisted
   findings/incidents so persisted evidence remains authoritative;
7. falls back to older valid checkpoints, or to full evidence replay if no compatible
   checkpoint exists.

Restore never fabricates events, findings, assets, incidents, graph edges, telemetry, or
recovery status. If the evidence store itself is inconsistent, restore fails closed as before.

## Write and integrity semantics

Checkpoint rows carry a SHA-256 digest of the JSON payload and a completion flag. A checkpoint
write inserts the row as incomplete and marks it complete only after the payload and digest are
stored inside the same SQLite transaction. Startup only considers complete rows whose digest
matches the payload.

Crashes during checkpoint creation are normal. Incomplete or corrupt rows are ignored and may
be removed by checkpoint maintenance.

## Retention boundary

Checkpoint maintenance may delete:

- incomplete checkpoint rows;
- older complete checkpoint rows beyond the retained checkpoint count.

Checkpoint maintenance must not delete events, findings, incidents, assets, evidence, audit
records, response records, fabric receipts, command receipts, or any other forensic record.

## Security and isolation assumptions

Checkpoints are scoped by tenant_id and site_id and stored in a database already bound to one
tenant/site. Payload validation also verifies nested detector, correlation, and graph scope.

The digest protects against accidental corruption and torn writes. It is not a substitute for
filesystem access control, disk encryption, or a keyed tamper-evident audit chain. A future
design can add signed checkpoints if the local threat model requires malicious local-disk
tamper resistance.

## Consequences

- Ordinary restart no longer needs to replay all retained forensic events.
- Forensic retention remains independent from restore performance.
- Checkpoint restore plus post-boundary replay remains deterministic against full replay for
  the covered engine state.
- Checkpoint schema compatibility is explicit and fail-safe.
- Checkpoint payload size still grows with derived graph/window state. That is bounded by
  detector/telemetry windows and graph aggregation, not by raw retained event count.
