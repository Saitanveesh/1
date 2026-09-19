# ADR 0028: Durable local analysis state and deterministic warm restore

## Status
Accepted

## Context

ADR 0027 introduced a production Site Controller process with durable event delivery,
response execution, response reporting, and TTL recovery. The local evidence pipeline still
kept events, assets, findings, incidents, detector windows, correlation pointers, telemetry
windows, and attack-graph state only in process memory.

That meant a Site Controller restart could preserve containment safety while losing local
investigation continuity. A restarted detector could also miss a multi-event pattern whose
first observations occurred before the restart.

Serializing arbitrary Python engine internals was rejected because it would create an
unstable, implementation-specific persistence format.

## Decision

MON separates durable evidence objects from reconstructable engine state.

A new `PipelineStore` contract contains only the persistence operations required by the
evidence pipeline. The production Site Controller uses a site-scoped
`SQLiteSiteAnalysisStore` that persists:

- normalized security events;
- assets derived from evidence;
- findings;
- incidents.

The database is permanently bound to one `tenant_id` and `site_id`, uses SQLite WAL,
`synchronous=FULL`, foreign-key enforcement, and a bounded busy timeout. Event and finding
identifier collisions with different content fail closed. Assets and incidents are upserted
because those objects are intentionally enriched over time.

## Warm restore

In-memory engines are reconstructed from durable evidence rather than from Python object
serialization.

At Site Controller startup, `SecurityPipeline.restore_scope`:

1. resets detector, graph, correlation, and telemetry engine memory;
2. replays durable events through telemetry, attack-graph observation, and detector window
   logic;
3. discards detector findings generated during replay because persisted findings are
   authoritative;
4. attaches persisted findings to the rebuilt graph;
5. reconstructs active correlation pointers from persisted open/investigating incidents and
   their persisted findings.

Assets are not re-observed during restore, preventing counters and observations from being
double-counted.

The production Site Controller reports the persistence mode as `DURABLE_RESTORED` and
exposes restore counts in health output.

## Concurrency

A Security Pipeline instance serializes reset, restore, and event-processing state
transitions with a re-entrant lock. Individual engines may still use their own finer-grained
locks, but graph/correlation state is not allowed to race across concurrent local ingestion
requests.

This is an in-process ordering boundary, not a distributed ordering guarantee.

## Event history

The local analysis database currently retains its event history until an explicit retention
policy is introduced. MON does not silently delete local analysis history merely to bound
storage.

This is intentionally conservative. A later retention design must preserve the evidence
needed for incident investigation and define what portion of the local attack graph can be
reconstructed after compaction.

## Crash-consistency boundary

This ADR makes evidence objects durable and restart-restorable, but it does not claim that
an event and every derived asset/finding/incident mutation are one SQLite transaction.

The current pipeline stores the event and derived objects in multiple writes. A process
failure inside that sequence can therefore leave a partially processed durable event.
Because event IDs are idempotency keys, blindly replaying a partially persisted event could
either skip missing derived work or double-count mutable asset state if implemented
naively.

MON must not hide this boundary. ADR 0029 subsequently closes it with an atomic
analysis transaction, durable processing receipt, and analysis-gated event spool. This ADR
remains the decision record for durable evidence and deterministic warm restore.

## Failure model

- Analysis database opened under another tenant/site: fail startup.
- Event ID reused with different payload: reject.
- Finding ID reused with different payload: reject.
- Restart with valid durable state: rebuild detector/telemetry/graph/correlation memory before
  serving as fully restored.
- Duplicate event after successful processing: return duplicate without creating new derived
  state.
- Missing persisted finding referenced by an incident during restore: do not invent it; skip
  that correlation pointer.
- Very large retained history: restore cost grows with retained events; this is visible
  technical debt until retention/snapshotting is explicitly designed.

## Consequences

- Local assets, findings, incidents, and event history survive Site Controller restart.
- Multi-event detector windows can continue across restart after warm restore.
- Local attack-graph and correlation continuity can be rebuilt from evidence.
- The pipeline dependency is narrower than the full SaaS control-plane store.
- Python internal data structures are not used as a persistence format.
- Transactional processing of one event into all derived local state is provided by ADR
  0029; retained-history growth and restore cost remain separate scale concerns.
