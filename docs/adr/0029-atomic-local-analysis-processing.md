# ADR 0029: Atomic local analysis processing and delivery staging

## Status
Accepted

## Context

ADR 0028 made local normalized events, assets, findings, and incidents durable and made
detector, telemetry, graph, and correlation state reconstructable after restart.

One crash boundary remained: processing one event performed multiple durable writes. A process
failure after storing the event but before all derived asset/finding/incident writes could
leave an event that looked like a duplicate on restart even though its derived state was
incomplete.

A second race existed between the event-delivery spool and local analysis. The cloud flush
loop could observe an event in the spool while local analysis of that event was still in
progress.

## Decision

MON makes one local event-analysis operation an atomic SQLite unit of work when the pipeline
uses a transactional local store.

### Analysis transaction

`SQLiteSiteAnalysisStore` schema version 2 adds an atomic processing receipt table keyed by
tenant, site, and event id.

For one new event the Security Pipeline:

1. opens a SQLite `BEGIN IMMEDIATE` transaction;
2. stores the normalized event;
3. applies durable asset enrichment;
4. stores any detector findings;
5. stores any correlated incident changes;
6. writes the event processing receipt;
7. commits the transaction.

If any durable write or the final commit fails, SQLite rolls back the complete local
evidence mutation.

Detector, telemetry, attack-graph, and correlation engines are in-memory reconstruction
caches. They may have advanced before a database failure is detected. After a failed
transaction, MON immediately warm-restores those engines from the last committed durable
state before accepting the next event.

A process crash during the transaction leaves no committed event or processing receipt.
A crash after commit leaves both. The receipt is therefore the authoritative durable marker
that local analysis completed.

### Duplicate and uncertain events

An existing event with a processing receipt is an idempotent duplicate.

An existing event without a processing receipt is not treated as successfully processed.
MON raises an explicit pipeline state error and refuses to invent or repeat derived changes.

This fail-closed rule also protects upgrades from the pre-transactional analysis schema.
A version-1 analysis database containing event rows cannot be automatically upgraded because
MON cannot prove those old events completed every derived write. Such a database requires an
explicit rebuild/migration procedure. An empty version-1 database can be upgraded safely.

### Cloud-delivery staging

The local event spool schema version 2 adds:

- `analysis_ready`;
- `analysis_attempts`;
- `analysis_last_error`.

Newly ingested events enter the spool as not analysis-ready. Only after the atomic local
analysis operation succeeds does the Site Controller mark the spool row analysis-ready.

The cloud sender reads only analysis-ready rows.

This creates a recoverable two-database protocol rather than pretending the spool and
analysis databases share one transaction:

- crash after spool insert but before analysis: startup/flush reprocesses the staged row;
- crash during analysis: the analysis transaction rolls back and the staged row remains;
- crash after analysis commit but before the spool ready flag: the processing receipt proves
  analysis completed, replay is recognized as a duplicate, and the spool row is marked ready;
- crash after the ready flag: the event is eligible for ordinary at-least-once cloud delivery.

Version-1 spool rows are migrated with `analysis_ready = 0` so they cannot be uploaded until
the local analysis boundary is reconciled.

### Startup and runtime recovery

The production Site Controller attempts staged-analysis recovery during service composition
and before each cloud flush.

Analysis failures remain in the spool with attempt/error diagnostics. Other already-ready
events may continue to synchronize; the site health remains degraded while analysis-pending
or analysis-error rows exist.

Response execution and TTL recovery remain separate from this analysis path, so an analysis
failure does not authorize or fabricate response state.

## Concurrency

Security Pipeline event processing remains serialized with its process-level lock. The
SQLite analysis transaction additionally holds the local analysis store lock for the unit of
work.

This guarantees one ordered local analysis mutation per Site Controller process. It is not a
distributed event-ordering guarantee across multiple independent Site Controller processes;
production deployment must run a single writer for a given site analysis database.

## Schema migration

Analysis store schema version 1 to 2 is automatic only when no version-1 event rows exist.
Existing version-1 events are intentionally rejected because their completion state is
unknowable.

Event spool schema version 1 to 2 is safe to migrate automatically: existing rows become
analysis-pending and are not cloud-deliverable until reconciled.

## Failure model

- Durable write fails mid-event: roll back event and all derived local state, then restore
  engine memory from committed evidence.
- Commit fails: same rollback/restore behavior.
- Existing event has no processing receipt: fail closed.
- Spool row exists but analysis event does not: process it, then mark ready.
- Spool row exists and analysis processing receipt exists: mark ready without regenerating
  derived state.
- Analysis retry continues to fail: keep the event staged, increment diagnostics, report
  degraded health, and do not upload it.
- Duplicate event id with different payload in either spool or analysis store: reject.
- Cloud unavailable: analysis-ready rows stay buffered and local analysis/recovery continues.

## Consequences

- One local normalized event and its durable asset/finding/incident mutations now commit
  atomically.
- Cloud telemetry cannot outrun local evidence processing.
- Restart recovery distinguishes completed events from uncertain legacy/partial events.
- Random detector/incident identifiers cannot leak from a rolled-back partial transaction;
  retries generate a fresh complete transaction after engine warm restore.
- The remaining scale concern is unbounded retained analysis history and linear warm-restore
  cost. Snapshotting/retention must be designed without deleting evidence required by active
  investigations.
