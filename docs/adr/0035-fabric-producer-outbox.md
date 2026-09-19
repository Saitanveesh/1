# ADR 0035: Durable event-fabric producer outbox

## Status

Accepted

## Context

ADR 0034 defined the event-fabric envelope and consumer-side idempotency contract.
A producer still needed a durable boundary that guarantees retries reuse the exact same
envelope instead of rebuilding the message with a new producer timestamp.

The Site Controller already has a durable event spool. That spool protects raw normalized
events and gates cloud delivery on completed local analysis, but it stores SecurityEvent
objects rather than the cross-process fabric envelope. Reconstructing a fabric envelope on
every retry would violate ADR 0034 because produced_at is part of immutable message identity.

## Decision

MON adds a tenant/site-bound SQLite DurableFabricOutbox and integrates it into the
Site Controller as an optional delivery path.

### Exact envelope persistence

After local analysis is complete, the Site Controller stages each SecurityEvent into the
fabric outbox. The first staging operation creates the FabricEnvelope and persists its full
canonical JSON, SHA-256 identity, and producer timestamp.

Later staging attempts for the same event ID return the already-persisted envelope. A caller
cannot accidentally change produced_at on retry.

If the same event ID is reused with different SecurityEvent content, staging fails closed.

### Durability

The outbox uses:

- one tenant/site scope per database;
- SQLite WAL;
- synchronous=FULL;
- finite busy timeout;
- a primary key on event_id;
- durable attempt/error metadata;
- durable delivered and source-reconciled timestamps.

The existing local event spool remains the pre-analysis and local-analysis recovery boundary.
The fabric outbox becomes the cross-process delivery boundary.

### Delivery ordering

A tenant/site is one logical ordering domain.

The Site Controller publishes pending fabric envelopes sequentially in durable creation order.
If one publish fails, later messages are not sent in that flush cycle. This prevents later
messages from overtaking a failed predecessor within the site stream.

Delivery remains at-least-once. A crash after the remote consumer accepts an envelope but
before the local outbox records success causes the exact same envelope to be published again.

### Two-database reconciliation

The local event spool and fabric outbox are separate SQLite databases, so MON does not claim a
single atomic transaction across them.

The success sequence is:

1. persist the exact fabric envelope;
2. publish it;
3. mark the outbox row delivered;
4. remove the corresponding analysis-ready event from the local spool;
5. mark the outbox row source-reconciled.

A delivered outbox row is retained until source reconciliation is recorded.

Crash handling:

- crash before outbox staging: the spool still contains the analysis-ready event and stages it
  later;
- crash after outbox staging but before publish: the exact persisted envelope is retried;
- crash after remote accept but before local delivered mark: exact-envelope redelivery occurs;
- crash after delivered mark but before spool deletion: restart removes the spool event
  without republishing;
- crash after spool deletion but before source-reconciled mark: restart observes the delivered
  outbox receipt, sees no source row is required, and completes reconciliation.

### Receipt compaction

Delivered receipts are compactable only after source_reconciled_at is present and only with an
explicit positive retention window.

This prevents a delivered receipt from disappearing while the source spool can still recreate
the same event. Unreconciled receipts are never compacted automatically.

### Compatibility

The existing EventBatchSender path remains available for tests and compatibility while the
fabric HTTP transport is introduced in the next tranche.

When a fabric outbox is configured, the Site Controller uses it instead of the legacy batch
sender for event delivery.

## Failure model

- wrong tenant/site outbox: startup or staging fails;
- duplicate event with identical content: persisted envelope is reused;
- duplicate event with changed content: fails closed;
- publisher unavailable: pending envelope remains durable and attempt/error state is recorded;
- first envelope fails: later envelopes do not overtake it;
- remote accepts but local process crashes: exact envelope may be redelivered;
- source cleanup crashes: delivered receipt drives deterministic reconciliation;
- compaction requested before source reconciliation: row is retained.

## Consequences

MON now has both sides of the broker-independent at-least-once contract:

- durable exact-envelope producer replay;
- durable idempotent consumer processing.

This still does not justify Kafka/Redpanda by itself. The next tranche should provide the
authenticated HTTP fabric transport and control-plane ingress using the same envelope
unchanged. Broker infrastructure remains gated by measured load and recovery requirements.
