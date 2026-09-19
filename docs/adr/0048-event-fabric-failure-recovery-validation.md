# ADR 0048: Event-fabric failure-injection and recovery validation

## Status

Accepted.

## Context

The current event fabric moves tenant/site-scoped security events from a local
site controller to the control plane with at-least-once delivery. The sender
uses a durable exact-envelope outbox, and the receiver uses durable fabric
receipts plus transactional pipeline processing receipts. Previous milestones
defined these mechanisms individually. This milestone adds deterministic
failure-injection coverage that proves the current behavior under common
interruption modes without adding a broker or weakening forensic retention.

## Decision

MON validates the current event-fabric recovery contract with local deterministic
tests that exercise the real sender outbox, site spool, fabric ingress, pipeline
store, and load-probe runner boundaries.

The tested contract is:

- fabric envelopes are replayed exactly as originally persisted;
- a failed publish attempt stops later events in the same tenant/site ordering
  domain from overtaking the failed predecessor;
- ambiguous delivery, such as a lost acknowledgement after receiver processing,
  is recovered by replaying the same envelope and relying on receiver-side
  idempotent receipts;
- a pending receiver claim after interruption is not considered healthy until
  the event is processed and the receipt is completed;
- an event that exists without a durable pipeline processing receipt is
  explicitly uncertain and is not silently reported as recovered;
- a database interruption before the receiver claim is written returns failure
  and does not fabricate an acknowledgement;
- reopening the site spool and outbox delivers queued events after controller
  restart;
- failures in one tenant/site queue do not block another tenant/site queue;
- compaction is limited to reconciled sender-side derived delivery records and
  does not delete forensic events or receiver receipts;
- load/soak evidence can record a failed interval and later converge when the
  same caller-supplied canonical corpus is replayed.

## Failure semantics

Recovery is reported as healthy only when the durable queues and receipts
converge. A restarted process alone is not enough. The site controller reports
`DEGRADED` when publish attempts fail and `OFFLINE` when no fabric publisher is
configured. It reports `SYNCED` only after pending outbox entries are delivered,
the local source spool is reconciled, and local analysis recovery has no failed
events.

The producer outbox currently records attempts and the last error. It bounds
retry work to one attempt per failed predecessor per flush and preserves ordering
by stopping after the first failed envelope. It does not yet implement a
time-based exponential backoff scheduler; deployment scheduling must avoid tight
external flush loops.

The receiver first writes an exact-envelope fabric receipt. If domain processing
fails after that claim, the pending receipt prevents another envelope from
claiming the same event ID and allows exact replay. If the event is present but
the transactional processing receipt is absent, MON raises an uncertainty error
instead of treating the event as safely recovered.

## Security and data-integrity assumptions

Tenant and site IDs remain first-class scope fields in envelopes, spools,
outboxes, receipts, events, findings, and incidents. Scope-bound local stores
reject mismatched tenant/site state, and regression coverage verifies that a
failed queue for one scope does not block a different scope.

The tests use synthetic MON events and local stores. They are intended to prove
deterministic software recovery semantics, not production throughput,
high-availability failover, arbitrary network partition behavior, or disaster
recovery across independent control-plane regions.

## Retention boundary

Forensic evidence remains durable. Event-fabric maintenance may compact only
obsolete sender-side restore material after source reconciliation. It must not
delete security events, findings, incidents, evidence, fabric receiver receipts,
or audit records.

## Consequences

This milestone improves confidence in local recovery and CI regression coverage
for the existing event fabric. It intentionally does not introduce Kafka,
Redpanda, ClickHouse, OpenSearch, or another runtime dependency. Future work may
add scheduled retry backoff, broker-backed transport, broader partition testing,
and multi-node control-plane failover validation.
