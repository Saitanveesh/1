# ADR 0037: Durable control-plane event-fabric ingress

## Status

Accepted

## Context

ADR 0034 defined the typed event-fabric envelope and consumer idempotency contract.
ADR 0035 added the durable Site Controller producer outbox.
ADR 0036 added the authenticated HTTPS publisher boundary.

The remaining gap was control-plane acceptance. A 2xx response from a transport proxy is not
enough evidence that the exact envelope was durably claimed and its derived event state
committed. MON needs explicit recovery semantics for lost acknowledgements, duplicate
delivery, changed-content collisions, and crashes during domain processing.

## Decision

MON adds a verified site-mTLS fabric route and a durable control-plane receipt lifecycle.

### Transport path

The production telemetry path is:

Site Controller fabric outbox
  -> POST /api/v1/site/fabric/events over site mTLS
  -> mTLS ingress verifies certificate tenant/site
  -> POST /api/v1/fabric/events on the internal control plane
  -> durable exact-envelope claim
  -> transactional SecurityPipeline processing
  -> durable processing receipt
  -> fabric receipt PROCESSED
  -> exact event ID + SHA-256 acknowledgement

The external ingress forwards the original canonical envelope bytes. It does not rebuild the
message or assign a new producer timestamp.

### Site identity and authorization

The mTLS gateway parses the FabricEnvelope and requires its tenant_id and site_id to match the
verified site certificate SPIFFE identity before forwarding.

The existing site bearer token is still required. The internal control-plane API independently
applies INGEST authorization for the same tenant/site scope.

### Exact acknowledgement

A successful control-plane response includes the event ID, duplicate state, and SHA-256 of
the exact canonical envelope.

The site publisher validates event ID and digest before its durable outbox can mark delivery
successful. A 2xx response carrying a mismatched or malformed acknowledgement is a delivery
failure and remains retryable.

### Durable fabric claim

The control plane persists a fabric receipt keyed by tenant/site/event ID before domain
processing. The initial status is PENDING and stores the exact canonical envelope JSON,
SHA-256 digest, and receive time.

Once an event ID is claimed, a different envelope using the same event ID is rejected even if
the first processing attempt failed. Exact redelivery is allowed.

After event processing is proven complete, the receipt becomes PROCESSED and records
processed_at. Exact redelivery of a PROCESSED receipt returns duplicate=true without
rerunning the pipeline.

### Atomic control-plane event processing

DatabaseStore now implements TransactionalPipelineStore. Migration 0006 adds
event_processing_receipts and fabric_receipts.

For a new event, the SQL transaction includes the event row, asset updates, finding updates,
incident updates, and event-processing receipt. If any durable step fails, the transaction
rolls back and SecurityPipeline restores its in-memory detector/correlation/graph state from
the last committed evidence boundary.

The fabric PENDING claim is intentionally outside the domain transaction. This preserves the
exact message identity across a failed processing attempt while still allowing the same
envelope to retry.

### Crash recovery

- before the PENDING claim commits: producer retries normally;
- after PENDING but before processing: exact-envelope retry processes the event;
- processing transaction fails: event/derived state rolls back, PENDING remains;
- processing commits but fabric completion does not: retry observes the durable event plus
  event-processing receipt, completes the fabric receipt, and returns duplicate=true;
- PROCESSED commits but HTTP acknowledgement is lost: exact redelivery returns the same
  digest and duplicate=true;
- same event ID with different envelope content: conflict, fail closed.

### Historical migration boundary

Migration 0006 does not backfill event_processing_receipts for historical security_events.
MON cannot prove that a pre-migration event committed every derived asset/finding/incident
mutation, so it does not invent a completed processing receipt.

If a fabric delivery encounters an existing event without a processing receipt, the control
plane returns an uncertain-state failure. Operators upgrading from the legacy batch path
should drain the old site spool before cutover or perform an explicit reconciliation/rebuild.

### Legacy event routes

/api/v1/events and /api/v1/events/batch remain for compatibility. Because DatabaseStore now
exposes the transactional processing contract, new events through those routes also receive
atomic processing receipts. An existing historical event without a receipt fails explicitly
instead of being silently treated as a successful duplicate.

### Broker boundary

This milestone still does not introduce Kafka or Redpanda. The HTTP path proves authentication,
message identity, durable claims, processing atomicity, and retry semantics first.

Broker adoption remains gated by ADR 0026 load measurements: throughput, queue lag, end-to-end
latency, restart recovery, storage growth, and concurrent tenant isolation.

## Consequences

MON now has a complete broker-independent at-least-once telemetry path from the durable site
producer outbox to durable control-plane processing.

The system can distinguish new processing, exact duplicate delivery, changed-message
collision, and historical/partial processing uncertainty without fabricating success.
