# ADR 0030: Typed event-fabric envelope and durable consumer idempotency

## Status
Accepted

## Context
ADR 0026 defines the SaaS scale boundary around `(tenant_id, site_id)` and requires at-least-once delivery with idempotent consumers before a broker is introduced. The repository did not yet have a concrete cross-process message contract or a durable consumer receipt primitive.

## Decision
MON uses a versioned `FabricEnvelope` for events that cross a process or broker boundary. Every envelope carries an immutable event ID, tenant ID, site ID, event type, schema version, source occurrence time, producer time, and payload. Both timestamps must be timezone-aware.

The broker partition key is exactly `tenant_id:site_id`. Consumers must reject envelopes outside their configured tenant/site scope rather than routing them opportunistically.

`DurableFabricInbox` provides the first consumer-side at-least-once boundary. It stores a durable receipt in SQLite using WAL and `synchronous=FULL`. The handler and receipt are committed in one local transaction. A redelivery of the same event ID and same immutable envelope is acknowledged without rerunning the handler. Reuse of an event ID with changed scope, type, schema version, or payload fails closed as an identity collision.

Handler failure rolls back the receipt and any derived writes made through the supplied SQLite connection. External side effects are explicitly outside this atomic boundary and require their own idempotency protocol.

## Consequences
This creates a broker-independent contract that can later be adapted to Kafka/Redpanda without changing MON's identity, partitioning, or duplicate semantics. It does not introduce a broker, fabricate throughput targets, or claim exactly-once delivery.

The SQLite inbox is suitable for local and integration use. A horizontally scaled control-plane consumer must use an equivalent durable receipt in its authoritative datastore so competing workers share the same idempotency boundary.

## Validation
Regression tests cover partition identity, timezone validation, duplicate suppression across restart, transaction rollback, tenant/site isolation, and conflicting event-ID reuse.
