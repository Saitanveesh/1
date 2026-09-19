# ADR 0034: Typed event-fabric contract and durable consumer idempotency

## Status

Accepted

## Context

ADR 0026 defines the SaaS scale foundation: durable asynchronous work is partitioned by
`(tenant_id, site_id)`, delivery is at-least-once, and consumers must be idempotent.
The repository already has durable local analysis receipts for the Site Controller, but it
did not have a reusable cross-process message contract or a broker-independent consumer
idempotency primitive.

Introducing Kafka or Redpanda before defining these semantics would make broker behavior an
accidental architecture contract. MON needs stable event identity, scope, versioning, and
duplicate behavior first.

## Decision

MON adds a typed `FabricEnvelope`, a broker-independent publisher protocol, a normalized
`SecurityEvent` adapter, and a site-scoped durable inbox.

This ADR does not introduce a broker.

### Envelope contract

Every fabric envelope carries:

- stable `event_id`;
- authenticated/routing `tenant_id` and `site_id`;
- `event_type`;
- integer `schema_version`;
- source observation time;
- producer/envelope creation time;
- explicit `source`;
- typed JSON-compatible payload.

Tenant and site IDs use the same bounded string model used by the rest of MON. They are not
redefined as UUIDs.

Both timestamps must be timezone-aware.

The logical partition key is the tuple `(tenant_id, site_id)`. For transports that require
bytes, MON emits a canonical JSON two-element array. This avoids delimiter ambiguity when a
tenant or site ID itself contains punctuation.

### Immutable message identity

A fabric message is canonicalized with sorted JSON keys, compact separators, UTF-8, and
non-finite JSON numbers rejected. SHA-256 of that canonical representation is used as the
consumer collision fingerprint.

The canonical identity includes all envelope fields, including both timestamps and source.

Therefore a producer retry must resend the exact persisted envelope. Recreating the same
event ID with a new `produced_at` is a conflicting message, not a valid retry.

This is intentional: a stable logical event ID cannot be allowed to identify changing
message content.

### Normalized SecurityEvent adapter

The first domain adapter wraps `SecurityEvent` as
`telemetry.normalized.security_event` schema version 1.

The outer envelope reuses the normalized event's event ID, tenant/site scope, observed time,
and sensor ID as source. The complete typed event remains in the payload.

Deserialization validates that outer routing identity matches the payload:

- event ID;
- tenant ID;
- site ID;
- sensor/source identity;
- observed timestamp.

A mismatch fails closed rather than letting an outer envelope route a different inner event.

The adapter requires `produced_at` from the caller. It does not silently call the clock on
every retry. Once a producer creates an envelope, the producer is responsible for persisting
or otherwise reusing that exact envelope for at-least-once delivery.

### Durable consumer inbox

`DurableFabricInbox` is a site-scoped SQLite consumer idempotency primitive.

It uses:

- one tenant/site binding per database;
- WAL;
- `synchronous=FULL`;
- finite busy timeout;
- `BEGIN IMMEDIATE`;
- canonical full-envelope SHA-256 plus canonical envelope JSON in the receipt.

The handler executes in the same SQLite transaction as the receipt insert. If the handler
raises, both receipt and local writes performed through the supplied connection roll back.
The same envelope can then be retried.

If the same event ID is redelivered with the exact same envelope, the handler is not rerun.
If the same event ID is reused with different envelope content, processing fails as an
identity collision.

A process lock serializes calls through one inbox object; SQLite transaction locking remains
the cross-process coordination primitive.

### External effects are not exactly-once

The inbox only makes effects performed in the supplied SQLite transaction atomic with the
receipt.

It does not make firewall actions, HTTP calls, emails, broker publications, or other external
side effects exactly-once. Any such handler must use its own durable idempotency/outbox
protocol.

MON must not describe this as exactly-once event processing.

### Broker adapter boundary

`FabricPublisher` is intentionally broker-independent. A later Kafka/Redpanda adapter must
publish the typed envelope unchanged and use the envelope's tenant/site partition key.

Small deployments and tests are not required to run a broker.

Before a production broker is enabled, ADR 0026 still requires measured load gates including
throughput, queue lag, end-to-end latency, restart recovery, storage growth, and concurrent
tenant-isolation tests.

## Failure model

- naive timestamp: envelope validation fails;
- wrong tenant/site inbox: delivery fails before handler execution;
- duplicate exact envelope: acknowledged without rerunning handler;
- same event ID with changed type/schema/timestamp/source/payload: collision, fail closed;
- handler exception: local mutation and receipt roll back together;
- process restart after committed receipt: duplicate remains suppressed;
- inbox database reopened under another tenant/site: startup fails;
- retry envelope recreated with a new producer timestamp: collision; producer must reuse the
  original envelope;
- handler performs an external effect then crashes before receipt commit: the external effect
  may repeat on retry unless that effect implements its own idempotency protocol.

## Consequences

MON now has broker-independent event identity and consumer semantics that can be carried into
Kafka/Redpanda without redefining tenant routing or duplicate behavior.

This is a contract/foundation slice. Existing synchronous control-plane and Site Controller
pipelines are not rerouted through a fake in-memory broker merely to claim event-fabric
adoption.

The next event-fabric tranche should add a durable producer outbox and transport adapter,
then broker/load integration only when measurements justify the infrastructure.
