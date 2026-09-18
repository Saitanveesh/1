# ADR 0004: Local site autonomy and at-least-once synchronization

Status: Accepted

## Decision

Each MON site controller has a durable SQLite event outbox. Events are persisted before
local analytics are executed. The local pipeline continues detection, graphing and
incident correlation without a cloud connection.

Synchronization to the SaaS control plane is at-least-once. Event IDs are idempotency
keys, and the control plane acknowledges duplicate replays so the site can safely remove
delivered events from its outbox.

## Failure behavior

- Cloud unavailable: events remain locally queued and local detection continues.
- Partial acknowledgement: only acknowledged events are removed.
- Site-controller restart: queued events remain in SQLite.
- Duplicate sensor delivery: local and central pipelines do not reprocess the same event ID.
- Wrong tenant/site: the site controller rejects the event.

SQLite is intentionally the local durability boundary because a single site controller
must remain useful without requiring a cloud database or Kafka cluster.

## Current limitations

Central control-plane persistence is still in-memory. The next persistence milestone
will add durable tenant state and database migrations. Site-to-cloud authentication,
mTLS identities and signed enrollment are also required before production deployment.
