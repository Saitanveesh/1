# ADR 0005: Durable control-plane persistence

Status: Accepted

## Decision

MON uses PostgreSQL-compatible relational persistence for authoritative control-plane
state: events accepted by the control plane, findings, incidents, assets, enforcement
points, and enforcement bindings.

Database schema changes are managed with Alembic migrations. The application does not
silently create production tables. The development Compose stack applies migrations
before starting the API.

The domain payload is stored as JSON alongside explicit tenant/site/object identity
columns. This preserves strict scope queries while allowing the domain contract to
evolve without tying every API field to a physical SQL column immediately.

## Why PostgreSQL is not the packet warehouse

This database is the transactional/security-state source of truth. High-volume flows,
packet metadata, long-term search, and PCAP references will use a dedicated telemetry
and evidence storage path. Keeping those workloads separate protects incident/policy
state from packet-volume pressure.

## Reliability properties

- Event IDs remain idempotency keys across process restarts.
- Tenant/site scope is part of every persisted object key.
- Incidents and control metadata survive API restarts.
- CI boots a real PostgreSQL service, applies migrations, and validates persistence.
- SQLite remains useful for unit tests and the local site outbox, not as the SaaS database.

## Remaining work

The in-process detector and attack graph state is not yet fully rehydrated from
historical events after control-plane restart. Event streaming and durable analytical
state are separate milestones.
