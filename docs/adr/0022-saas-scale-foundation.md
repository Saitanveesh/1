# ADR 0022: SaaS scale foundation

Status: Accepted

## Context

MON now has tenant/site-scoped APIs, durable site command delivery, site-local execution, result replay protection, and bounded receipt retention. The next stage is scaling the control plane without weakening tenant isolation or making local protection depend on SaaS availability.

A single application process and transactional database are useful for the current implementation, but they must not become implicit ownership boundaries for telemetry, live delivery, or site command execution. Scaling by simply adding replicas would otherwise create duplicate work, unbounded fan-out, and cross-tenant failure domains.

## Decision

MON will scale around explicit tenant/site partition keys and separate control-plane concerns from high-volume telemetry concerns.

### Transactional control plane

PostgreSQL remains the system of record for tenants, sites, identities, policy, incidents, response state, command state, and audit metadata. Every tenant-owned record and query must retain `tenant_id`; site-owned records also retain `site_id`. Repository methods remain scope-explicit rather than relying on ambient process state.

Application replicas are stateless with respect to durable product state. In-memory structures may be caches or connection registries only; they cannot be the sole copy of a command, response, incident, or audit transition.

### Partition ownership

Durable asynchronous work is partitioned by `(tenant_id, site_id)` whenever ordering matters. A single site stream has one logical ordering domain. Work for unrelated sites may execute concurrently. Consumers must be idempotent because delivery is at-least-once.

No global queue consumer may infer tenant or site from payload contents that are not authenticated/enveloped. The transport envelope carries the scope used for authorization and routing.

### Telemetry path

High-volume normalized telemetry is not forced indefinitely through PostgreSQL. PostgreSQL stores control-plane metadata and references; a dedicated telemetry/search store may be introduced behind an adapter when measured load justifies it. The first supported production candidate is ClickHouse for append-heavy analytical telemetry. OpenSearch is optional and must have a concrete search requirement before adoption.

Raw packet retention remains external/evidence-reference based; MON does not duplicate packet payloads into transactional rows.

### Event transport

The event-fabric boundary is Kafka-compatible so a production deployment can use Redpanda or Kafka without coupling domain code to a broker client. Broker adoption must preserve the existing synchronous/in-process path for tests and small deployments through an adapter interface.

Events require a stable event ID, schema version, tenant ID, site ID, observed timestamp, source, and payload. Consumers deduplicate by event ID within their durable effect boundary.

### Live operator delivery

Operator updates remain push-based. API replicas publish scoped change notifications to the event fabric; WebSocket/SSE gateways subscribe only to scopes authorized for each connection. There is no periodic 2–3 second refresh loop as a scaling mechanism.

Backpressure is explicit: slow clients may be disconnected and required to resynchronize from durable APIs. The server must not fabricate snapshots or silently drop security state while reporting the connection healthy.

### Site autonomy

Site controllers remain independently durable for command receipts/results and local response execution. SaaS replicas do not acquire site-local enforcement privileges. Cloud loss may delay centralized visibility but must not disable already-authorized local recovery/TTL behavior.

### Isolation and secrets

Tenant/site authorization remains enforced at the API and repository boundaries. Production PostgreSQL row-level security is a defense-in-depth target, not a replacement for application scoping; it will be introduced only with transaction-scoped tenant context and dedicated migration/integration tests.

Connector credentials are referenced by secret identifiers. They are not placed in telemetry events, browser payloads, audit detail, or general database JSON blobs.

### Scale gates

New infrastructure is justified by measurements rather than projected vanity scale. Before enabling a broker or analytical store in production, MON must have load tests that record throughput, queue lag, end-to-end event latency, storage growth, recovery after consumer restart, and tenant-isolation behavior under concurrent load.

## Consequences

- Horizontal API scaling does not change the security ownership model.
- Tenant/site scope becomes the routing and ordering key across distributed components.
- At-least-once delivery is assumed; idempotency is mandatory.
- PostgreSQL remains authoritative for control state while telemetry can scale independently.
- Push delivery remains immediate but gains an explicit backpressure/resync contract.
- Redpanda/Kafka and ClickHouse are architectural candidates, not mandatory dependencies in small deployments.
- The next implementation slices are a typed event-fabric envelope/adapter, durable consumer idempotency tests, then measured broker/load integration. PostgreSQL RLS follows as a separate defense-in-depth change with dedicated integration coverage.
