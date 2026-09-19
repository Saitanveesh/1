# ADR 0036: Authenticated HTTP event-fabric ingress

## Status

Accepted

## Context

ADR 0034 defined the typed event-fabric envelope and consumer idempotency contract.
ADR 0035 added a durable Site Controller producer outbox so retries preserve the exact
envelope.

The remaining production boundary was transport and control-plane acceptance. Sending the
outbox back through the legacy EventBatch endpoint would discard the envelope's immutable
producer identity and would not provide a durable control-plane claim for the exact message.

MON also needs to distinguish three crash states:

1. the envelope never reached the control plane;
2. the control plane received the exact envelope but domain processing did not complete;
3. domain processing completed but the HTTP acknowledgement was lost.

Those states must not be collapsed into fabricated success.

## Decision

MON adds an authenticated HTTPS fabric publisher, an mTLS site-ingress route, and a durable
control-plane fabric-receipt lifecycle.

### Transport path

Site Controller durable fabric outbox
  -> HTTPS + site mTLS
  -> mon-mTLS-site-ingress
  -> internal control-plane /api/v1/fabric/events
  -> durable exact-envelope claim
  -> SecurityPipeline
  -> durable processing receipt
  -> fabric receipt PROCESSED
  -> exact digest acknowledgement

The Site Controller sends the canonical FabricEnvelope JSON unchanged.

The external site ingress derives tenant/site identity from the TLS client certificate and
rejects any envelope whose outer tenant/site scope does not match that verified identity.
It also requires the existing site service authorization token before forwarding the raw
envelope bytes to the internal control plane.

The control-plane API independently enforces the authenticated principal's INGEST permission
for the envelope tenant/site.

### HTTP acknowledgement

A successful response includes event ID, accepted=true, duplicate state, and SHA-256 of the
exact canonical envelope. The Site Controller validates both event ID and digest before
marking its local outbox row delivered. A syntactically successful response for a different
envelope is treated as a transport failure.

### Durable exact-envelope claim

The control plane stores a fabric receipt keyed by tenant/site/event ID. The first valid
envelope creates a PENDING claim containing the exact canonical envelope JSON, canonical
SHA-256, receive time, and status.

The claim is persisted before domain processing begins. A later request using the same event
ID but different envelope content fails as a collision even if the first processing attempt
failed.

After domain processing is proven complete, the receipt becomes PROCESSED and receives a
processed timestamp. Exact redelivery of a PROCESSED envelope is acknowledged as a duplicate
without rerunning the pipeline.

### Atomic control-plane event processing

PostgreSQL gains an event-processing receipt table. DatabaseStore now implements the same
transactional pipeline contract used by the durable local Site Controller store.

For a newly received event the pipeline transaction contains the normalized event row, asset
mutation, finding mutations, incident mutations, and event-processing receipt. If any step
fails, the transaction rolls back. The in-memory detector/graph/correlation state is restored
from the last committed durable state by the existing SecurityPipeline failure path.

The fabric claim is intentionally separate from the domain transaction. A failed domain
transaction therefore leaves a PENDING exact-envelope claim and no committed event. Retrying
the same envelope can safely retry processing, while a different envelope with the same event
ID remains blocked.

### Crash recovery

- crash before PENDING claim commit: producer retries and creates the claim;
- crash after PENDING claim but before event processing: exact-envelope retry runs processing;
- event transaction fails: event and derived mutations roll back, PENDING claim remains;
- event transaction commits but crash occurs before fabric receipt completion: retry sees the
  event plus its processing receipt, marks the fabric claim PROCESSED, and acknowledges a
  duplicate without rerunning processing;
- PROCESSED receipt commits but HTTP acknowledgement is lost: producer redelivers the exact
  envelope and receives an idempotent duplicate acknowledgement;
- same event ID arrives with changed envelope content after the claim: conflict, fail closed.

### Historical migration boundary

Migration 0006 creates event-processing receipts but does not backfill them for historical
security_events.

MON cannot prove that an event written before this atomic boundary completed every derived
asset/finding/incident mutation, so automatically marking those rows processed would invent
evidence about transaction completion.

If a fabric envelope references a historical event that exists without an event-processing
receipt, the control plane returns an explicit uncertain-state failure instead of
acknowledging it.

Deployments upgrading from the legacy batch transport must therefore drain the old Site
Controller event spool before switching to the fabric path, or perform an explicit
operator-reviewed reconciliation/rebuild of historical event state. This repository does not
silently backfill that uncertainty.

### Legacy route

The legacy /api/v1/events and /api/v1/events/batch routes remain for migration, compatibility,
and direct API clients.

Once DatabaseStore exposes the transactional processing contract, new events arriving through
those routes also receive atomic processing receipts. If an old PostgreSQL event exists
without a processing receipt, duplicate delivery fails with service-unavailable state rather
than being treated as successfully processed.

The production Site Controller service now uses the fabric HTTP publisher and durable fabric
outbox rather than the legacy batch sender.

### Broker boundary

This milestone still does not introduce Kafka or Redpanda. The HTTP adapter proves the
envelope, authentication, durable claim, retry, and consumer semantics without adding broker
infrastructure. It sends one envelope per request and is not claimed as the eventual
high-throughput transport.

ADR 0026 still requires measured throughput, queue lag, latency, restart recovery, storage
growth, and tenant-isolation load tests before enabling a broker in production.

## Security properties

- site mTLS identity constrains tenant/site scope before the control-plane API;
- bearer authorization remains required and is independently scope checked;
- outer routing identity cannot smuggle an inner SecurityEvent from another site or sensor
  because deserialization validates event ID, scope, source, and observed time;
- exact-envelope digest is confirmed end to end before the Site Controller advances delivery;
- changed-content event-ID reuse fails closed.

## Consequences

MON now has a complete broker-independent at-least-once path from a durable Site Controller
producer to durable control-plane processing.

The control plane can distinguish exact duplicate delivery, changed-message collision,
processing uncertainty, and new processing.

The next scaling milestone can focus on measured transport throughput and analytical telemetry
storage rather than redefining message identity or recovery semantics.
