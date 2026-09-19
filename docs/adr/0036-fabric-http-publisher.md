# ADR 0036: Authenticated HTTP event-fabric publisher

## Status

Accepted

## Context

ADR 0034 defines the immutable fabric envelope and ADR 0035 persists that exact envelope before delivery. The Site Controller still needs a concrete network publisher. Introducing Kafka or Redpanda before measured load just moves the reliability boundary without evidence that a broker is required.

## Decision

MON adds an HTTPS event-fabric publisher that implements the existing `FabricPublisher` protocol.

The publisher sends the already-persisted `FabricEnvelope` to `/api/v1/site/fabric/events` as canonical JSON. It does not rebuild the envelope, change `produced_at`, assign a new event ID, batch unrelated site streams, or mark delivery successful itself.

Authentication uses the existing site service bearer credential and supports the existing site mTLS SSL context. Ambient proxy configuration is disabled so site telemetry cannot be silently redirected through workstation or process proxy settings.

Plain HTTP is rejected for production construction. Test transports may use an in-process `httpx` transport while retaining an HTTPS base URL.

A non-success HTTP status or transport failure is surfaced to the durable producer outbox. The outbox remains responsible for retry, ordering, attempt diagnostics, and delivered/source-reconciled state.

## Scope and isolation

The publisher does not accept tenant or site arguments separate from the envelope. Scope remains part of the immutable envelope. The receiving mTLS ingress must derive tenant/site from the verified site certificate and reject an envelope whose scope differs before forwarding it to a control-plane consumer.

That receiving endpoint and its durable control-plane consumer receipt are a separate change. Until they are merged, this publisher is a transport primitive and must not be configured as the production Site Controller fabric destination.

## Failure model

- missing bearer credential: construction fails;
- plaintext production URL: construction fails;
- TLS/connection failure: publish raises and the durable outbox retains the envelope;
- HTTP rejection: publish raises and the durable outbox retains the envelope;
- retry after failure: the caller resends the same persisted canonical envelope.

## Consequences

This creates the concrete site-side network boundary without inventing broker capacity or weakening at-least-once semantics. Production activation remains gated on the authenticated receiver, certificate-scope enforcement, durable consumer idempotency, and end-to-end integration tests.
