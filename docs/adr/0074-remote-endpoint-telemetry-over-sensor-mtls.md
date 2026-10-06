# ADR 0074: Remote endpoint telemetry uses the sensor mTLS boundary

Status: Accepted

## Context

The Windows and Linux endpoint collectors originally delivered only to the Site Controller loopback API through LocalSiteEventSender. That boundary is safe on one machine, but a victim VM on another physical lab host could not send endpoint evidence without either colocating MON on the victim or exposing the unauthenticated loopback API.

The dedicated sensor ingress already provides the correct remote trust boundary: mutual TLS, certificate-derived tenant/site/sensor identity, local revocation/trust-snapshot authorization, and loopback-only forwarding to mon-site.

## Decision

Remote endpoint collectors may send one normalized SecurityEvent to POST /api/v1/sensors/events on mon-sensor-ingress.

The sender must use HTTPS with a configured server CA, present a sensor client certificate and private key, bind its configured tenant/site/sensor identifiers to every event, reject embedded URL credentials, and ignore environment proxy settings.

The ingress authenticates and authorizes the certificate, validates the complete SecurityEvent schema, requires payload tenant/site/sensor scope to exactly match the verified certificate identity, and forwards only to the Site Controller loopback /api/v1/site/events endpoint.

The raw Site Controller endpoint remains loopback-only.

## Consequences

A remote Windows or Linux victim can contribute endpoint evidence without weakening the Site Controller trust boundary. Existing local deployments continue to use LocalSiteEventSender when no sensor-ingress URL is configured.

Sensor enrollment and certificate distribution are prerequisites for remote endpoint collection. Endpoint event delivery does not replace sensor heartbeat/fleet reporting; those remain separate lifecycle concerns.

Collectors retain their durable local buffers. A network or ingress failure is reported as transport unavailable and the event remains queued for replay.
