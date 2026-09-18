# ADR 0009: Dedicated mTLS site-ingestion gateway

Status: Accepted

## Decision

Site-controller traffic enters MON through a dedicated mutual-TLS gateway rather than
through arbitrary client-certificate headers on the operator API.

The gateway:

1. requires a TLS client certificate signed by the MON site CA;
2. reads the verified peer certificate directly from the TLS transport;
3. requires clientAuth extended key usage;
4. extracts exactly one MON SPIFFE tenant/site identity from the SAN;
5. validates that every event in the batch has the same tenant/site scope;
6. requires the site service bearer token as an independent application credential; and
7. forwards the batch only to the internal control-plane endpoint.

The control plane then performs its normal JWT/site authorization and event processing,
so mTLS and application authorization are independent checks.

## Live updates

The gateway forwards into the existing control-plane ingestion path. Findings, incidents
and graph changes therefore continue to publish through the WebSocket push channel
without introducing a separate delayed analytics path.

## Deployment boundary

The internal control-plane address used by the gateway must not be exposed as the public
site-ingestion endpoint. Production network policy should allow site ingestion only to
the mTLS gateway, and gateway-to-control-plane traffic only on the protected service
network.

The application never trusts public X-Forwarded-Client-Cert style headers.
