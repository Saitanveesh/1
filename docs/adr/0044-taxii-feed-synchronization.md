# ADR 0044: TAXII threat-intelligence feed synchronization

## Status

Accepted

## Context

ADR 0043 added direct STIX 2.1 bundle ingestion and exact-match indicator findings. Operators
also need MON to pull intelligence from remote TAXII 2.1 collections without introducing a
separate indicator parser, storing feed credentials inline, or reporting failed feed sync as
healthy.

This milestone adds a TAXII client only. MON does not expose a TAXII server or publish
intelligence to upstream TAXII collections.

## Decision

MON now has tenant/site-scoped TAXII feed configuration and synchronization state. A feed
defines a source id/name, API root URL, collection id, credential reference, auth mode,
polling interval, sync limits, and TLS/SSRF policy knobs. Durable state tracks the last
successful cursor, last attempt, health, failure class, bounded failure text, retry/backoff,
and last sync counts.

The synchronization path is:

TAXII transport -> TAXII object envelope validation -> existing STIX bundle ingestion ->
existing threat-indicator persistence -> existing evidence-backed matching pipeline.

No second indicator parser or alternate matching table is introduced.

## TAXII 2.1 client boundary

The client supports:

- optional TAXII server discovery against `/taxii2/`;
- configured API root URLs;
- collection validation with collection id and `can_read`;
- `GET collections/{collection_id}/objects/`;
- `Accept: application/taxii+json;version=2.1`;
- TAXII JSON response content-type validation;
- TAXII object envelopes containing STIX objects;
- pagination using `more` and opaque `next`;
- incremental sync using `added_after`.

The client does not implement TAXII write APIs, TAXII server behavior, or feed publication.

## Cursor and pagination semantics

The durable cursor is the UTC start time of the last successful synchronization. It is passed
as TAXII `added_after` on the next run. The cursor is not advanced until all pages fetched for
the run have been successfully committed through the existing STIX ingestion path.

If ingestion succeeds but cursor persistence fails, a later retry may refetch the same objects.
That is intentional: STIX object identity/version handling is idempotent, so retrying is safer
than advancing a cursor before durable commit.

`next` values are treated as opaque strings and replayed exactly. MON fails the sync if
pagination is malformed, if `more` is not boolean, if `more=true` lacks a valid `next`, or if
page/object/byte limits are exceeded.

## Credential handling

TAXII feed objects contain only `credential_ref`; plaintext bearer tokens and HTTP Basic
secrets are resolved through the existing connector-secret vault at synchronization time.

Supported authentication modes are:

- unauthenticated;
- bearer token from connector-secret plaintext;
- HTTP Basic from connector-secret JSON containing `username` and `password`.

Audit records and feed state contain nonsecret metadata only. Authorization headers and
resolved secret values are not recorded.

## HTTP security and SSRF assumptions

HTTPS is required by default. Certificate verification remains enabled by `httpx`. Requests
use explicit connect/read/overall timeouts, bounded response size, bounded page count, and
bounded object count.

MON rejects malformed URLs, embedded URL credentials, unsupported content types, and automatic
credential forwarding across origins. Credential-bearing cross-origin redirects fail closed.

By default, the client resolves configured destinations and rejects loopback, private,
link-local, multicast, reserved, and unspecified addresses. This reduces obvious SSRF risk but
is not claimed as complete SSRF protection against every DNS rebinding or network-topology
case. Deployments should still restrict outbound network access for the MON process.

## Retry, scheduling, and health

Failures are classified as authentication, transport, protocol, parsing, ingestion, or
security failures. Failed syncs preserve the previous successful cursor, set degraded health,
record bounded failure metadata, and schedule exponential backoff with jitter.

The scheduler is intentionally small: it scans configured feeds, starts at most one active sync
per feed, prevents overlap, supports clean shutdown/cancellation, and lets one failing feed
finish independently from others. It does not require Celery, Redis, Kafka, or Kubernetes jobs.

Feeds that have never synchronized remain `NEVER_SYNCED`; failed feeds are `DEGRADED`.
Disabled feeds do not poll and report `DISABLED`.

## Tenant/site isolation

Feed configuration and state include tenant_id and site_id. PostgreSQL persistence uses forced
row-level security under the same tenant/site scope model as events, audit records, connector
secrets, and threat indicators.

## Consequences

- MON can pull TAXII 2.1 collection objects into the existing STIX threat-intelligence path.
- Feed credentials stay in the connector-secret vault.
- Sync restart/retry behavior is idempotent and cursor-safe.
- Remaining limitations include no TAXII server, no TAXII write APIs, no advanced TAXII query
  filtering beyond `added_after`, and no claim of complete SSRF protection without deployment
  egress controls.
