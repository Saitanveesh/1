# ADR 0032: Managed sensor identity lifecycle and fleet health

## Status
Accepted

## Context

ADR 0031 cryptographically bound remote sensor traffic to a tenant, site, and sensor
identity, but certificate provisioning remained an external deployment responsibility.
There was no durable sensor registry, no renewal/revocation lifecycle, no SaaS fleet health,
and no way for the local sensor ingress to reject a certificate that was still valid at the
X.509 layer after an operator revoked that sensor.

MON must preserve two properties at the same time:

1. revocation decisions must reach the sensor enforcement boundary;
2. already-known local trust decisions must keep working while SaaS connectivity is lost.

Calling the SaaS control plane synchronously for every sensor event would violate local
autonomy. Treating CA validity alone as authorization would make revocation ineffective until
certificate expiry.

## Decision

MON adds a durable sensor fleet lifecycle in the control plane, a durable site-local trust
snapshot, periodic trust synchronization, request-level authorization at the sensor mTLS
ingress, and collector fleet heartbeats.

### Durable sensor registry

The control plane stores three sensor lifecycle object types:

- one-time sensor enrollment tokens;
- sensor fleet records keyed by tenant/site/sensor;
- sensor certificate identities.

Sensor identity status is one of:

- `ACTIVE`
- `RETIRING`
- `REVOKED`

The registry is tenant/site scoped in the repository contract and PostgreSQL schema.
Certificate fingerprints are unique.

### Enrollment

An operator with `CONFIGURE` permission creates a one-time enrollment token scoped to one
tenant, site, and sensor id.

The sensor private key remains outside the control plane. A CSR is submitted with the
one-time token to `/api/v1/sensor-enrollment`.

Token consumption, sensor-record creation, and first identity persistence are committed as
one store operation. A consumed or expired token cannot be reused.

A sensor id that is already enrolled cannot receive a second enrollment token. Existing
sensors use renewal rather than reenrollment.

The sensor CA is configured independently through:

- `MON_SENSOR_CA_CERT_FILE`
- `MON_SENSOR_CA_KEY_FILE`
- optional `MON_SENSOR_CA_KEY_PASSWORD`

### Renewal

A currently accepted sensor certificate can submit a new CSR through the existing sensor
mTLS ingress.

The path is:

```text
sensor
  -> sensor mTLS ingress
  -> loopback Site Controller
  -> site mTLS ingress
  -> control plane
```

The sensor ingress derives the current certificate fingerprint from TLS. The request body
cannot choose that fingerprint.

The control plane requires the fingerprint to belong to the same tenant/site/sensor and to a
non-revoked sensor.

A successful renewal:

1. creates a new `ACTIVE` identity;
2. moves the old identity to `RETIRING`;
3. gives the old identity a bounded overlap window;
4. makes the new identity current for the sensor;
5. returns the updated site trust snapshot with the new certificate.

The default overlap window is one hour and is never allowed to extend beyond the old
certificate's expiry.

Renewal uses a compare-and-swap store transition. Concurrent renewal/revocation cannot
silently resurrect a revoked sensor.

If a renewal response is lost, retrying the same old certificate and the same CSR returns the
already-created successor certificate. A retry with a different CSR key fails rather than
silently issuing another successor.

This tranche implements the renewal protocol and certificate issuance path. The current
Zeek/Suricata collector processes do **not** yet replace their on-disk key/certificate
automatically. Automated credential activation must use a crash-safe generation switch and
is intentionally left for a follow-up tranche rather than performing unsafe two-file
replacement.

### Revocation

An operator with `CONFIGURE` permission can revoke a sensor with an explicit reason.

Revocation is committed under the same lifecycle lock used by renewal and heartbeat updates.
The sensor record and all identities known for that sensor become revoked atomically.

A revoked sensor cannot renew and cannot update fleet health.

### Site-local trust snapshot

The control plane exposes a site-scoped allow set containing only identities that are
currently acceptable:

- active, unexpired identities;
- retiring identities whose overlap deadline has not passed;
- never identities belonging to a revoked sensor.

The production Site Controller synchronizes this snapshot periodically. The default sync
interval is 15 seconds.

The local snapshot is stored in SQLite with:

- one tenant/site bound per database;
- WAL;
- `synchronous=FULL`;
- generated and received timestamps;
- the accepted certificate fingerprint set.

An older snapshot cannot replace a newer one. Reusing the same generation timestamp with
different content is rejected as equivocation.

When cloud synchronization fails, the last durable snapshot remains available. MON therefore
continues enforcing the last known sensor trust state locally.

A revocation made while the site is disconnected cannot reach that site until connectivity
returns. MON does not claim otherwise. Under healthy connectivity the propagation delay is
bounded primarily by the configured trust-sync interval plus request latency.

### Sensor ingress authorization

The TLS layer still validates the sensor certificate chain, validity period, client-auth EKU,
and SPIFFE-style tenant/site/sensor identity.

After TLS verification, every application request also asks the loopback Site Controller
whether the exact sensor id + certificate fingerprint is present in the durable local trust
snapshot.

If the local trust service is unavailable, the ingress fails closed. If the certificate is
not in the allow set, the ingress returns a forbidden response.

This request-level check means an already-established TLS connection does not bypass a newly
synchronized revocation.

### Fleet heartbeat

Zeek and Suricata collectors submit a fleet heartbeat on a bounded interval. The default is
30 seconds.

A heartbeat contains:

- collector state: `READY` or `DEGRADED`;
- collector kind;
- MON version;
- observation time;
- error detail when degraded.

Tenant, site, sensor id, and certificate fingerprint are injected by the authenticated sensor
transport path rather than trusted from the collector request body.

The control plane records server receipt time as `last_seen_at`. Sensor clock time is kept
separately. An out-of-order heartbeat can refresh connectivity last-seen time but cannot
overwrite a newer health observation.

Heartbeats more than five minutes in the future are rejected.

### Fleet state

The fleet API derives, rather than fabricates, sensor state.

The default stale threshold is 90 seconds:

- `REVOKED`: sensor lifecycle is revoked;
- `STALE`: no heartbeat exists or server last-seen age exceeds the threshold;
- `DEGRADED`: a recent heartbeat explicitly reported degraded;
- `READY`: a recent heartbeat explicitly reported ready.

The API exposes the heartbeat age and stale threshold supporting the state calculation.

## Failure model

- Enrollment token expired/used: enrollment fails.
- Existing sensor id reenrollment attempt: fails; renewal is required.
- Sensor CA unavailable: enrollment/renewal returns service unavailable.
- Renewal with an unknown, expired, or revoked current certificate: fails.
- Duplicate renewal using the same CSR: returns the persisted successor.
- Duplicate renewal using a different CSR after transition: fails.
- Renewal racing revocation: lifecycle locking prevents revoked state from being overwritten.
- Heartbeat racing revocation: lifecycle locking prevents health updates from resurrecting
  revoked state.
- SaaS trust sync fails: last durable local snapshot remains authoritative.
- Site has never received a trust snapshot: remote sensor authorization fails closed.
- Sensor ingress cannot reach the loopback trust service: request fails closed.
- Revocation occurs while site is offline: site continues using its last known snapshot until
  synchronization resumes.
- Heartbeat cannot reach SaaS: fleet state naturally becomes stale; MON does not synthesize a
  healthy value.
- Sensor clock sends heartbeat more than five minutes in the future: heartbeat is rejected.

## Security boundaries and follow-up

The trust snapshot is authenticated in transit by the existing site mTLS channel and scoped
service authorization. It is not a CRL or OCSP implementation.

The next credential-management tranche should add crash-safe automatic on-disk certificate
activation for collectors and proactive renewal scheduling before certificate expiry.

Fleet UI work should consume the explicit fleet-state fields and heartbeat age rather than
inventing an independent score.
