# ADR 0031: Authenticated sensor transport and durable file collectors

## Status
Accepted

## Context

ADR 0030 introduced deterministic Zeek JSON and Suricata EVE normalization at the Site
Controller, but the raw sensor endpoints were intentionally limited to a trusted local
collector boundary.

A caller-supplied `sensor_id` is not an identity. Exposing those endpoints on a network
socket without authenticated transport would allow one sensor to impersonate another and
would weaken tenant/site evidence provenance.

MON also needs real collection processes for the common operational case where Zeek writes
JSON log files and Suricata writes EVE JSON. Collector delivery must survive process crashes,
network outages, log rotation, and duplicate delivery without silently skipping telemetry.

## Decision

MON adds a dedicated mutual-TLS sensor ingress plus durable Zeek and Suricata file
collectors.

### Sensor identity

Sensor client certificates use a SPIFFE-style URI SAN:

`spiffe://mon.local/tenant/<tenant>/site/<site>/sensor/<sensor>`

The sensor certificate:

- is an end-entity certificate;
- requires the TLS client-auth extended key usage;
- is scoped to exactly one tenant, site, and sensor id;
- defaults to 30 days of validity;
- cannot be issued for more than 90 days by the repository issuance helper.

The ingress extracts identity only from the certificate that the TLS stack has already
validated. Request bodies cannot select or override tenant, site, or sensor identity.

The ingress rejects a valid certificate whose tenant/site scope does not match the Site
Controller it fronts.

### Transport boundary

`mon-sensor-ingress` is the network-facing sensor transport.

The TLS server is configured with:

- a server certificate and key;
- the trusted sensor client CA;
- mandatory client-certificate verification.

The ingress accepts raw Zeek and Suricata batches that contain no `sensor_id`. It injects
the certificate-derived sensor id before forwarding the request to the Site Controller's
existing normalization API.

The internal Site Controller forward URL is restricted to loopback HTTP. The production
`mon-site` listener is also restricted to loopback addresses. This means the unauthenticated
internal raw-event API cannot be turned into a remote sensor endpoint through configuration.

Remote sensors must use the mTLS ingress.

### Collector identity binding

The Zeek and Suricata collector processes require:

- tenant id;
- site id;
- sensor id;
- sensor ingress HTTPS URL;
- trusted server CA;
- sensor client certificate and private key.

Before starting, the collector parses its own client certificate and requires the configured
tenant/site/sensor identity to match the certificate SAN.

The HTTPS client uses hostname verification and the configured mTLS client certificate.

### Zeek file collection

`mon-zeek-collector` reads the supported JSON logs from the configured current-log
directory:

- `conn.log`
- `dns.log`
- `http.log`
- `ssl.log`
- `notice.log`
- `weird.log`

Only complete newline-terminated JSON records are eligible for delivery. A partial append at
EOF is left unread until the line is complete.

Missing Zeek log files are not treated as fabricated zero activity; they are reported as
missing sources and retried on later polls.

### Suricata file collection

`mon-suricata-collector` tails the configured `eve.json`.

The collector forwards only event types currently supported by ADR 0030:

- alert
- flow
- dns
- http
- tls

Other valid EVE event types are intentionally filtered and counted in durable diagnostics so
an enabled Suricata `stats` or other logger does not permanently block the collector.

A malformed JSON record or a record missing `event_type` is not skipped. It is a degraded
collector condition and the cursor does not advance beyond that record.

### Durable cursor semantics

Each collector owns a sensor-id-bound SQLite cursor database using WAL and
`synchronous=FULL`.

A source checkpoint contains:

- configured path;
- device id;
- inode;
- byte offset;
- update time;
- failure diagnostics;
- filtered-record count.

The collector reads a batch first, sends it, and advances the durable cursor only after the
mTLS ingress accepts the batch. Delivery failure therefore replays the same records.
ADR 0030 deterministic event ids make that replay safe at the Site Controller.

Records filtered by explicit Suricata type policy can advance the cursor because they are
outside the currently supported MON normalization contract.

### Rotation and truncation

A committed cursor is tied to device/inode, not only a filename.

If the configured filename points to a new inode, the collector scans sibling files for the
previous inode and drains it before transitioning to byte zero of the replacement file.

If the previous inode cannot be located, or the same inode has been truncated below the
committed offset, MON reports a rotation/truncation gap and does not silently reset the
cursor. This prefers visible telemetry uncertainty over hidden data loss.

This design cannot recover data if an external rotation/compression policy destroys the old
inode before the collector drains it. Operators must configure retention/rotation so the
previous file remains available long enough for collection.

### Batch and resource bounds

Collector batches are bounded to at most 1000 records. The normalization layer retains its
1 MiB per-record limit from ADR 0030.

File scans are bounded by the batch size even when Suricata records are filtered, preventing
a single poll from walking an unbounded EVE file.

### Observability

Collector poll state changes and degraded states are emitted through the process logger.
Cursor databases retain source-specific failure counts, last errors, offsets, and filtered
record counts.

The ingress health endpoint itself requires a valid sensor client certificate.

## Certificate lifecycle boundary

This tranche provides certificate issuance primitives and authenticated transport, but it
does not yet provide a SaaS-managed sensor enrollment, revocation, or automatic certificate
rotation workflow.

Sensor certificates must therefore be provisioned through a controlled deployment process.
Short validity reduces but does not replace the need for explicit revocation and rotation.

A later fleet-management tranche should add durable sensor enrollment records, certificate
renewal, revocation status, and sensor health/fleet reporting.

## Failure model

- No client certificate: TLS handshake fails.
- Untrusted/expired client certificate: TLS handshake or identity validation fails.
- Certificate for another tenant/site: HTTP 403.
- Configured collector identity differs from its certificate: fail collector startup.
- Sensor ingress cannot reach loopback Site Controller: return gateway failure; collector
  cursor remains unchanged.
- Sensor ingress rejects a batch: collector cursor remains unchanged.
- Collector restarts after acknowledged delivery: resume from durable byte offset.
- Collector restarts before acknowledgement: replay from the prior offset.
- Partial JSON line: wait for completion without advancing.
- Invalid JSON: degrade and stop at that byte offset.
- File rotates and prior inode still exists: drain old inode, then move to the new file.
- Prior inode disappears or file truncates below checkpoint: degrade; do not silently reset.
- Unsupported Suricata event type: count/filter under the explicit support policy.

## Consequences

- Remote network sensors no longer authenticate by a caller-supplied sensor id.
- Sensor provenance is cryptographically bound to tenant/site/sensor scope.
- The unauthenticated Site Controller API remains a loopback implementation boundary.
- Zeek and Suricata have real restart-safe file collector processes with at-least-once
  delivery.
- Rotation gaps are surfaced instead of hidden.
- Sensor fleet enrollment, revocation, renewal, and health management remain the next
  identity/fleet tranche.
