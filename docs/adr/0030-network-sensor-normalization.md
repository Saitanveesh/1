# ADR 0030: Network sensor normalization boundary

## Status
Accepted

## Context

MON needs network telemetry from mature engines such as Zeek and Suricata, but the rest of the
system must not depend directly on either engine's vendor-specific JSON schema.

Raw sensor records also cannot be copied blindly into MON events. Different sensor versions
represent timestamps, DNS transactions, packet counters, flow identifiers, and application
metadata differently. Treating missing fields as zero or inferring network direction without
site topology would create false evidence.

The Site Controller already provides a durable, atomic local event-processing boundary. The
sensor layer therefore needs a normalization boundary in front of that pipeline.

## Decision

MON adds explicit Zeek JSON and Suricata EVE normalizers.

The normalizers produce the existing typed `SecurityEvent` model. Tenant and site scope are
taken from the Site Controller, not from raw sensor input.

### Supported Zeek records

The initial Zeek adapter accepts JSON records from:

- `conn.log`;
- `dns.log`;
- `http.log`;
- `ssl.log`;
- `notice.log`;
- `weird.log`.

The adapter accepts both flattened Zeek JSON connection keys such as `id.orig_h` and a
nested `id` object for compatibility with controlled collector transformations.

For `conn.log`, MON preserves originator/responder addresses and ports, protocol, UID,
service, connection state, duration, packet/byte counters, and connection history when
present.

Aggregate packet and byte values are emitted only when both originator and responder
measurements are present. A missing side is not treated as zero.

TCP SYN/ACK observations are derived only from documented Zeek connection-history symbols;
MON does not otherwise infer packet flags.

Zeek DNS logging is transaction-oriented around the connection originator asking the
responder. The normalized category is therefore `dns.query`, while response metadata such
as `rcode_name` remains attached to that transaction.

### Supported Suricata records

The initial Suricata EVE adapter accepts:

- `alert`;
- `flow`;
- `dns`;
- `http`;
- `tls`.

Common EVE fields such as flow id, transaction id, tuple, application protocol, Community ID,
interface, and packet-capture references are preserved when supplied.

Suricata alert records normalize to `suricata.alert` and preserve signature id, signature
text, severity, category, action, and generator metadata required by MON's existing IDS
signature detector.

Flow records normalize to `network.connection`. Bidirectional packet/byte totals are
calculated only when both directional counters exist.

Suricata DNS request/query records normalize to `dns.query`; response/answer records
normalize to `dns.response`. Records without an explicit request/response type use
`dns.transaction`. This prevents DNS responses from being counted as source query-rate
activity.

Both Suricata DNS v3 `queries[]` and the older top-level `rrname`/`rrtype` representation
are accepted without inventing missing values.

When EVE supplies both `pcap_filename` and `pcap_cnt`, the normalized evidence reference
points to that packet location. Otherwise the Suricata flow id is used when available.

### Deterministic replay identity

Normalized event ids are deterministic UUIDv5 values derived from:

- sensor engine;
- tenant id;
- site id;
- configured sensor id;
- raw record type;
- SHA-256 of a canonical JSON representation of the raw record.

Evidence ids are also deterministic from the normalized event identity and evidence
reference.

This supports at-least-once collector delivery without creating duplicate MON evidence.
Changing tenant, site, sensor identity, record type, or raw content changes the event id.

### Raw sensor ingestion

The local Site Controller API exposes batch endpoints for Zeek and Suricata raw JSON.

A complete batch is normalized before any event is submitted to the local analysis pipeline.
A malformed or unsupported record therefore prevents a partially normalized batch.

After normalization, each event is processed through the existing Site Controller ingestion
path, including durable spool staging, atomic local analysis, duplicate detection, and later
cloud delivery.

The batch itself is not one cross-event transaction. Each normalized event retains the
per-event atomicity defined by ADR 0029.

## Evidence rules

Normalization is descriptive. It does not assert compromise, malicious intent, or attack
success.

Missing telemetry remains missing. In particular MON does not synthesize:

- packet or byte counts;
- TCP flags;
- internal/external/east-west direction;
- asset identity;
- threat confidence beyond the provenance confidence of the sensor record.

Network direction requires site topology/address-space context and is intentionally left
unset by these generic sensor normalizers.

Suricata signature matches are preserved as IDS evidence. Downstream detection may create a
finding, but that finding remains a signature-match observation rather than independent
proof of compromise.

## Sensor identity boundary

The production Site Controller binds tenant and site identity locally. Raw sensor requests
may provide a `sensor_id`, but in this tranche that value is an assertion from the local
collector boundary, not a cryptographically authenticated remote-sensor identity.

The Site Controller listens on loopback by default. Deployments that accept remote sensor
traffic require a separate authenticated sensor enrollment/transport design before exposing
these endpoints beyond a trusted local collector boundary.

MON must not treat a caller-supplied sensor id as proof of sensor identity.

## Unsupported records

Unsupported Zeek log types and Suricata EVE event types fail closed with a normalization
error. They are not silently converted into generic events.

Additional types such as Suricata anomaly, ARP, file information, stats, and other
application protocols can be added only when MON has a defined schema and detection or
investigation requirement for them.

## Failure model

- Invalid or timezone-free timestamp: reject.
- Invalid IP address: reject.
- Unsupported log/event type: reject.
- Non-finite/non-JSON canonical record content: reject.
- Missing optional measurement: omit the normalized measurement.
- Duplicate raw record from the same sensor/scope: produce the same deterministic event id.
- Same raw record from another sensor or scope: produce a different event id.
- Malformed member in a raw batch: reject normalization before local event mutation.
- Local pipeline failure after normalization: retain the per-event durability/recovery
  behavior defined by ADR 0029.

## Consequences

- Zeek and Suricata are adapters into MON rather than architectural dependencies.
- Existing MON detection can consume real IDS signatures, DNS names, TCP observations, and
  measured flow volume without vendor-specific parsing in the detector.
- Raw telemetry replay is idempotent at the normalized event boundary.
- Packet references can be carried forward when Suricata provides them.
- Generic normalizers do not guess network trust direction.
- Authenticated remote sensor enrollment and production file/socket collector processes
  remain separate implementation tranches.
