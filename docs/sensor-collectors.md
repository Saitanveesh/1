# Authenticated network sensor collection

MON supports a dedicated mTLS sensor-ingress process plus file collectors for Zeek JSON logs
and Suricata EVE JSON.

## Process layout

A typical site runs:

1. `mon-site` on loopback, for example `127.0.0.1:8090`;
2. `mon-sensor-ingress` on the sensor-facing network, for example TCP 9443;
3. one or more `mon-zeek-collector` or `mon-suricata-collector` processes.

Collectors authenticate with client certificates. The sensor ingress derives
tenant/site/sensor identity from the verified certificate and forwards only to the Site
Controller loopback API.

Do not expose `mon-site` directly to remote sensors.

## Sensor certificate identity

The client certificate URI SAN must be:

```text
spiffe://mon.local/tenant/<tenant>/site/<site>/sensor/<sensor-id>
```

Certificates require TLS client-auth EKU.

The repository provides certificate-generation/issuance primitives in
`mon.sensor_identity` and the control plane now provides one-time enrollment, renewal,
revocation, site trust synchronization, and fleet-health APIs. Initial private-key generation
still happens on the sensor side.

The current collectors do not yet replace their active certificate/key files automatically.
Use the renewal protocol with a new CSR and activate the returned credentials through a
crash-safe deployment mechanism.

## Sensor ingress configuration

Required:

```text
MON_TENANT_ID
MON_SITE_ID
MON_SENSOR_INGRESS_SERVER_CERT_FILE
MON_SENSOR_INGRESS_SERVER_KEY_FILE
MON_SENSOR_CA_CERT_FILE
```

Optional:

```text
MON_SENSOR_INGRESS_SERVER_KEY_PASSWORD
MON_SENSOR_INGRESS_HOST=0.0.0.0
MON_SENSOR_INGRESS_PORT=9443
MON_SENSOR_INTERNAL_SITE_URL=http://127.0.0.1:8090
MON_SENSOR_INGRESS_TIMEOUT_SECONDS=10
```

`MON_SENSOR_INTERNAL_SITE_URL` must be loopback HTTP. A non-loopback target is rejected.

Start:

```text
mon-sensor-ingress
```

## Collector TLS configuration

Both collectors require:

```text
MON_TENANT_ID
MON_SITE_ID
MON_SENSOR_ID
MON_SENSOR_INGRESS_URL=https://sensor-ingress.example:9443
MON_SENSOR_SERVER_CA_CERT_FILE=/etc/mon/server-ca.pem
MON_SENSOR_CLIENT_CERT_FILE=/etc/mon/sensor.pem
MON_SENSOR_CLIENT_KEY_FILE=/etc/mon/sensor-key.pem
```

Optional:

```text
MON_SENSOR_CLIENT_KEY_PASSWORD
MON_SENSOR_STATE_DIR=/var/lib/mon-sensor
MON_SENSOR_BATCH_SIZE=100
MON_SENSOR_POLL_INTERVAL_SECONDS=1
MON_SENSOR_HEARTBEAT_INTERVAL_SECONDS=30
MON_SENSOR_TIMEOUT_SECONDS=10
```

The collector refuses to start if the tenant/site/sensor values do not match its certificate.

Collectors report `READY`/`DEGRADED` fleet heartbeat state through the authenticated
sensor ingress. The control plane uses server receipt time for last-seen calculations and
marks the sensor stale by default after 90 seconds without a heartbeat.

## Zeek

Configure Zeek to write JSON logs. The collector expects a directory containing the current
supported log files and defaults to:

```text
MON_ZEEK_LOG_DIR=/opt/zeek/logs/current
```

Start:

```text
mon-zeek-collector
```

The collector watches `conn.log`, `dns.log`, `http.log`, `ssl.log`, `notice.log`,
and `weird.log`. Missing files are retried later rather than interpreted as zero activity.

Only complete newline-terminated JSON records are sent.

## Suricata

The collector defaults to:

```text
MON_SURICATA_EVE_FILE=/var/log/suricata/eve.json
```

Start:

```text
mon-suricata-collector
```

Supported EVE types are `alert`, `flow`, `dns`, `http`, and `tls`. Other valid EVE
types are filtered and counted in cursor diagnostics. Malformed JSON or a record without
`event_type` is treated as an error and is not skipped.

## Cursor and rotation behavior

Collector state is persisted in SQLite under `MON_SENSOR_STATE_DIR`. The cursor database
is bound to the configured tenant, site, and sensor identity and cannot be reused under a
different scope.

A checkpoint advances only after the sensor ingress accepts the batch. Network or server
failure therefore causes safe replay rather than silent loss.

Rotation is tracked by device/inode. If a filename changes to a new inode, MON looks for the
previous inode in sibling files and drains it first. If the prior inode disappears or the
file is truncated below the committed offset, the collector reports a degraded gap and does
not reset automatically.

Rotation policies should retain the previous uncompressed file long enough for the collector
to drain it.

## Managed enrollment and revocation

Create a one-time sensor enrollment token through the control-plane
`/api/v1/sensor-enrollment-tokens` API, generate the sensor private key/CSR locally, then
complete enrollment through `/api/v1/sensor-enrollment`.

A certificate renewal request travels from the authenticated sensor ingress through the
loopback Site Controller and site mTLS channel. The old certificate remains accepted for a
bounded one-hour overlap by default, allowing the new credential to be activated without an
instant cutover.

Revocation is synchronized to each Site Controller as a durable local trust snapshot. Sensor
ingress checks the exact certificate fingerprint against that local snapshot on every
application request. If cloud connectivity fails, the last known trust snapshot remains in
force. A revocation created during the outage cannot take effect at that site until trust
synchronization resumes.

The default Site Controller trust-sync interval is 15 seconds and is configurable with:

```text
MON_SITE_SENSOR_TRUST_INTERVAL_SECONDS=15
```

## Security boundary

The mTLS ingress validates the X.509 client certificate and SPIFFE-style scope, then enforces
the durable local fingerprint allow set. The raw Site Controller sensor API remains an
internal loopback boundary.

Revocation is application-layer authorization backed by the local trust snapshot; this is not
a CRL/OCSP implementation. Automatic crash-safe replacement of the collectors' on-disk
certificate/key pair remains a follow-up item.
