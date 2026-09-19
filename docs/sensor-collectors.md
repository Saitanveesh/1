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
`mon.sensor_identity`. Automated SaaS enrollment/renewal/revocation is not implemented yet,
so deployment tooling must currently provision these certificates securely.

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
MON_SENSOR_TIMEOUT_SECONDS=10
```

The collector refuses to start if the tenant/site/sensor values do not match its certificate.

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

Collector state is persisted in SQLite under `MON_SENSOR_STATE_DIR`.

A checkpoint advances only after the sensor ingress accepts the batch. Network or server
failure therefore causes safe replay rather than silent loss.

Rotation is tracked by device/inode. If a filename changes to a new inode, MON looks for the
previous inode in sibling files and drains it first. If the prior inode disappears or the
file is truncated below the committed offset, the collector reports a degraded gap and does
not reset automatically.

Rotation policies should retain the previous uncompressed file long enough for the collector
to drain it.

## Security boundary

The mTLS ingress authenticates transport identity. The raw Site Controller sensor API is an
internal loopback boundary and does not independently authenticate remote sensors.

Sensor certificate revocation, automatic renewal, enrollment approval, and fleet health are
not yet implemented. Until that milestone, use short-lived sensor certificates and controlled
certificate provisioning.
