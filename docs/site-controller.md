# Site Controller service

The supported local service entry point is:

```text
mon-site
```

The process owns the local API plus independent telemetry flush, response recovery, and site
command loops. It persists local delivery and response state under one site state directory.

## Required identity

`MON_TENANT_ID` and `MON_SITE_ID` are required.

`MON_SITE_STATE_DIR` defaults to `/var/lib/mon-site`. The directory contains independent
SQLite databases for event buffering, exact event-fabric delivery, response execution/audit
state, command-result receipts, response updates, and the last synchronized sensor trust
snapshot. These files are bound to
the configured tenant/site and must not be copied between site identities.

The local API listens on `127.0.0.1:8090` by default. `MON_SITE_PORT` may change the
port. `MON_SITE_HOST` must remain a loopback address (`localhost`, `127.0.0.0/8`, or
`::1`); non-loopback bindings are rejected.

## Offline operation

Cloud configuration may be omitted. In that mode MON still accepts local events, runs the
local evidence pipeline, preserves telemetry for later upload, reconciles local response state,
and performs TTL recovery for responses already authorized and represented locally.

Health output reports that the cloud publisher and command channel are not configured. It
does not fabricate cloud connectivity. Analysis-ready telemetry is staged into the durable
fabric outbox and remains there until authenticated cloud delivery resumes.

## Cloud/mTLS operation

Set `MON_SITE_INGRESS_URL` to an HTTPS site-ingress endpoint and configure:

- `MON_SITE_CA_CERT_FILE`
- `MON_SITE_CLIENT_CERT_FILE`
- `MON_SITE_CLIENT_KEY_FILE`
- one of `MON_SITE_BEARER_TOKEN` or `MON_SITE_BEARER_TOKEN_FILE`

The token-file form is preferred for service deployments because it avoids embedding the
service token in command arguments or general configuration files.

`MON_SITE_CLIENT_KEY_PASSWORD` is optional for encrypted private keys.

Plain HTTP is rejected by the production Site Controller configuration.

The production event path uses the durable fabric outbox and sends one exact FabricEnvelope
per HTTPS request. The same site mTLS identity and bearer token used for command/fleet traffic
authenticate event delivery. The legacy EventBatch sender remains a compatibility boundary
but is not the production mon-site event path.

## Loop intervals

Optional settings:

- `MON_SITE_FLUSH_INTERVAL_SECONDS` — default 5
- `MON_SITE_RECOVERY_INTERVAL_SECONDS` — default 5
- `MON_SITE_COMMAND_INTERVAL_SECONDS` — default 2
- `MON_SITE_SENSOR_TRUST_INTERVAL_SECONDS` — default 15
- `MON_SITE_REQUEST_TIMEOUT_SECONDS` — default 10

Values must be positive and no greater than 3600 seconds.

## API

The local service currently exposes:

- `GET /health`
- `POST /api/v1/site/events`
- `POST /api/v1/site/sensors/zeek/batch`
- `POST /api/v1/site/sensors/suricata/batch`
- `POST /api/v1/site/sensors/authorize`
- `POST /api/v1/site/sensors/heartbeat`
- `POST /api/v1/site/sensors/renew`
- `POST /api/v1/site/sensors/trust/sync`
- `POST /api/v1/site/flush`
- `GET /api/v1/site/runtime`

The raw sensor endpoints normalize Zeek JSON and Suricata EVE records into tenant/site-scoped
MON events before they enter the same durable local analysis path used by
`/api/v1/site/events`. A complete raw batch is normalized before the first event is
submitted, so malformed sensor data does not create a partially normalized batch.

Supported Zeek inputs are `conn`, `dns`, `http`, `ssl`, `notice`, and `weird`.
Supported Suricata EVE inputs are `alert`, `flow`, `dns`, `http`, and `tls`.
Unsupported types fail closed rather than becoming generic evidence.

The Site Controller supplies tenant/site scope. These raw endpoints remain an internal
loopback boundary. Remote sensors must use the dedicated `mon-sensor-ingress` mTLS service,
which derives sensor identity from a verified client certificate and injects that identity
before loopback forwarding. See `docs/sensor-collectors.md`.

The production `mon-site` configuration now rejects non-loopback listener addresses so the
unauthenticated internal API cannot be exposed remotely through configuration.

The runtime endpoint reports the last state/error for cloud flush, local recovery, command
polling, and sensor-trust synchronization.

Sensor authorization is evaluated from the durable local trust snapshot, not by a live SaaS
lookup on every event. If SaaS is unavailable, the last known trust snapshot continues to
apply. If no trust snapshot has ever been synchronized, remote sensor authorization fails
closed.

## Enforcement

The service receives an enforcement-adapter registry from deployment code. The default
`mon-site` executable does not silently activate a host firewall adapter.

The repository's nftables implementation intentionally operates only in disposable Linux
network namespaces when its explicit sandbox environment guard is enabled. Do not use that
adapter as a production host-firewall deployment path.

## Current restart boundary

Event delivery, exact fabric-envelope identity, response state, command-result receipts,
response-update receipts, TTL recovery, normalized local events, assets, findings, and
incidents are durable across process restart.

At startup the Site Controller warm-restores detector windows, telemetry windows, attack
graph state, and active correlation pointers from durable evidence. `/health` reports
`local_pipeline_state_persistence: DURABLE_RESTORED` plus restore counts.

Local analysis uses an atomic processing receipt transaction: the normalized event,
asset enrichment, findings, incident mutations, and processing receipt commit together.
Events remain analysis-pending in the delivery spool until that transaction is known complete,
so cloud delivery cannot outrun local evidence processing. ADR 0029 documents the staging and
crash-recovery protocol.

The remaining local scale boundary is retained analysis history and the resulting linear
warm-restore cost. Retention/snapshotting must preserve evidence required by active
investigations rather than silently discarding it.


## Fabric upgrade boundary

The current production Site Controller uses the fabric path documented by ADRs 0034-0036.
A deployment upgrading from the older batch-delivery path should drain its legacy event spool
before switching, unless historical control-plane event state has been explicitly reconciled.

Control-plane migration 0006 intentionally does not invent processing receipts for historical
events. If an old event exists without proof that its complete derived state committed, fabric
redelivery returns an uncertain-state failure instead of acknowledging success.
