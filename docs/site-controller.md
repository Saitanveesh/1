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
SQLite databases for event buffering, response execution/audit state, command-result receipts,
and response updates. These files are bound to the configured tenant/site and must not be
copied between site identities.

The local API listens on `127.0.0.1:8090` by default. Use `MON_SITE_HOST` and
`MON_SITE_PORT` to change the listener.

## Offline operation

Cloud configuration may be omitted. In that mode MON still accepts local events, runs the
local evidence pipeline, preserves telemetry for later upload, reconciles local response state,
and performs TTL recovery for responses already authorized and represented locally.

Health output reports that the cloud sender and command channel are not configured. It does
not fabricate cloud connectivity.

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

## Loop intervals

Optional settings:

- `MON_SITE_FLUSH_INTERVAL_SECONDS` — default 5
- `MON_SITE_RECOVERY_INTERVAL_SECONDS` — default 5
- `MON_SITE_COMMAND_INTERVAL_SECONDS` — default 2
- `MON_SITE_REQUEST_TIMEOUT_SECONDS` — default 10

Values must be positive and no greater than 3600 seconds.

## API

The local service currently exposes:

- `GET /health`
- `POST /api/v1/site/events`
- `POST /api/v1/site/flush`
- `GET /api/v1/site/runtime`

The runtime endpoint reports the last state/error for cloud flush, local recovery, and command
poll loops.

## Enforcement

The service receives an enforcement-adapter registry from deployment code. The default
`mon-site` executable does not silently activate a host firewall adapter.

The repository's nftables implementation intentionally operates only in disposable Linux
network namespaces when its explicit sandbox environment guard is enabled. Do not use that
adapter as a production host-firewall deployment path.

## Current restart boundary

Event delivery, response state, command-result receipts, response-update receipts, and TTL
recovery are durable across process restart.

Detector windows, local incident correlation state, telemetry windows, and in-memory attack
graph state are not yet restart-persistent. `/health` exposes this boundary as
`local_pipeline_state_persistence: MEMORY_ONLY`.
