# ADR 0067: Networked mTLS restart acceptance gate

## Status

Accepted.

## Context

ADR 0066 added an end-to-end lifecycle acceptance gate, but explicitly did not
prove four boundaries: a real Site Controller to Control Plane network
connection over mutual TLS, real network outage/reconnect behavior, actual Site
Controller process termination/restart, or command/result recovery across a
process boundary.

## Decision

Add a separate Linux-only acceptance workflow,
`.github/workflows/networked-restart-e2e.yml`, and a focused test,
`tests/test_networked_restart_e2e.py`.

The gate starts three real loopback services:

- the Control Plane API through `uvicorn mon.api:app`;
- the mTLS site ingress through `python -m mon.mtls_ingress`;
- the production Site Controller service through `python -m mon.site_service`.

The test generates an ephemeral CA, server certificate, valid Site Controller
client certificate, wrong-CA client certificate, and wrong-scope client
certificate. The valid client certificate contains the existing MON SPIFFE
identity form:

`spiffe://mon.local/tenant/<tenant_id>/site/<site_id>`

The Site Controller uses `HttpFabricPublisher` and `HttpSiteCommandClient`
against the real HTTPS/mTLS ingress. The ingress forwards to the Control Plane
over loopback HTTP, and the Control Plane persists into PostgreSQL.

The gate proves:

- trusted client certificates succeed;
- missing client certificates fail at the TLS/ingress boundary;
- wrong CA certificates fail;
- wrong tenant/site certificate scope is rejected;
- bearer authentication is still required in addition to mTLS;
- a real locally queued event reaches the Control Plane through mTLS exactly
  once and produces a matching fabric receipt;
- a real ingress outage leaves the durable outbox queued/degraded with a
  bounded error instead of reporting fake health;
- reconnect retries the queued event and keeps the Control Plane event count at
  one logical event;
- a graceful Site Controller process restart reuses the same local state
  directory;
- a hard process restart after command execution preserves command result
  receipt state;
- a normal Control Plane rollback command reaches the restarted Site Controller
  over mTLS, removes the disposable nftables rule, reports back, and leaves an
  audit trail.

The workflow uses PostgreSQL 17 plus PostgreSQL 17 client tools, temporary
directories, ephemeral certificates, loopback sockets, and a disposable Linux
network namespace. The namespace is cleaned up even on failure. The test writes
`networked-restart-acceptance-report.json` with measured stage status and no
private-key, bearer-token, or certificate material.

## Implementation note

`mon.site_service` now has a narrow opt-in environment hook for the existing
`DisposableNftablesAdapter`:

- `MON_SITE_DISPOSABLE_NETNS`
- `MON_SITE_DISPOSABLE_NFTABLES_VENDOR`

This exists so the production Site Controller subprocess can exercise the same
CI-safe adapter used by the acceptance gates. It is still restricted by the
adapter's Linux, namespace-name, and `MON_ENABLE_DISPOSABLE_NETNS_ENFORCEMENT=1`
guards.

## Failure semantics

Any failed stage is recorded as `NOT_PROVEN` and the pytest test still fails.
The report is uploaded even on failure. The gate never converts missing
infrastructure, TLS failure, command delivery failure, or process restart
failure into a healthy result.

## Limitations

This is still an acceptance gate, not full production certification. It does
not certify arbitrary production hosts, real customer PKI, host firewall
changes outside a disposable namespace, process supervision policy, upgrade and
rollback packaging, or every detector/correlation path. It proves the specific
networked mTLS, durable replay, process restart, command/result, containment,
and rollback boundaries described above.
