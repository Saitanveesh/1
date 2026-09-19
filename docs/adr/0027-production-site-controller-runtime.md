# ADR 0027: Production site-controller runtime composition

## Status
Accepted

## Context

MON already had the individual primitives needed for local autonomy: a durable event spool,
durable site command result and response-update outboxes, durable response execution state,
mTLS-capable cloud clients, local response execution, verification/reconciliation, TTL
recovery, and independent runtime loops.

Those pieces were previously assembled only by tests or callers. There was no supported
site-controller process that bound them to one tenant/site identity, owned their lifecycle,
and failed closed when local state or cloud credentials were inconsistent.

The existing event spool also allowed unbound use and used SQLite NORMAL synchronous mode.
That was weaker than the durability guarantees used for response state and command receipts.

## Decision

MON provides a production site service composition in `mon.site_service`.

The service binds exactly one `tenant_id` and `site_id` to a state directory and creates:

- a site-scoped SQLite event spool;
- a site-scoped SQLite response execution/audit store;
- a durable site command-result receipt/outbox;
- a durable site response-update outbox;
- a `SiteResponseExecutor`;
- a `ProductionSiteController`;
- independent cloud flush, command poll, and local recovery loops;
- a local FastAPI service exposing health, local event ingestion, explicit flush, and
  runtime-loop status.

The executable entry point is `mon-site`.

## Local persistence

The event spool now uses SQLite WAL plus `synchronous=FULL`, a bounded busy timeout, and
durable metadata binding the file to one tenant/site scope.

Opening a scope-bound spool under another tenant or site fails closed. Existing legacy spool
files can be adopted only when all existing rows belong to exactly one matching scope.
A legacy file containing more than one scope requires an explicit migration rather than an
automatic guess.

The service uses separate SQLite files for event delivery, response state, command-result
receipts, and response updates. They are separate because their retention and replay
semantics differ.

## Cloud connectivity

Cloud connectivity is optional so local ingestion and recovery can run while disconnected.

When a cloud ingress URL is configured, the service requires all of:

- HTTPS;
- bearer service authorization;
- trusted CA certificate;
- site client certificate;
- site client private key.

The same verified mTLS identity is used for telemetry upload, command polling, command result
delivery, and site response updates.

A bearer token can be loaded from a file. Configuring both an inline token and token file is
rejected.

No plaintext HTTP cloud fallback is provided by the production site service.

## Runtime lifecycle

The FastAPI lifespan owns the runtime loops. Startup launches independent flush, command,
and recovery tasks. Shutdown signals all loops, waits for bounded completion, cancels only
after the shutdown deadline, and then closes local SQLite resources.

Runtime status records both exceptions and returned operational states. A controller method
that returns `DEGRADED` is not reported as healthy merely because it did not raise an
exception.

The production controller also reports durable outbox delivery errors as degraded health.

## Enforcement adapters

The service composition accepts an `EnforcementRegistry` so production connector packages
can register only the enforcement capabilities installed at that site.

The default executable does not silently enable host firewall enforcement. In particular,
the disposable nftables network-namespace adapter remains test/sandbox-only. If a command
targets an unavailable adapter, local execution fails explicitly and the result is audited
and reported.

## Current persistence boundary

The event delivery path and response/recovery path are durable.

The local detection/correlation pipeline is still memory-resident and health output states
this explicitly as `local_pipeline_state_persistence = MEMORY_ONLY`. This tranche does not
claim restart-persistent detector windows, attack-graph state, or local incident correlation.
Those require a separate durable local analysis-state design rather than serializing process
memory without schema/version semantics.

## Failure model

- State directory contains a spool for another tenant/site: fail startup.
- Cloud URL is HTTP: fail startup.
- Cloud URL is configured without complete mTLS/auth material: fail startup.
- Credential file is missing or token file is empty: fail startup.
- Cloud is unavailable after startup: retain event, command-result, and response-update
  data locally and continue local recovery.
- Runtime operation returns degraded state: expose degraded runtime state.
- Response execution remains uncertain: expose it in site health and continue verification
  attempts without fabricating success.
- Shutdown occurs during a loop: request cooperative stop, then bounded cancellation before
  closing durable stores.

## Consequences

- MON now has one explicit, testable process composition for the Local Site Controller.
- Local state files cannot be silently reused across tenants or sites.
- Event delivery durability matches the stronger response-path SQLite policy.
- Operators can distinguish local readiness from cloud/runtime degradation.
- Production enforcement remains adapter-driven and fail-closed.
- Restart persistence for local detection/correlation becomes the next local-autonomy
  implementation tranche.
