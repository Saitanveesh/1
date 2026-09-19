# ADR 0021: Response execution-plane dispatch

Status: Accepted

## Context

MON separates policy decisions from enforcement execution. The control plane can plan and
authorize a response, but site-local network and endpoint controls must remain operable when
SaaS connectivity is degraded and must not require the SaaS process to hold local enforcement
privileges.

The durable site command channel from ADR 0018 and replay-safe result outbox from ADR 0019
provide the transport required to place execution at the site. ADR 0020 bounds retained
acknowledged command receipts without compacting pending outcomes.

## Decision

The Response Dispatcher is the execution-placement boundary after policy evaluation.

Default execution planes are:

- ENDPOINT, NAC, SWITCH, ROUTER and FIREWALL: SITE.
- WAF, CLOUD and UPSTREAM: CONTROL_PLANE.

An enforcement point may explicitly set `attributes.execution_plane` to `SITE` or
`CONTROL_PLANE` for deployment-specific topology. Any other value fails closed and is
reported as a response state error; MON does not guess an execution location.

For site-local actions, the control plane stores the response as `DISPATCH_PENDING` and
enqueues an `APPLY_RESPONSE` command into the durable site command queue. The command ID is
deterministic for the tenant, site and response execution, so repeated API requests cannot
create duplicate local enforcement work.

For control-plane actions, the existing policy-gated Response Orchestrator continues to use
the registered control-plane adapter.

## Approval safety

If a response is `PENDING_APPROVAL`, later approval resumes the stored response plan.
The approving request cannot change the target, action or enforcement point after review.

## Rollback

Rollback follows the same execution plane as the original response. Site-local rollback
moves the response to `ROLLBACK_PENDING` and enqueues a `ROLLBACK_RESPONSE` command.
A duplicate rollback request reuses the pending command. A rollback retry after
`ROLLBACK_FAILED` receives a new deterministic attempt ID.

## Command failure reconciliation

A queued command has a finite delivery lifetime. If an undelivered apply command expires,
the corresponding `DISPATCH_PENDING` response becomes `FAILED`. If an undelivered rollback
command expires, `ROLLBACK_PENDING` becomes `ROLLBACK_FAILED`. These transitions emit audit
records.

The same reconciliation applies when the site returns a failed command result without a
response execution object, for example when the command reached the site after its
`not_after` deadline. This prevents an operator-visible response from remaining indefinitely
pending while the command record is already terminal.

The response action TTL begins when the site actually applies the action, not when the
control plane queues the command.

## Consequences

- SaaS no longer directly executes site-local endpoint, NAC, switch, router or firewall
  actions by default.
- Local enforcement privileges remain at the site controller.
- Response state, command state, site result state and audit state are reconciled rather than
  presenting a false healthy/pending condition.
- Deployment topology can override the default plane explicitly, but malformed configuration
  is rejected rather than inferred.
