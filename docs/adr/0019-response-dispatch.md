# ADR 0019: Response execution-plane dispatch

Status: Accepted

## Decision

MON separates response planning from execution placement. Once a response plan has passed
policy, the Response Dispatcher determines whether the selected enforcement point is
site-local or control-plane reachable.

By default:

- ENDPOINT, NAC, SWITCH, ROUTER and FIREWALL execute at the site;
- WAF, CLOUD and UPSTREAM execute through control-plane adapters.

An enforcement point may explicitly set attributes.execution_plane to SITE or
CONTROL_PLANE when a deployment topology requires an override. Invalid values fail closed.

Site-local actions are not executed by the SaaS API. The control plane writes a
DISPATCH_PENDING response execution and enqueues an APPLY_RESPONSE command into the
durable mTLS site command channel. Duplicate API calls reuse the existing response and
deterministic apply command, so they cannot create multiple local actions.

Control-plane actions continue through the Response Orchestrator and its adapter registry.

## Approval safety

A PENDING_APPROVAL response that is later approved dispatches the stored response plan.
The approving request cannot change the target, action or enforcement point.

## Rollback

Site-local rollback changes the response to ROLLBACK_PENDING and enqueues a
ROLLBACK_RESPONSE command. Duplicate rollback calls reuse a pending rollback command.
A failed rollback may create a new retry command.

## Stale command reconciliation

Site commands have a finite delivery lifetime. If an APPLY_RESPONSE command expires before
delivery, a DISPATCH_PENDING response becomes FAILED. If a rollback command expires,
ROLLBACK_PENDING becomes ROLLBACK_FAILED. These transitions write audit records rather
than leaving the operator console with a false indefinite pending state.

The response TTL still begins when the site actually applies the action, not when the
control plane queues the command.
