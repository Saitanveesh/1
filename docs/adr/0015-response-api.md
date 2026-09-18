# ADR 0015: Authenticated response API and administrative approval boundary

Status: Accepted

## Decision

MON exposes response planning, execution, rollback and audit through authenticated
tenant/site-scoped APIs.

The API overwrites response `actor_id` and actor type from the authenticated principal.
Client JSON cannot assert the audit identity.

SOC analysts retain `respond` permission, allowing them to submit actions that policy
already allows. A new `approve_response` permission is restricted to tenant and
platform administrators. When policy returns REQUIRE_APPROVAL, an analyst can create a
PENDING_APPROVAL execution but cannot approve it.

Approval of a pending execution resumes the stored response plan. A second payload with
the same request ID cannot change the target or action while obtaining approval.

## Live console

Response executions and audit records are included in the reconnect snapshot. Response
state transitions are pushed over the existing tenant/site WebSocket stream. The
black/white console provides read-only Response and Audit views.

## Connector boundary

No real enforcement connector is registered by the API. The response API can therefore
exercise planning, approval and durable failure behavior safely until validated
connectors are installed.
