# ADR 0018: Durable mTLS site response command channel

Status: Accepted

## Decision

Enforcement credentials and OS-native network-control privileges remain at the site.
The SaaS control plane therefore delivers response commands to the Local Site Controller
through a durable pull channel rather than calling local firewalls directly.

Commands are stored in PostgreSQL with tenant_id and site_id, a command id, explicit
not-after time, delivery count and terminal result. Pull delivery is at-least-once:
a command stays pending until the site reports a result. The Local Site Controller uses
the response request id as the durable execution id, so redelivery cannot apply the same
response twice.

The existing mTLS site ingress is extended with command pull and result submission routes.
The verified client certificate SPIFFE identity determines tenant and site scope. A
site_controller bearer principal also requires the dedicated site_command permission.
Result payload scope must match the verified certificate before it can be forwarded.

## Site safety

An APPLY_RESPONSE command contains a response plan that already passed control-plane
policy. A REQUIRE_APPROVAL plan must also carry its administrator approval. A denied plan
cannot be serialized as a site command.

The site persists an EXECUTING response record before calling an enforcement adapter.
A replay returns the existing local execution. If the response has already expired and
rolled back, replay reports the ROLLED_BACK execution and does not reapply it.

ROLLBACK_RESPONSE commands reference an existing local execution and use the same adapter
rollback path as TTL recovery.

## Result reconciliation

Site results contain the final local response execution and its response audit records.
The control plane verifies the command/execution relationship before mirroring those
records into tenant-scoped response and audit storage.

## Failure model

Cloud result upload may fail after local enforcement succeeds. The command is then
redelivered. Local idempotency prevents re-execution and the result can be uploaded on a
later poll. TTL recovery remains a separate local loop and does not depend on command or
event synchronization succeeding.
