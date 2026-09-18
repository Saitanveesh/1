# ADR 0014: Durable response execution, audit and rollback state machine

Status: Accepted

## Decision

MON response execution is a durable state machine separate from detection and
investigation.

A response request ID is also the execution idempotency key. Repeating the same request
returns the existing execution and must not call the enforcement adapter twice.

Execution states are:

- PENDING_APPROVAL
- EXECUTING
- APPLIED
- FAILED
- DENIED
- ROLLBACK_PENDING
- ROLLED_BACK
- ROLLBACK_FAILED

Disruptive response plans carry a connector/topology blast-radius estimate when one has
been supplied. If no estimate exists, the orchestration policy requires approval rather
than fabricating a safe blast radius.

Adapters receive the execution ID and return a typed result so vendor connectors can
implement idempotent external operations and preserve their external rule/reference ID.

Applied temporary actions record an expiry timestamp from their TTL. The recovery layer
can query due actions and invoke the same adapter's rollback path.

## Audit

Response start, denial, approval wait, application, failure and rollback transitions
write durable tenant/site-scoped audit records.

## Current boundary

This ADR establishes the safe execution core. No real firewall/NAC adapter is registered
by default. A missing adapter fails closed. Vendor/OS adapters must be validated in
disposable environments before being enabled.
