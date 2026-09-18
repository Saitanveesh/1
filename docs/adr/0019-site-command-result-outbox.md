# ADR 0019: Durable site command result outbox and receipt ledger

## Status
Accepted

## Context
The site controller can execute a response locally while the control plane is temporarily unreachable. If result upload fails after execution, an in-memory-only result can be lost on process restart. A redelivered command can also cause repeated work unless the site retains durable knowledge that the command was already executed.

This boundary is safety-critical because response actions may alter network enforcement state. Delivery must tolerate cloud loss without fabricating success or relying on the operator workstation.

## Decision
Production site controllers persist each `SiteCommandResult` to a site-scoped SQLite outbox before attempting cloud delivery.

The same table is also a command receipt ledger:

- `command_id` is the durable idempotency key.
- tenant and site scope are checked before persistence.
- unreported results remain queued and retain retry diagnostics.
- successful cloud acknowledgement sets `reported_at`; it does not delete the receipt.
- a redelivered command whose receipt already exists is not executed again.
- result delivery is retried before new commands are accepted, bounding backlog growth.
- SQLite uses WAL and `synchronous=FULL` for this safety-sensitive local state.

The existing site command endpoint remains the transport. This ADR changes local delivery semantics, not command authorization or approval policy.

## Consequences
A site process restart no longer discards an unreported response outcome. Control-plane outages can produce delayed result reporting, but not a false healthy result. Receipt retention consumes local disk and therefore requires an explicit retention/compaction policy before high-volume production rollout.

This mechanism does not claim exactly-once distributed execution. It provides durable site-side deduplication around the command ID; connector-level idempotency remains required for crash windows inside an external enforcement operation.

## Safety
No production workstation or unvalidated binary is used by this change. Tests use temporary SQLite files and fake command/executor implementations. Real enforcement remains governed by the existing approval, TTL, rollback, and adapter controls.
