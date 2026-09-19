# ADR 0022: Autonomous site recovery reporting

## Status
Accepted

## Context

ADR 0017 makes finite-TTL containment recoverable at the site without SaaS connectivity.
ADR 0018/0019 report the outcome of control-plane commands, and ADR 0021 routes site-local
enforcement through that command channel.

TTL recovery is different: it can happen autonomously after the original APPLY_RESPONSE
command has already completed. Without a separate recovery report, the site can restore the
network while the control plane continues to show the response as APPLIED. That violates
MON's VERIFY and RECOVER lifecycle and can present stale containment state to operators.

## Decision

The site reports autonomous terminal rollback state through a dedicated `SiteResponseUpdate`.

A report contains:

- tenant and site scope;
- a deterministic update id derived from the terminal response execution state;
- the complete response execution;
- response audit records produced locally;
- the site observation timestamp.

Production site controllers persist updates in a site-scoped SQLite outbox before cloud
delivery. Acknowledged rows are retained as receipts rather than immediately deleted.
Compaction is explicit and accepts only a positive operator-selected retention duration;
there is no fabricated default retention period.

The controller reconstructs missing updates by scanning local response executions for
terminal rollback state backed by `mon-site-recovery` rollback audit evidence. This closes
the enqueue gap after a local rollback when the local response/audit store itself survives
the process failure. A production deployment therefore still requires durable local
response and audit storage; this ADR does not claim that an in-memory store survives restart.

Command results are flushed before recovery updates. This preserves causal ordering when an
APPLY_RESPONSE result and a later autonomous rollback were both buffered during a cloud
outage.

## Transport and authorization

The mTLS site ingress exposes `/api/v1/site/responses/updates`.

The verified client certificate SPIFFE identity must match the update tenant/site. The
ingress forwards accepted payloads to the internal control-plane
`/api/v1/site-response-updates` endpoint, which also requires the `site_command` permission
for that tenant/site scope.

## Reconciliation safety

The control plane never blindly replaces response state from a site report.

The response plan, request timestamps, approval, apply timestamp, expiry timestamp and apply
result are immutable. A site update may report only `ROLLED_BACK` or `ROLLBACK_FAILED`.

Allowed transitions are:

- APPLIED -> ROLLBACK_FAILED
- ROLLBACK_PENDING -> ROLLBACK_FAILED
- APPLIED -> ROLLED_BACK
- ROLLBACK_PENDING -> ROLLED_BACK
- ROLLBACK_FAILED -> ROLLED_BACK

An identical terminal report is idempotent. Regressions from ROLLED_BACK and unrelated
states are rejected.

Incoming audit records are scope-checked by the model and cannot overwrite an existing
audit id with different content. The control plane adds its own receipt audit using server
time and records the site's observation timestamp as evidence rather than trusting it as
the control-plane clock.

## Failure model

Cloud loss never blocks local rollback. Failed uploads remain queued.

If a recovery update reaches the control plane before its original APPLY_RESPONSE result,
the update is rejected as an invalid transition and remains in the local outbox. On a later
cycle the command result is delivered first, then the recovery update is retried.

The protocol provides at-least-once reporting with idempotent reconciliation. It does not
claim exactly-once distributed execution.

## Consequences

- The operator-visible response state can converge from APPLIED to the actual autonomous
  recovery outcome.
- Recovery evidence and audit history are carried back to the control plane.
- Recovery reporting is durable independently of event telemetry buffering.
- Receipt storage is bounded only when an explicit retention policy is configured.
- Durable local response/audit storage remains a separate production requirement and must
  be completed before claiming restart-safe autonomous recovery.
