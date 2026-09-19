# ADR 0025: Late site execution reconciliation after command expiry

## Status
Accepted

## Context

ADR 0024 lets a site resolve a crash-interrupted `EXECUTING` response from connector
verification evidence without blindly repeating an external enforcement action.

A remaining distributed-state gap exists when the site cannot reach the control plane until
after the original apply command has expired.

Example:

1. the control plane dispatches an APPLY_RESPONSE command;
2. the site durably records EXECUTING and the external device applies the effect;
3. the site process fails before APPLIED is persisted;
4. the control plane later expires the command and marks the response FAILED because it has
   no confirmed command result;
5. the site restarts offline, verifies that the effect is PRESENT, and may autonomously
   roll it back after the conservative TTL;
6. the site reconnects after the command is already EXPIRED.

The normal command-result endpoint cannot safely be used to overwrite an expired command
with a late terminal result. Conversely, leaving the control plane at delivery-failure
state would hide authoritative site evidence and could report the wrong final response
state.

## Decision

MON extends the existing durable site response-update channel with an explicit
`EXECUTION_RECONCILIATION` update kind.

The normal command-result path remains preferred. A late execution reconciliation is
generated only when all of these conditions are true:

- the local response has a terminal or evidence-backed state produced from interrupted
  execution verification;
- the response audit trail contains `VERIFY/PRESENT` or `VERIFY/ABSENT` evidence from
  `mon-site-reconciliation`;
- the original `EXECUTE/STARTED` audit contains the site command id and exact
  `command_not_after` deadline;
- the local clock has reached that command deadline;
- no durable command-result receipt is already reported or superseded.

The site persists `command_not_after` in the pre-enforcement STARTED audit. MON does not
reconstruct or guess a command deadline from a default configuration value.

## Accepted late states

An execution reconciliation may report:

- `APPLIED` backed by `VERIFY/PRESENT`;
- `FAILED` backed by `VERIFY/ABSENT`;
- `ROLLED_BACK` backed by `VERIFY/PRESENT` plus autonomous recovery audit evidence;
- `ROLLBACK_FAILED` backed by `VERIFY/PRESENT` plus autonomous recovery audit evidence.

A verified-present late execution still has no fabricated `applied_at`. Its
`expires_at` must equal the conservative safety bound defined by ADR 0024:

`site command created_at + response TTL`

The verified result must explicitly identify that it was reconstructed after an interrupted
execution.

## Control-plane acceptance rules

The control plane accepts an execution-reconciliation update only when:

- the referenced command exists;
- the command is an `APPLY_RESPONSE`;
- the command status is `EXPIRED`;
- the control-plane response is in the command-expiry FAILED state and has a matching
  `SITE_COMMAND/EXPIRED` audit for that command;
- the site-reported plan exactly matches the dispatched plan;
- approval state exactly matches the dispatched command;
- the site-reported `requested_at` equals the command `created_at`;
- the reported conservative expiry is exact;
- all site audit ids are collision-safe.

The control plane preserves its own canonical response `requested_at` instead of replacing
it with the site's command-start timestamp. Only dynamic execution fields are reconciled.

The site-command record remains `EXPIRED`. Reconciliation corrects response state; it does
not rewrite history to pretend that the command-result transport completed before its
deadline.

A control-plane `SITE_EXECUTION_RECONCILIATION/ACCEPTED` audit records the previous state,
reported state, command id, site observation time, site request time, and preserved
control-plane request time.

## Command-result hardening

An already EXPIRED command cannot later be completed through the normal command-result
endpoint.

For non-expired commands, apply results must preserve the dispatched plan, approval, and
command creation timestamp. Successful apply results must be APPLIED or ROLLED_BACK.
A successful result without an exact `applied_at` is accepted only when it includes
`VERIFY/PRESENT` evidence.

Rollback results cannot replace the stored response with a different plan. Invalid or
nonterminal response states are not trusted as rollback completion.

## Durable outbox convergence

A command result that could not be accepted because the control plane had already expired
the command can coexist temporarily with a response-reconciliation update.

When the response-reconciliation update is accepted, the local command-result receipt is
marked `superseded`. Superseded receipts:

- remain durable for replay protection and auditability;
- are excluded from retry;
- are counted separately in diagnostics;
- may be compacted only under the same explicit positive retention policy used for
  acknowledged receipts.

This prevents a permanently failing late command result from keeping the site in a false
degraded state after authoritative response reconciliation succeeded.

## Autonomous recovery reporting

Responses with interrupted-execution verification history use the richer execution
reconciliation update, including their final autonomous rollback state. They are not also
sent as ordinary recovery-only updates.

Responses that were applied normally continue using the ADR 0022 recovery update path.

## Failure model

- Missing command id or command deadline evidence: do not construct a late reconciliation.
- Command has not expired: control plane rejects reconciliation; normal command delivery is
  still authoritative.
- Command expired but no matching control-plane expiry audit exists: reject.
- Plan, approval, request identity, or conservative expiry mismatch: reject.
- VERIFY evidence is UNKNOWN or missing: no reconciliation update is generated.
- Conflicting audit id: reject without overwriting existing audit history.
- Reconciliation upload fails: retain it durably and retry.
- Reconciliation succeeds while an old command result remains queued: mark that command
  result superseded and stop retrying it.

## Consequences

- A site that recovers and rolls back an interrupted containment while disconnected can
  later converge the control plane to the evidence-backed final state.
- Command transport history and response execution history remain distinct and truthful.
- No apply timestamp, deadline, plan, or approval state is guessed.
- The response-update transport remains one mTLS-authenticated path while update intent is
  explicit in the typed schema.
