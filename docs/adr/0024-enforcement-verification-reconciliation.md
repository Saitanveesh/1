# ADR 0024: Reconcile interrupted enforcement with connector verification

## Status
Accepted

## Context

ADR 0023 persists site response state before and after enforcement, but an external
enforcement action cannot participate in the same SQLite transaction.

The critical crash window is:

1. persist response state as `EXECUTING`;
2. call the external enforcement adapter;
3. the external system applies the action;
4. the site process fails before APPLIED is persisted.

After restart, MON cannot safely infer whether the external effect exists. Blindly
re-running an action can duplicate or broaden enforcement. Marking it FAILED can hide a
live containment rule. Marking it APPLIED without evidence fabricates state and timing.

This ambiguity also matters during cloud loss: an unresolved containment action must not
silently remain beyond its intended TTL simply because the control plane is unavailable.

## Decision

MON defines a typed connector verification contract.

A verifiable enforcement adapter exposes:

`verify(plan, execution_id) -> EnforcementVerification`

The verification state is one of:

- `PRESENT`: the connector has authoritative evidence that the intended effect exists;
- `ABSENT`: the connector has authoritative evidence that the intended effect does not
  exist;
- `UNKNOWN`: the connector cannot establish either condition safely.

Inspection failures and ambiguous matches are UNKNOWN, not ABSENT.

The disposable nftables network-namespace adapter implements this contract by looking for
the deterministic `mon:<execution_id>` rule marker. Exactly one matching rule is PRESENT,
a successfully inspected chain with no marker is ABSENT, and inspection errors or duplicate
markers are UNKNOWN.

## Local reconciliation

`SiteResponseExecutor` reconciles persisted EXECUTING responses using connector evidence.

### PRESENT

The response becomes APPLIED without invoking `execute` again.

The original apply instant is unknowable after the crash, so MON does not fabricate
`applied_at`. Instead it calculates a conservative expiry deadline from the durable
pre-call `requested_at + ttl_seconds`.

Because the actual external apply cannot have occurred before the durable request timestamp,
this deadline is no later than the configured TTL measured from the real apply. Reconciliation
therefore cannot extend containment beyond the configured duration.

The persisted `EnforcementResult` explicitly states that presence was verified after an
interrupted execution and that the original adapter result was not persisted.

### ABSENT

The response becomes FAILED with an explicit verification error. MON does not automatically
re-apply the action under the same response id. A new policy decision is required for a new
containment attempt.

### UNKNOWN or verification failure

The response remains EXECUTING. MON does not synthesize success or failure.

Verification observations are written to the response audit trail using the
`mon-site-reconciliation` actor.

## Command delivery behavior

An unresolved EXECUTING response is not turned into a terminal site-command receipt.

Both the basic and production site controllers defer such command results. The control-plane
command therefore remains eligible for at-least-once redelivery and verification can retry.

This prevents a transient connector inspection failure from being recorded as a confirmed
failed enforcement action.

## Offline recovery

Local TTL recovery first attempts to reconcile uncertain EXECUTING responses when a site
response executor is available.

If verification finds PRESENT and the conservative expiry deadline has passed, the same
recovery cycle can roll the action back without SaaS connectivity.

If verification remains UNKNOWN, recovery reports a degraded state and leaves the response
EXECUTING. MON prefers visible uncertainty over an unsafe guessed rollback or re-apply.

## Failure model

- Connector does not implement verification: keep EXECUTING.
- Connector verification raises: keep EXECUTING and audit the error.
- Connector reports UNKNOWN: keep EXECUTING.
- Connector reports ABSENT: persist FAILED.
- Connector reports PRESENT: persist APPLIED without re-execution.
- Verified PRESENT effect is already past its conservative TTL: local recovery may roll it
  back immediately.
- Site command is redelivered while state remains EXECUTING: do not persist or upload a
  terminal command result.

This mechanism does not create exactly-once external enforcement. It provides evidence-based
reconciliation around the external side-effect crash boundary.

## Consequences

- Restart no longer requires blindly re-running an interrupted enforcement operation.
- Connectors must implement verification before MON can automatically reconcile their
  interrupted actions.
- The site can recover verified containment locally during cloud outages.
- Operator status exposes the count of unresolved EXECUTING responses.
- A later tranche should add broader asynchronous control-plane convergence for reconciliation
  that resolves only after the original command has already expired at the control plane.
