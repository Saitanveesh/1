# ADR 0023: Durable site response state

## Status
Accepted

## Context

ADR 0017 requires local TTL recovery to continue while SaaS connectivity is unavailable.
ADR 0022 reconstructs autonomous recovery reports after a process failure, but that
reconstruction only works if the site's response execution and response audit state survive
restart.

Using the control-plane store at the site would couple local safety to unrelated SaaS state
and interfaces. Using an in-memory store loses APPLIED state, TTL deadlines, rollback
results, and recovery audit evidence on restart.

## Decision

MON uses a narrow `ResponseStateStore` contract for local response execution and recovery.

The production-oriented local implementation is `SQLiteSiteResponseStore`. Each database
is permanently bound to exactly one `tenant_id` and `site_id` in metadata. Reopening the
same file under a different scope fails closed.

The store persists:

- complete `ResponseExecution` objects;
- execution status used by local replay and TTL recovery;
- apply and rollback results;
- apply/expiry/rollback timestamps;
- response audit records.

SQLite runs in WAL mode with `synchronous=FULL` and a bounded busy timeout. The site
response store is intentionally separate from command-result and response-update outboxes:
those structures answer different durability questions and must not be treated as a
replacement for response state.

`ResponseRollbackEngine` depends only on `ResponseStateStore`. The control-plane
`ResponseOrchestrator` retains its wider `Store` dependency for incident, asset,
enforcement-graph, and policy planning, then delegates rollback and TTL lookup to the
narrow engine. This lets the site controller recover responses without implementing the
full control-plane persistence contract.

## Scope and integrity rules

Every stored response must match the database tenant/site scope at three levels:

- the response execution;
- the embedded response request;
- the embedded enforcement point.

The site execution id must equal the response request id. Response timestamps written to
the durable store must be timezone-aware.

Audit writes are idempotent by audit id. Reusing an existing audit id with different
content is rejected instead of overwriting history.

## Restart behavior

An APPLIED response survives process restart. Replaying the original site command returns
the stored execution and does not call the enforcement adapter again.

An expired APPLIED response remains eligible for local TTL recovery after restart. The
rollback result and rollback audit records are persisted, allowing ADR 0022 recovery-update
reconstruction after another restart.

## External side-effect crash boundary

Persistence cannot make an external enforcement operation transactional with SQLite.

The site writes `EXECUTING` before invoking an enforcement adapter. A process may fail
after the external device accepted the action but before MON persisted APPLIED. On restart
that `EXECUTING` record is therefore an uncertain side-effect state.

MON must not guess whether the external effect exists. The site does not automatically
re-run the apply operation, does not synthesize an APPLIED timestamp, and does not include
an EXECUTING response in TTL rollback selection. The state remains visible as EXECUTING
until a connector-specific verification/reconciliation mechanism can establish the actual
external state.

This is a deliberate safety choice: silent duplicate enforcement or fabricated timing is
worse than surfacing an unresolved execution state. A subsequent ADR must define the
connector verification contract required to reconcile this crash boundary.

## Failure model

- Database scope mismatch: fail startup for that store.
- Malformed or cross-scope durable payload: fail closed rather than use it.
- Cloud unavailable: local persisted TTL recovery still runs.
- Command replay after APPLIED/ROLLED_BACK: return persisted state without applying again.
- Restart with EXECUTING: preserve uncertainty and do not automatically repeat the
  external action.
- Audit id collision with different content: reject the write.

This design provides durable local response state and restart-safe recovery of known
APPLIED actions. It does not claim exactly-once external enforcement across a process crash.

## Consequences

- Local recovery no longer depends on in-memory response state.
- Autonomous recovery reporting can reconstruct terminal state after restart.
- Site response persistence has a smaller interface than the control-plane store.
- Tenant/site database reuse is prevented by durable metadata binding.
- The remaining execution crash ambiguity is explicit, testable, and cannot be mistaken
  for a confirmed apply or rollback.
- Production connector verification/reconciliation is the next required safety tranche.
