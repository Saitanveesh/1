# ADR 0049: Durable event-fabric exponential retry backoff

## Status

Accepted.

## Context

ADR 0048 validated the event-fabric recovery path and called out one remaining
runtime limitation: failed deliveries were retried by attempt count only, with
no durable time-based retry schedule. That made restart behavior durable but
could still create tight network retry loops if the runtime was configured with
a short flush interval.

## Decision

The durable fabric producer outbox now owns retry scheduling. Each undelivered
envelope may carry:

- `attempts`;
- sanitized `last_error`;
- `next_attempt_at`;
- effective `retry_delay_seconds`;
- `retry_jitter_seconds`.

The retry formula is:

```text
capped_delay = min(base_delay * 2^(attempt - 1), max_delay)
jitter = capped_delay * 0.20 * bounded_random[-1.0, 1.0]
effective_delay = clamp(capped_delay + jitter, 0, max_delay)
next_attempt_at = failure_time + effective_delay
```

Defaults are a 1 second base delay and a 300 second maximum delay. Production
site-service configuration exposes only these two operator knobs:

- `MON_SITE_FABRIC_RETRY_BASE_DELAY_SECONDS`;
- `MON_SITE_FABRIC_RETRY_MAX_DELAY_SECONDS`.

Both are bounded to positive values no greater than 3600 seconds, and the base
delay cannot exceed the maximum.

## Ordering impact

MON preserves the existing per-tenant/site ordering guarantee. Pending envelopes
remain ordered by creation time and event ID. If the oldest undelivered envelope
is in backoff, later envelopes in the same local ordering domain are not
returned as eligible and cannot overtake it.

## Restart semantics

Retry state is persisted in the same WAL-backed SQLite outbox as the exact
fabric envelope. A process restart does not reset attempts or `next_attempt_at`.
Success clears active retry state while preserving the delivery receipt until
source reconciliation.

## Runtime scheduling

The Site Controller runtime still uses a simple local loop. After a flush result
includes a future fabric retry time, the runtime waits until that retry time when
it is later than the normal flush interval. Shutdown remains prompt because the
wait is implemented through the existing stop event, not through an external
scheduler.

## Health semantics

The fabric diagnostics and flush result expose factual delivery state:

- pending counts;
- whether backoff is active;
- next retry timestamp;
- maximum attempts;
- bounded sanitized last error.

The controller reports `OFFLINE` when a publisher is absent and work is pending.
It reports `DEGRADED` while delivery is failed or backing off. It must not report
`SYNCED` merely because no network attempt was made during a backoff window.

## Schema migration

The outbox schema version is now `2`. Version `1` outboxes are upgraded in place
by adding nullable retry timestamp state plus delay/jitter columns with safe
defaults. Queued envelopes remain readable and are not deleted or invalidated.

If persisted retry metadata is malformed, such as a corrupted retry timestamp or
impossible negative delay, startup fails visibly rather than reporting the
outbox as healthy.

## Security boundary

Delivery errors are untrusted and may include HTTP headers, bearer tokens, or
other credential material from lower layers. Fabric outbox persistence, runtime
status, and flush responses use the shared fabric error sanitizer before storing
or exposing last-error strings. Tests cover bearer-token, password, and private
key redaction.

## Limitations

This milestone does not introduce broker-backed high availability, arbitrary
network-partition certification, multi-region failover, disaster recovery, or a
distributed scheduler. It hardens the current local durable HTTP fabric path.
