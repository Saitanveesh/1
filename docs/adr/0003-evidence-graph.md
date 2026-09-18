# ADR 0003: Evidence graph and finding correlation

Status: Accepted

## Decision

MON maintains a site-scoped evidence graph derived from observed communications.
Detectors attach their findings to observed edges rather than creating unsupported
network relationships.

Findings are correlated into incidents by observed actor within a bounded time window.
Correlation does not increase confidence numerically by itself: incident confidence is
the maximum confidence of its constituent findings. Independent evidence sources and
detectors remain visible to policy and operators.

## Rationale

A critical-network product must answer how systems are related to an incident, not only
show alert rows. Keeping graph edges tied to event IDs and finding IDs preserves the
difference between observed communication and analytical interpretation.

## Current limitations

The in-memory graph and correlator are development implementations. Durable graph/event
storage and cross-site correlation require the event/persistence layer planned next.
