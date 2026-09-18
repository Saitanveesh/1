# ADR 0020: Site command receipt retention and compaction

## Status
Accepted

## Context
ADR 0019 keeps acknowledged command receipts indefinitely to preserve site-side replay protection. That is safe at low volume but creates unbounded local SQLite growth at production command rates.

## Decision
The site result outbox exposes explicit, site-scoped compaction for acknowledged receipts only.

- Unreported results are never eligible for compaction.
- Retention must be a positive duration; zero or negative values fail closed.
- Cutoffs use timezone-aware UTC timestamps.
- Deletion remains constrained by the outbox tenant and site identifiers.
- Compaction is explicit rather than hidden in command processing so deployment policy can choose a retention window based on command replay guarantees and storage capacity.
- No default production retention duration is fabricated in code.

Operators must configure a retention window longer than the maximum period in which the control plane can legitimately redeliver an already acknowledged command. Connector-level idempotency remains required for crash windows inside external enforcement operations.

## Consequences
Local receipt storage can now be bounded without risking deletion of unreported outcomes. Removing an acknowledged receipt also removes site-side command-ID deduplication for that command, so retention policy is part of the security boundary and must not be shortened merely to reclaim disk.

## Safety
This change does not execute enforcement and does not touch an operator workstation. Tests use temporary SQLite databases only. Tenant/site isolation remains mandatory in every compaction query.
