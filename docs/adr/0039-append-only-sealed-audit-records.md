# ADR 0039: Append-only sealed audit records

## Status

Accepted

## Context

MON response execution already emits tenant/site-scoped audit records, but the persistence
repository used an upsert. Reusing an audit identifier could therefore replace an existing
record. A control-plane database write performed outside the repository could also update or
delete audit rows without an application-level signal.

For a critical-network response system, an audit record must not be silently rewritten after it
has been accepted.

## Decision

Every durable audit record is sealed with a SHA-256 digest over a canonical JSON representation
of the complete AuditRecord payload.

The repository treats `(tenant_id, site_id, audit_id)` as immutable identity:

- the first write inserts the record and its digest;
- an exact replay of the same record is idempotent;
- reuse of the same audit identity with different content fails closed;
- audit reads recompute the digest and fail with an integrity error on a mismatch.

Migration 0007 backfills digests for existing audit rows before making the digest column
non-null.

PostgreSQL additionally installs a BEFORE UPDATE OR DELETE trigger on `audit_records`.
Normal database roles, including the application table owner used by MON's integration gate,
therefore cannot mutate or delete an accepted row through ordinary DML. The repository-level
identity rule remains in place for SQLite development stores and as a second layer in
PostgreSQL.

The in-memory store follows the same immutable-identity semantics, but it is not a durable
tamper-evident audit store.

## Security boundary

This design is tamper-evident at record-read time and append-only against ordinary PostgreSQL
DML. It is not an external transparency ledger and does not claim protection from a database
superuser or infrastructure administrator that can disable triggers, rewrite storage, or
replace both data and application code.

The per-record digest does not by itself prove completeness or detect a privileged deletion
performed after disabling the trigger. Cross-system anchoring or a chained/WORM audit export is
a separate future control if the deployment threat model requires administrator-independent
non-repudiation.

## Consequences

- Audit identifiers can no longer be reused to rewrite history.
- Silent payload corruption is detected when audit records are read.
- Existing audit records are sealed during migration.
- PostgreSQL UPDATE and DELETE attempts fail before changing audit history.
- Disaster recovery and retention workflows must treat audit data as append-only and use
  database-level lifecycle procedures rather than ordinary row deletion.
