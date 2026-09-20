# ADR 0064: PostgreSQL logical backup and restore

## Status

Accepted

## Context

MON control-plane state is PostgreSQL-backed and includes tenant/site scoped security
events, derived investigation objects, audit records, fabric receipts, enrollment and fleet
state, and other schema-managed records. The repository needed a tested restore contract that
uses PostgreSQL-native tooling instead of a custom SQL serializer.

## Decision

MON now owns `tools/backup/control_plane.py`, a thin repository wrapper around
`pg_dump --format=custom` and `pg_restore`. Backup requires an explicit PostgreSQL URL and an
explicit file destination. Restore requires an explicit PostgreSQL URL and refuses non-empty
targets unless the caller deliberately supplies an override.

Each backup writes a sidecar metadata file with a schema version, tool version, source commit,
UTC creation time, PostgreSQL major version, backup artifact name, and SHA-256 digest. The
metadata deliberately omits database URLs, passwords, credentials, and connection strings.

The restore path verifies metadata checksum evidence when present before invoking
`pg_restore`. Verification opens the restored database through normal MON store APIs and
checks representative object counts and identities, tenant/site isolation, fabric receipt
state, audit digest integrity, and migration-version presence. A successful `pg_restore`
process alone is not considered sufficient proof of recovery.

## CI Validation

The dedicated `backup-restore` workflow starts disposable PostgreSQL, applies migrations,
seeds representative scoped MON state, creates a custom-format logical backup, verifies
metadata sanitization and checksum behavior, restores into a fresh database, and runs the MON
restore verifier against the restored database.

## Limitations

This is logical backup and restore only. It is not point-in-time recovery, streaming
replication, multi-region disaster recovery, or high-availability failover. Backup storage
encryption, retention, scheduling, offsite replication, and operational access controls remain
deployment responsibilities.
