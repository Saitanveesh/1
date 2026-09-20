# MON Backup And Recovery

## Control Plane PostgreSQL

Use `tools/backup/control_plane.py` for repository-owned logical backup and restore checks.
The tool wraps PostgreSQL-native `pg_dump` and `pg_restore`; it does not implement a custom
SQL serializer.

Create a backup:

```bash
python tools/backup/control_plane.py backup \
  --database-url "$MON_DATABASE_URL" \
  --output ./control-plane.dump
```

Restore into a fresh disposable database:

```bash
python tools/backup/control_plane.py restore \
  --database-url "$MON_RESTORE_DATABASE_URL" \
  --backup ./control-plane.dump
python tools/backup/control_plane.py verify \
  --database-url "$MON_RESTORE_DATABASE_URL"
```

The backup sidecar metadata contains only non-secret restore evidence: schema version, tool
version, source commit, creation timestamp, artifact name, artifact SHA-256, and PostgreSQL
major version. Do not treat the metadata as a replacement for secured backup storage.

Limitations: this is not point-in-time recovery, streaming replication, multi-region disaster
recovery, or high-availability failover. Backup encryption, retention, scheduling, offsite
replication, and operator access controls are deployment responsibilities.

## Site Controller durable state

Use `tools/backup/site_state.py` for repository-owned snapshot/verify/restore of the Site
Controller's local durable state. This is a **quiesced** snapshot: stop or quiesce the Site
Controller before creating one. It does not claim cross-database transactional consistency
while the service is actively writing; each individual database is still captured through
SQLite's own backup API, never a raw copy of the live `.db`/`-wal`/`-shm` files.

Exactly seven MON-owned databases are captured, read directly from
`build_site_service_resources` (`mon.site_service`):

```text
event-spool.db
fabric-outbox.db
analysis-state.db
response-state.db
command-results.db
response-updates.db
sensor-trust.db
```

No other file under the state directory is ever archived -- private keys, bearer tokens,
connector vault material, and certificates are explicitly excluded.

Create a snapshot:

```bash
python tools/backup/site_state.py snapshot \
  --state-dir /var/lib/mon-site \
  --output ./site-state.zip \
  --tenant-id acme \
  --site-id hq
```

Verify a snapshot without restoring it:

```bash
python tools/backup/site_state.py verify \
  --archive ./site-state.zip \
  --tenant-id acme \
  --site-id hq
```

Restore into a fresh (empty or nonexistent) destination directory:

```bash
python tools/backup/site_state.py restore \
  --archive ./site-state.zip \
  --destination /var/lib/mon-site-restored \
  --tenant-id acme \
  --site-id hq
```

Restore refuses an existing, non-empty destination directory by default. The full archive
(manifest schema/version, exact member set, every SHA-256 and byte size, SQLite integrity, and
tenant/site scope where a store persists that metadata) is validated before anything is written
to the destination, and the destination is written through a temporary staging directory
finalized with one atomic rename, so a failed restore never leaves a half-restored directory
reporting success. After restoring, every database is reopened through its real MON store class
and its `diagnostics()` are reported as representative proof durable state (queued events,
fabric outbox entries, analysis/checkpoint state, response executions, command-result and
response-update outbox entries, sensor trust state) survived.

Limitations: this requires Site Controller quiescence and is not continuous replication, high
availability, or multi-site disaster recovery. Secrets/certificates need a separate,
deployment-specific backup policy. A successful restore proves the seven durable databases
round-tripped; it does not itself prove network or Site Controller service recovery, and
restored queues/outboxes still require their normal replay/reconciliation path after the
service actually restarts.
