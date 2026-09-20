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
