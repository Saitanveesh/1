# ADR 0065: Site Controller durable-state snapshot / verify / restore

## Status

Accepted.

## Context

ADR 0064 added repository-owned PostgreSQL logical backup/restore for the control plane. The
Site Controller has a separate durable-state surface: `build_site_service_resources`
(`mon.site_service`) opens exactly seven SQLite databases under its configured state directory
(`event-spool.db`, `fabric-outbox.db`, `analysis-state.db`, `response-state.db`,
`command-results.db`, `response-updates.db`, `sensor-trust.db`). MON had no repository-owned way
to snapshot, verify, or restore that local durable state.

## Decision

### Snapshot contract

`mon.site_state_snapshot.create_site_state_snapshot()` produces a **quiesced** snapshot: it does
not claim cross-database transactional consistency while the Site Controller is actively writing
multiple SQLite databases concurrently, and both the module docstring and this ADR require the
service to be stopped or quiesced before calling it. Each individual database is still captured
through SQLite's own backup API (`sqlite3.Connection.backup()`), never a raw filesystem copy of
the live `.db`/`-wal`/`-shm` files -- this is a per-database consistency guarantee that holds
regardless of quiescence; the quiescence requirement is specifically about consistency *between*
the seven databases.

### Exact allowlist

The seven database filenames are read directly from `build_site_service_resources`'s own
construction calls (`DATABASE_FILENAMES` in `mon.site_state_snapshot`), not independently
guessed. No other file under the state directory -- private keys, bearer tokens, connector vault
material, certificates -- is ever archived; a snapshot only ever reads exactly those seven
filenames from the source directory and rejects (rather than silently ignores) if any is missing.

### Manifest

A versioned `manifest.json` (Pydantic `SnapshotManifest`, `schema_version`, `tool_version`,
`tenant_id`, `site_id`, `created_at` UTC, `source_commit`, and one `SnapshotDatabaseEntry` per
database with `filename`/`sha256`/`size_bytes`) sits inside the archive alongside the seven
databases. It carries no credentials or secrets -- only filenames, hashes, and sizes.

### Format

The artifact is a ZIP archive (`zipfile.ZIP_DEFLATED`) containing exactly `manifest.json` plus
the seven database files, flat (no directory members). Snapshot creation works entirely inside a
temporary working directory and only atomically renames (`os.replace`) the finished archive into
place after every database has been backed up, integrity-checked, and hashed, and the manifest
written -- a failed snapshot never leaves a valid-looking partial artifact at the output path.

### Verification

`verify_site_state_snapshot()` never treats ZIP-open success as sufficient. It validates: the
archive is a well-formed ZIP with a bounded, flat, non-duplicate member set; `manifest.json`
parses and matches the current schema version; the member set is exactly
`{manifest.json} | DATABASE_FILENAMES` (no extra, no missing); every database's streamed SHA-256
and byte size match the manifest; `PRAGMA integrity_check` passes for every database; and --
where a store persists a scope-binding metadata row (five of the seven: everything except the two
lightweight outboxes) -- that the manifest's declared tenant/site actually matches what
`ValueError`-raising construction of the real store class reports. Extraction never calls
`ZipFile.extractall()`: every member name is checked against a strict `[A-Za-z0-9_.-]` allowlist
pattern before a single byte is streamed out via `ZipFile.open()`, which is also how path
traversal and zip-bomb-style oversized members are rejected (bounded manifest size, bounded
per-database size, bounded member count).

### Restore

`restore_site_state_snapshot()` requires an explicit destination and refuses an existing,
non-empty destination directory by default (an existing, genuinely empty directory is allowed,
matching "restore to an empty/nonexistent state directory"). The entire archive is validated --
identically to `verify_site_state_snapshot()` -- in a temporary directory *before* anything is
written to the destination; a tenant/site mismatch against the caller's explicit restore target
is rejected before any write. The destination is populated through a temporary staging directory
under the same parent (so the same filesystem, allowing a real atomic rename) and finalized with
one `os.replace()`; any failure before that point leaves the destination untouched, so a
half-restored directory can never be reported as success.

### Post-restore validation

After the atomic rename, `restore_site_state_snapshot()` reopens every one of the seven restored
databases through its real MON store class (`SQLiteEventSpool`, `DurableFabricOutbox`,
`SQLiteSiteAnalysisStore`, `SQLiteSiteResponseStore`, `SQLiteCommandResultOutbox`,
`SQLiteResponseUpdateOutbox`, `SQLiteSensorTrustStore`) from the final destination and calls each
store's own `diagnostics()` as representative proof durable state survived -- there is no second,
hand-rolled schema parser. This proves the databases round-trip; it does not itself prove Site
Controller process, network, or fabric connectivity recovery, and restored queues/outboxes still
require their normal replay/reconciliation path after the service actually restarts.

### CLI

`tools/backup/site_state.py` is a thin wrapper (mirroring `tools/backup/control_plane.py`)
around `mon.site_state_snapshot.main()`, exposing `snapshot`, `verify`, and `restore`
subcommands. No new `pyproject.toml` console-script entry was added; this tool is invoked the
same way `control_plane.py` is.

## Limitations

- Requires the Site Controller to be stopped or quiesced; this is not continuous replication.
- Not high availability and not multi-site disaster recovery.
- Secrets, certificates, and connector vault material are explicitly excluded and need a
  separate, deployment-specific backup policy -- this tool never touches them.
- A successful restore proves the seven durable databases round-tripped; it does not itself
  prove network or service recovery. Normal MON restart/reconciliation remains responsible for
  that, and restored queues/outboxes still require their usual replay/reconciliation path.
- `SQLiteCommandResultOutbox` and `SQLiteResponseUpdateOutbox` do not persist a scope-binding
  metadata row like the other five stores, so their tenant/site verification is a best-effort
  scan of up to 1000 pending records rather than a hard construction-time guarantee.
