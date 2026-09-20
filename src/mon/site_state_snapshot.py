"""Site Controller durable-state snapshot / verify / restore.

This is a **quiesced** snapshot tool. It does not claim cross-database
transactional consistency while the Site Controller is actively writing to
multiple SQLite databases concurrently: stop or quiesce the service before
calling `create_site_state_snapshot`. Each individual database is still
captured through SQLite's own backup API (never a raw copy of the live
`.db`/`-wal`/`-shm` files), so a single database is always internally
consistent as of the moment its backup ran; the quiescence requirement is
about consistency *between* the seven databases, not within any one of them.

The exact seven databases snapshotted here are derived directly from
`mon.site_service.build_site_service_resources` -- no other file under the
state directory (credentials, certificates, private keys, connector vault
material) is ever archived.

A successful restore proves the durable databases round-trip: it does not by
itself prove the Site Controller process, network, or fabric connectivity is
recovered. Normal MON restart/reconciliation remains responsible for actual
service recovery, and restored queues/outboxes still require their usual
replay/reconciliation path.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from mon.event_fabric_outbox import DurableFabricOutbox
from mon.site_analysis_store import SQLiteSiteAnalysisStore
from mon.site_command_outbox import SQLiteCommandResultOutbox
from mon.site_controller import SQLiteEventSpool
from mon.site_response_outbox import SQLiteResponseUpdateOutbox
from mon.site_response_store import SQLiteSiteResponseStore
from mon.site_sensor_trust import SQLiteSensorTrustStore

SNAPSHOT_SCHEMA_VERSION = 1
TOOL_VERSION = "1"
MANIFEST_FILENAME = "manifest.json"

_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_DATABASE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = 16
_MEMBER_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class SiteStateSnapshotError(RuntimeError):
    pass


# Exact allowlist, derived directly from build_site_service_resources
# (mon.site_service). Only these seven MON-owned durable databases are ever
# read from a state directory or written into a restore destination.
_DATABASE_STORES: dict[str, type] = {
    "event-spool.db": SQLiteEventSpool,
    "fabric-outbox.db": DurableFabricOutbox,
    "analysis-state.db": SQLiteSiteAnalysisStore,
    "response-state.db": SQLiteSiteResponseStore,
    "command-results.db": SQLiteCommandResultOutbox,
    "response-updates.db": SQLiteResponseUpdateOutbox,
    "sensor-trust.db": SQLiteSensorTrustStore,
}
DATABASE_FILENAMES: tuple[str, ...] = tuple(sorted(_DATABASE_STORES))

# SQLiteCommandResultOutbox and SQLiteResponseUpdateOutbox do not persist a
# scope-binding metadata row the way the other five stores do, so opening
# them with the wrong tenant/site never raises at construction time. For
# these two, tenant/site verification falls back to a best-effort scan of
# up to their first 1000 pending() records (that method's own bound) rather
# than a hard construction-time bind.
_SCOPE_UNBOUND_STORES = frozenset({"command-results.db", "response-updates.db"})


class SnapshotDatabaseEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    filename: str = Field(min_length=1, max_length=128)
    sha256: str = Field(min_length=64, max_length=64)
    size_bytes: int = Field(ge=0)


class SnapshotManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    tool_version: str = Field(min_length=1, max_length=32)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    created_at: dt.datetime
    source_commit: str = Field(min_length=1, max_length=128)
    databases: list[SnapshotDatabaseEntry]

    @model_validator(mode="after")
    def validate_manifest(self) -> SnapshotManifest:
        if self.schema_version != SNAPSHOT_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported snapshot manifest schema version: {self.schema_version}"
            )
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("snapshot manifest created_at must be timezone-aware")
        names = [entry.filename for entry in self.databases]
        if len(set(names)) != len(names):
            raise ValueError("snapshot manifest contains duplicate database filenames")
        if sorted(names) != sorted(DATABASE_FILENAMES):
            raise ValueError(
                "snapshot manifest database list does not match the expected allowlist"
            )
        return self


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_commit() -> str:
    env_sha = os.environ.get("GITHUB_SHA", "").strip()
    if env_sha:
        return env_sha
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=False,
        text=True,
        capture_output=True,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def _integrity_check(path: Path) -> None:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        row = connection.execute("PRAGMA integrity_check").fetchone()
        result = str(row[0]) if row else "unknown"
    except sqlite3.DatabaseError as exc:
        raise SiteStateSnapshotError(
            f"sqlite integrity check could not run for {path.name}: {exc}"
        ) from exc
    finally:
        connection.close()
    if result != "ok":
        raise SiteStateSnapshotError(
            f"sqlite integrity check failed for {path.name}: {result}"
        )


def _backup_database(source_path: Path, dest_path: Path) -> None:
    """Copy one SQLite database using SQLite's own backup API.

    This is never a raw filesystem copy of `.db`/`-wal`/`-shm` files: the
    backup API reads a transactionally consistent view of the source as of
    when the backup starts, the same mechanism `sqlite3 .backup` and the C
    `sqlite3_backup_*` API use.
    """
    if not source_path.is_file():
        raise SiteStateSnapshotError(f"source database is missing: {source_path}")
    try:
        source_conn = sqlite3.connect(f"file:{source_path.as_posix()}?mode=ro", uri=True)
    except sqlite3.OperationalError as exc:
        raise SiteStateSnapshotError(
            f"unable to open source database {source_path.name} for backup: {exc}"
        ) from exc
    try:
        dest_conn = sqlite3.connect(dest_path)
        try:
            source_conn.backup(dest_conn)
        finally:
            dest_conn.close()
    except sqlite3.DatabaseError as exc:
        raise SiteStateSnapshotError(
            f"sqlite backup failed for {source_path.name}: {exc}"
        ) from exc
    finally:
        source_conn.close()


def create_site_state_snapshot(
    state_dir: str | Path,
    output: str | Path,
    *,
    tenant_id: str,
    site_id: str,
) -> Path:
    """Create a quiesced snapshot ZIP archive of the seven durable databases.

    The Site Controller must be stopped or quiesced before calling this; see
    the module docstring. A failed snapshot never leaves a valid-looking
    partial artifact at `output`: the archive is built entirely in a
    temporary working directory and only atomically renamed into place after
    every database has been backed up, integrity-checked, and hashed.
    """
    state_dir = Path(state_dir)
    output = Path(output)
    if not tenant_id or not site_id:
        raise SiteStateSnapshotError("tenant_id and site_id are required")
    if not state_dir.is_dir():
        raise SiteStateSnapshotError(f"state directory does not exist: {state_dir}")
    if output.exists() and output.is_dir():
        raise SiteStateSnapshotError("snapshot output must be a file path, not a directory")

    missing = [name for name in DATABASE_FILENAMES if not (state_dir / name).is_file()]
    if missing:
        raise SiteStateSnapshotError(
            "state directory is missing expected durable database(s): " + ", ".join(missing)
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix=".mon-site-snapshot-", dir=str(output.parent)))
    staged_archive = output.parent / f".{output.name}.part-{os.getpid()}"
    try:
        entries: list[SnapshotDatabaseEntry] = []
        for name in DATABASE_FILENAMES:
            source_path = state_dir / name
            dest_path = work_dir / name
            _backup_database(source_path, dest_path)
            _integrity_check(dest_path)
            entries.append(
                SnapshotDatabaseEntry(
                    filename=name,
                    sha256=_sha256_file(dest_path),
                    size_bytes=dest_path.stat().st_size,
                )
            )

        manifest = SnapshotManifest(
            schema_version=SNAPSHOT_SCHEMA_VERSION,
            tool_version=TOOL_VERSION,
            tenant_id=tenant_id,
            site_id=site_id,
            created_at=_utcnow(),
            source_commit=_source_commit(),
            databases=entries,
        )
        manifest_path = work_dir / MANIFEST_FILENAME
        manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

        if staged_archive.exists():
            staged_archive.unlink()
        with zipfile.ZipFile(staged_archive, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.write(manifest_path, MANIFEST_FILENAME)
            for name in DATABASE_FILENAMES:
                archive.write(work_dir / name, name)
        os.replace(staged_archive, output)
        return output
    except Exception:
        if staged_archive.exists():
            staged_archive.unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def _safe_member_names(archive: zipfile.ZipFile) -> list[str]:
    infos = archive.infolist()
    if len(infos) > _MAX_ARCHIVE_MEMBERS:
        raise SiteStateSnapshotError("snapshot archive has too many members")
    names: list[str] = []
    for info in infos:
        name = info.filename
        if info.is_dir():
            raise SiteStateSnapshotError(f"snapshot archive contains a directory entry: {name}")
        if not _MEMBER_NAME_RE.fullmatch(name):
            raise SiteStateSnapshotError(f"unsafe snapshot archive member name: {name}")
        if Path(name).name != name:
            raise SiteStateSnapshotError(f"snapshot archive member path is not flat: {name}")
        names.append(name)
    if len(set(names)) != len(names):
        raise SiteStateSnapshotError("snapshot archive contains duplicate member names")
    return names


def _load_and_validate_archive(archive_path: Path, extract_dir: Path) -> SnapshotManifest:
    """Fully validate an archive and extract its databases into `extract_dir`.

    Extraction never uses `ZipFile.extractall()`: every member name is
    checked against a strict allowlist pattern first, then streamed out one
    at a time through `ZipFile.open()`, so a hostile archive member can
    never traverse outside `extract_dir` or masquerade as an unexpected
    file.
    """
    if not archive_path.is_file():
        raise SiteStateSnapshotError(f"snapshot archive does not exist: {archive_path}")
    try:
        archive = zipfile.ZipFile(archive_path)
    except zipfile.BadZipFile as exc:
        raise SiteStateSnapshotError(f"snapshot archive is not a valid zip file: {exc}") from exc

    with archive:
        names = _safe_member_names(archive)
        if MANIFEST_FILENAME not in names:
            raise SiteStateSnapshotError("snapshot archive is missing manifest.json")

        manifest_info = archive.getinfo(MANIFEST_FILENAME)
        if manifest_info.file_size > _MAX_MANIFEST_BYTES:
            raise SiteStateSnapshotError("snapshot manifest exceeds bounded size")
        try:
            manifest_raw = archive.read(MANIFEST_FILENAME)
        except (zipfile.BadZipFile, OSError) as exc:
            raise SiteStateSnapshotError(f"unable to read snapshot manifest: {exc}") from exc
        try:
            manifest_payload: Any = json.loads(manifest_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SiteStateSnapshotError(f"snapshot manifest is not valid JSON: {exc}") from exc
        try:
            manifest = SnapshotManifest.model_validate(manifest_payload)
        except ValidationError as exc:
            raise SiteStateSnapshotError(f"snapshot manifest failed validation: {exc}") from exc

        expected_members = {MANIFEST_FILENAME, *DATABASE_FILENAMES}
        actual_members = set(names)
        unexpected = actual_members - expected_members
        if unexpected:
            raise SiteStateSnapshotError(
                "snapshot archive contains unexpected member(s): "
                + ", ".join(sorted(unexpected))
            )
        missing_members = expected_members - actual_members
        if missing_members:
            raise SiteStateSnapshotError(
                "snapshot archive is missing expected member(s): "
                + ", ".join(sorted(missing_members))
            )

        entries_by_name = {entry.filename: entry for entry in manifest.databases}
        extract_dir.mkdir(parents=True, exist_ok=True)
        for name in DATABASE_FILENAMES:
            info = archive.getinfo(name)
            if info.file_size > _MAX_DATABASE_BYTES:
                raise SiteStateSnapshotError(f"snapshot database {name} exceeds bounded size")
            dest_path = extract_dir / name
            digest = hashlib.sha256()
            with archive.open(name) as source, dest_path.open("wb") as sink:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    sink.write(chunk)
            actual_sha256 = digest.hexdigest()
            actual_size = dest_path.stat().st_size
            expected_entry = entries_by_name[name]
            if actual_sha256 != expected_entry.sha256:
                raise SiteStateSnapshotError(f"checksum mismatch for {name}")
            if actual_size != expected_entry.size_bytes:
                raise SiteStateSnapshotError(f"size mismatch for {name}")
            _integrity_check(dest_path)

    return manifest


def _assert_outbox_scope(store: Any, tenant_id: str, site_id: str, name: str) -> None:
    for record in store.pending(limit=1000):
        if record.tenant_id != tenant_id or record.site_id != site_id:
            raise SiteStateSnapshotError(
                f"tenant/site scope mismatch found in {name} pending records"
            )


def _open_and_verify_stores(
    directory: Path, tenant_id: str, site_id: str
) -> dict[str, dict[str, object]]:
    """Open every restored database through its real MON store class.

    This both proves tenant/site metadata matches (the five metadata-bound
    stores raise ValueError at construction on mismatch) and returns each
    store's own `diagnostics()`, which is the representative durable-state
    proof used by restore's post-restore validation and by tests.
    """
    diagnostics: dict[str, dict[str, object]] = {}
    for name, store_class in _DATABASE_STORES.items():
        path = directory / name
        try:
            store = store_class(path, tenant_id=tenant_id, site_id=site_id)
        except ValueError as exc:
            raise SiteStateSnapshotError(
                f"tenant/site scope mismatch while opening {name}: {exc}"
            ) from exc
        try:
            if name in _SCOPE_UNBOUND_STORES:
                _assert_outbox_scope(store, tenant_id, site_id, name)
            diagnostics[name] = store.diagnostics()
        finally:
            store.close()
    return diagnostics


def verify_site_state_snapshot(
    archive_path: str | Path,
    *,
    expected_tenant_id: str | None = None,
    expected_site_id: str | None = None,
) -> SnapshotManifest:
    """Fully validate a snapshot archive without restoring it anywhere.

    ZIP extraction success alone is never treated as sufficient: this also
    validates manifest schema/version, the exact member set, every SHA-256
    and byte size, SQLite integrity, and (when the store persists a
    scope-binding metadata row) that the manifest's declared tenant/site
    actually matches what is inside the databases.
    """
    archive_path = Path(archive_path)
    with tempfile.TemporaryDirectory(prefix=".mon-site-verify-") as tmp:
        tmp_path = Path(tmp)
        manifest = _load_and_validate_archive(archive_path, tmp_path)
        if expected_tenant_id is not None and manifest.tenant_id != expected_tenant_id:
            raise SiteStateSnapshotError(
                "snapshot manifest tenant_id does not match the expected tenant"
            )
        if expected_site_id is not None and manifest.site_id != expected_site_id:
            raise SiteStateSnapshotError(
                "snapshot manifest site_id does not match the expected site"
            )
        _open_and_verify_stores(tmp_path, manifest.tenant_id, manifest.site_id)
    return manifest


def restore_site_state_snapshot(
    archive_path: str | Path,
    destination_dir: str | Path,
    *,
    tenant_id: str,
    site_id: str,
) -> tuple[SnapshotManifest, dict[str, dict[str, object]]]:
    """Restore a validated snapshot into a fresh (empty/nonexistent) directory.

    The full archive is validated (checksums, SQLite integrity, member set,
    manifest schema) before anything is written to `destination_dir`. The
    destination is written through a temporary staging directory and
    finalized with a single atomic rename, so a failure never leaves a
    half-restored directory reporting success. Post-restore, every database
    is reopened through its real MON store class from the final destination
    as representative proof durable state survived; this does not itself
    prove Site Controller process/network recovery.
    """
    archive_path = Path(archive_path)
    destination_dir = Path(destination_dir)
    if not tenant_id or not site_id:
        raise SiteStateSnapshotError("tenant_id and site_id are required")
    if destination_dir.exists():
        if not destination_dir.is_dir():
            raise SiteStateSnapshotError("restore destination must be a directory")
        if any(destination_dir.iterdir()):
            raise SiteStateSnapshotError(
                "restore destination already exists and is not empty; refusing by default"
            )

    with tempfile.TemporaryDirectory(prefix=".mon-site-restore-") as tmp:
        tmp_path = Path(tmp)
        manifest = _load_and_validate_archive(archive_path, tmp_path)
        if manifest.tenant_id != tenant_id:
            raise SiteStateSnapshotError(
                "snapshot manifest tenant_id does not match the restore target"
            )
        if manifest.site_id != site_id:
            raise SiteStateSnapshotError(
                "snapshot manifest site_id does not match the restore target"
            )

        destination_dir.parent.mkdir(parents=True, exist_ok=True)
        staging_dir = destination_dir.parent / f".{destination_dir.name}.restoring-{os.getpid()}"
        if staging_dir.exists():
            shutil.rmtree(staging_dir)
        staging_dir.mkdir(parents=True)
        try:
            for name in DATABASE_FILENAMES:
                shutil.copy2(tmp_path / name, staging_dir / name)
            if destination_dir.exists():
                destination_dir.rmdir()
            os.replace(staging_dir, destination_dir)
        except Exception:
            shutil.rmtree(staging_dir, ignore_errors=True)
            raise

    diagnostics = _open_and_verify_stores(destination_dir, tenant_id, site_id)
    return manifest, diagnostics


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="MON Site Controller durable-state snapshot/verify/restore tooling"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    snap = sub.add_parser("snapshot", help="create a quiesced Site Controller state snapshot")
    snap.add_argument("--state-dir", required=True, type=Path)
    snap.add_argument("--output", required=True, type=Path)
    snap.add_argument("--tenant-id", required=True)
    snap.add_argument("--site-id", required=True)

    verify = sub.add_parser("verify", help="verify a snapshot archive without restoring it")
    verify.add_argument("--archive", required=True, type=Path)
    verify.add_argument("--tenant-id", default=None)
    verify.add_argument("--site-id", default=None)

    restore = sub.add_parser(
        "restore", help="restore a snapshot archive into a new state directory"
    )
    restore.add_argument("--archive", required=True, type=Path)
    restore.add_argument("--destination", required=True, type=Path)
    restore.add_argument("--tenant-id", required=True)
    restore.add_argument("--site-id", required=True)

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "snapshot":
            output = create_site_state_snapshot(
                args.state_dir,
                args.output,
                tenant_id=args.tenant_id,
                site_id=args.site_id,
            )
            print(json.dumps({"status": "ok", "archive": str(output)}))
        elif args.command == "verify":
            manifest = verify_site_state_snapshot(
                args.archive,
                expected_tenant_id=args.tenant_id,
                expected_site_id=args.site_id,
            )
            print(manifest.model_dump_json())
        elif args.command == "restore":
            manifest, diagnostics = restore_site_state_snapshot(
                args.archive,
                args.destination,
                tenant_id=args.tenant_id,
                site_id=args.site_id,
            )
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "destination": str(args.destination),
                        "manifest": json.loads(manifest.model_dump_json()),
                        "diagnostics": diagnostics,
                    }
                )
            )
        else:  # pragma: no cover - argparse enforces valid subcommands
            raise SiteStateSnapshotError(f"unknown command: {args.command}")
    except SiteStateSnapshotError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
