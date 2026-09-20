from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import create_engine, text

from mon.audit_integrity import AuditIntegrityError
from mon.database import DatabaseStore
from mon.domain import Asset, AuditRecord, Finding, Incident, SecurityEvent, Severity
from mon.event_fabric import FabricReceipt, security_event_envelope

TOOL_VERSION = "1"
METADATA_SCHEMA_VERSION = 1


class BackupRestoreError(RuntimeError):
    pass


def _utcnow() -> str:
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


def sanitize_database_url(database_url: str) -> str:
    parsed = urlsplit(database_url)
    if parsed.password is None:
        return database_url
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = parsed.username or ""
    netloc += ":****"
    netloc += f"@{hostname}"
    if parsed.port is not None:
        netloc += f":{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def require_postgres_url(database_url: str) -> None:
    scheme = urlsplit(database_url).scheme
    if scheme not in {"postgresql", "postgresql+psycopg"}:
        raise BackupRestoreError("explicit PostgreSQL URL is required")


def native_postgres_url(database_url: str) -> str:
    if database_url.startswith("postgresql+psycopg://"):
        return "postgresql://" + database_url.removeprefix("postgresql+psycopg://")
    return database_url


def require_backup_path(path: Path) -> None:
    if str(path).strip() in {"", ".", "./"}:
        raise BackupRestoreError("backup destination must be an explicit file path")
    if path.exists() and path.is_dir():
        raise BackupRestoreError("backup destination must be a file, not a directory")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_command(argv: list[str]) -> None:
    completed = subprocess.run(argv, check=False, text=True, capture_output=True)
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or argv[0]
        raise BackupRestoreError(message)


def query_scalar(database_url: str, sql: str) -> str:
    completed = subprocess.run(
        [
            "psql",
            native_postgres_url(database_url),
            "--no-password",
            "--tuples-only",
            "--no-align",
            "-c",
            sql,
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "psql failed"
        raise BackupRestoreError(message)
    return completed.stdout.strip()


def source_commit() -> str:
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


def backup(database_url: str, output: Path) -> Path:
    require_postgres_url(database_url)
    require_backup_path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()
    run_command(
        [
            "pg_dump",
            "--format=custom",
            "--no-owner",
            "--no-acl",
            "--file",
            str(output),
            native_postgres_url(database_url),
        ]
    )
    metadata = {
        "schema_version": METADATA_SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "source_commit": source_commit(),
        "created_at_utc": _utcnow(),
        "backup_artifact": output.name,
        "backup_sha256": sha256_file(output),
        "postgres_major_version": query_scalar(
            database_url,
            "SHOW server_version_num",
        )[:2],
    }
    metadata_path = output.with_suffix(output.suffix + ".metadata.json")
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return metadata_path


def database_is_empty(database_url: str) -> bool:
    count = query_scalar(
        database_url,
        "SELECT count(*) FROM pg_class "
        "WHERE relkind IN ('r','p','v','m','S','f') "
        "AND relnamespace NOT IN ("
        "SELECT oid FROM pg_namespace "
        "WHERE nspname IN ('pg_catalog','information_schema') "
        "OR nspname LIKE 'pg_toast%')",
    )
    return count == "0"


def restore(database_url: str, backup_path: Path, *, allow_nonempty: bool = False) -> None:
    require_postgres_url(database_url)
    if not backup_path.is_file():
        raise BackupRestoreError("backup artifact does not exist")
    if not allow_nonempty and not database_is_empty(database_url):
        raise BackupRestoreError("restore target is not empty; refusing overwrite")
    metadata_path = backup_path.with_suffix(backup_path.suffix + ".metadata.json")
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text())
        if metadata.get("backup_sha256") != sha256_file(backup_path):
            raise BackupRestoreError("backup checksum does not match metadata")
    run_command(
        [
            "pg_restore",
            "--exit-on-error",
            "--no-owner",
            "--no-acl",
            "--dbname",
            native_postgres_url(database_url),
            str(backup_path),
        ]
    )


def _table_count(database_url: str, table: str) -> int:
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            return int(connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one())
    finally:
        engine.dispose()


def verify(database_url: str) -> None:
    store = DatabaseStore(database_url)
    try:
        if len(store.list_events("backup-tenant-a", "backup-site-1")) != 1:
            raise BackupRestoreError("restored event count mismatch")
        if store.get_event("backup-tenant-b", "backup-site-1", "backup-event-a") is not None:
            raise BackupRestoreError("tenant isolation failed after restore")
        if store.get_asset("backup-tenant-a", "backup-site-1", "asset-a") is None:
            raise BackupRestoreError("restored asset identity missing")
        if not store.list_findings("backup-tenant-a", "backup-site-1"):
            raise BackupRestoreError("restored finding missing")
        if not store.list_incidents("backup-tenant-a", "backup-site-1"):
            raise BackupRestoreError("restored incident missing")
        if not store.get_fabric_receipt("backup-tenant-a", "backup-site-1", "backup-event-a"):
            raise BackupRestoreError("restored fabric receipt missing")
        try:
            records = store.list_audit_records("backup-tenant-a", "backup-site-1")
        except AuditIntegrityError as exc:
            raise BackupRestoreError(str(exc)) from exc
        if len(records) != 1:
            raise BackupRestoreError("restored audit record count mismatch")
    finally:
        store.close()

    if _table_count(database_url, "alembic_version") != 1:
        raise BackupRestoreError("migration head is not restored")


def seed(database_url: str) -> None:
    now = dt.datetime(2026, 9, 20, 8, 0, tzinfo=dt.UTC)
    store = DatabaseStore(database_url)
    try:
        event_a = SecurityEvent(
            event_id="backup-event-a",
            tenant_id="backup-tenant-a",
            site_id="backup-site-1",
            sensor_id="backup-sensor-a",
            observed_at=now,
            category="backup.restore.test",
            asset_id="asset-a",
            src_ip="10.10.0.5",
            dst_ip="10.10.0.10",
            protocol="tcp",
        )
        event_b = event_a.model_copy(
            update={
                "event_id": "backup-event-b",
                "tenant_id": "backup-tenant-b",
                "asset_id": "asset-b",
            }
        )
        store.add_event(event_a)
        store.add_event(event_b)
        store.add_asset(
            Asset(
                asset_id="asset-a",
                tenant_id="backup-tenant-a",
                site_id="backup-site-1",
                display_name="backup asset a",
                ip_addresses={"10.10.0.5"},
            )
        )
        finding = Finding(
            finding_id="finding-a",
            tenant_id="backup-tenant-a",
            site_id="backup-site-1",
            detector_id="backup-detector",
            title="Synthetic backup verification finding",
            severity=Severity.MEDIUM,
            confidence=0.8,
            asset_id="asset-a",
        )
        store.add_finding(finding)
        store.add_incident(
            Incident(
                incident_id="incident-a",
                tenant_id="backup-tenant-a",
                site_id="backup-site-1",
                title="Synthetic backup verification incident",
                severity=Severity.MEDIUM,
                confidence=0.8,
                affected_asset_ids={"asset-a"},
                finding_ids={finding.finding_id},
            )
        )
        envelope = security_event_envelope(event_a, produced_at=now + dt.timedelta(seconds=1))
        store.add_fabric_receipt(
            FabricReceipt(
                event_id=event_a.event_id,
                tenant_id=event_a.tenant_id,
                site_id=event_a.site_id,
                envelope_sha256=envelope.canonical_sha256,
                envelope_json=envelope.canonical_json(),
                received_at=now + dt.timedelta(seconds=2),
            )
        )
        store.add_audit_record(
            AuditRecord(
                audit_id="audit-a",
                tenant_id="backup-tenant-a",
                site_id="backup-site-1",
                actor_id="backup-ci",
                category="BACKUP_RESTORE",
                object_type="database",
                object_id="control-plane",
                action="SEED",
                outcome="APPLIED",
                occurred_at=now,
                details={"purpose": "logical backup restore verification"},
            )
        )
    finally:
        store.close()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="MON PostgreSQL logical backup tooling")
    sub = parser.add_subparsers(dest="command", required=True)
    backup_parser = sub.add_parser("backup")
    backup_parser.add_argument("--database-url", required=True)
    backup_parser.add_argument("--output", required=True, type=Path)
    restore_parser = sub.add_parser("restore")
    restore_parser.add_argument("--database-url", required=True)
    restore_parser.add_argument("--backup", required=True, type=Path)
    restore_parser.add_argument("--allow-nonempty", action="store_true")
    seed_parser = sub.add_parser("seed")
    seed_parser.add_argument("--database-url", required=True)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--database-url", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "backup":
            metadata_path = backup(args.database_url, args.output)
            print(metadata_path)
        elif args.command == "restore":
            restore(args.database_url, args.backup, allow_nonempty=args.allow_nonempty)
        elif args.command == "seed":
            seed(args.database_url)
        elif args.command == "verify":
            verify(args.database_url)
    except BackupRestoreError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
