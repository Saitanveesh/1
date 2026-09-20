from __future__ import annotations

import json
import subprocess

import pytest

from mon import control_plane_backup


def test_backup_refuses_empty_or_directory_destination(tmp_path) -> None:
    with pytest.raises(control_plane_backup.BackupRestoreError, match="file"):
        control_plane_backup.require_backup_path(tmp_path)


def test_backup_requires_postgresql_url() -> None:
    with pytest.raises(control_plane_backup.BackupRestoreError, match="PostgreSQL URL"):
        control_plane_backup.require_postgres_url("sqlite:///tmp.db")


def test_sanitize_database_url_removes_password() -> None:
    url = control_plane_backup.sanitize_database_url(
        "postgresql://mon:secret@example.test:5432/mon"
    )

    assert "secret" not in url
    assert "mon:****@example.test:5432" in url


def test_native_postgres_url_strips_sqlalchemy_psycopg_driver() -> None:
    assert control_plane_backup.native_postgres_url(
        "postgresql+psycopg://mon:secret@example.test/mon"
    ) == "postgresql://mon:secret@example.test/mon"


def test_pg_dump_failure_returns_nonzero_without_printing_password(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    def fake_run(argv, check, text, capture_output):  # noqa: ANN001
        assert check is False
        assert text is True
        assert capture_output is True
        assert argv[0] == "pg_dump"
        return subprocess.CompletedProcess(argv, 1, "", "pg_dump failed")

    monkeypatch.setattr(control_plane_backup.subprocess, "run", fake_run)

    rc = control_plane_backup.main(
        [
            "backup",
            "--database-url",
            "postgresql://mon:secret@example.test/mon",
            "--output",
            str(tmp_path / "backup.dump"),
        ]
    )

    captured = capsys.readouterr()
    assert rc == 1
    assert "pg_dump failed" in captured.err
    assert "secret" not in captured.err


def test_backup_metadata_has_checksum_and_no_credentials(tmp_path, monkeypatch) -> None:
    backup_path = tmp_path / "control-plane.dump"

    def fake_run(argv, check, text, capture_output):  # noqa: ANN001
        if argv[0] == "pg_dump":
            backup_path.write_bytes(b"backup-bytes")
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[0] == "psql":
            return subprocess.CompletedProcess(argv, 0, "160000\n", "")
        if argv[0] == "git":
            return subprocess.CompletedProcess(argv, 0, "abc123\n", "")
        raise AssertionError(argv)

    monkeypatch.setattr(control_plane_backup.subprocess, "run", fake_run)

    metadata_path = control_plane_backup.backup(
        "postgresql://mon:secret@example.test/mon",
        backup_path,
    )
    metadata = json.loads(metadata_path.read_text())

    assert metadata["backup_sha256"] == control_plane_backup.sha256_file(backup_path)
    assert metadata["postgres_major_version"] == "16"
    assert "secret" not in metadata_path.read_text()
    assert "postgresql://" not in metadata_path.read_text()


def test_restore_refuses_nonempty_target_before_pg_restore(tmp_path, monkeypatch) -> None:
    backup_path = tmp_path / "control-plane.dump"
    backup_path.write_bytes(b"backup-bytes")
    called = []

    def fake_run(argv, check, text, capture_output):  # noqa: ANN001
        called.append(argv[0])
        return subprocess.CompletedProcess(argv, 0, "1\n", "")

    monkeypatch.setattr(control_plane_backup.subprocess, "run", fake_run)

    with pytest.raises(control_plane_backup.BackupRestoreError, match="not empty"):
        control_plane_backup.restore("postgresql://mon@example.test/restore", backup_path)

    assert called == ["psql"]


def test_restore_rejects_corrupted_backup_checksum(tmp_path, monkeypatch) -> None:
    backup_path = tmp_path / "control-plane.dump"
    backup_path.write_bytes(b"backup-bytes")
    backup_path.with_suffix(".dump.metadata.json").write_text(
        json.dumps({"backup_sha256": "0" * 64})
    )

    def fake_run(argv, check, text, capture_output):  # noqa: ANN001
        return subprocess.CompletedProcess(argv, 0, "0\n", "")

    monkeypatch.setattr(control_plane_backup.subprocess, "run", fake_run)

    with pytest.raises(control_plane_backup.BackupRestoreError, match="checksum"):
        control_plane_backup.restore("postgresql://mon@example.test/restore", backup_path)
