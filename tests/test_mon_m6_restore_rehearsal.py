"""Static regression tests for the disposable PostgreSQL restore rehearsal."""

import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "mon-m6-restore-rehearsal.sh"


def test_restore_rehearsal_shell_syntax():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def test_restore_rehearsal_requires_arguments():
    result = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 2
    assert "64_CHARACTER_SHA256" in result.stderr


def test_restore_rehearsal_never_targets_live_database():
    script = SCRIPT.read_text()
    assert "mon-three-postgres" in script
    assert "--network none" in script
    assert "--rm" in script
    assert "trap cleanup EXIT" in script
    assert "sha256sum --check --status" in script
    assert "pg_restore --list" in script
    assert "--exit-on-error --single-transaction" in script
    assert "--no-owner --no-privileges" in script
    assert "--tmpfs /var/lib/postgresql/data" in script
    assert "SOURCE_TABLES=" in script
    assert "SOURCE_RLS=" in script
    forbidden = (
        "docker stop mon-three-postgres",
        "docker rm mon-three-postgres",
        "docker volume rm",
        "docker compose down",
        "nft flush",
        "wg set",
        "wg-quick down",
    )
    for command in forbidden:
        assert command not in script
