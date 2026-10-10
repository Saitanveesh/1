import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "mon-three-ui-v2-isolated.sh"


def test_isolated_mon_v2_shell_syntax() -> None:
    run = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr


def test_v2_never_modifies_existing_site_router_or_original_console() -> None:
    s = SCRIPT.read_text()
    assert 'PORT=5174' in s
    assert '5173' in s
    assert "console-v2-stage" in s
    assert 'git -C "$CODE" archive "$SOURCE_PIN" console' in s
    assert 'mv -- "$STAGING/console" "$APP"' in s
    assert 'mon-three-console-v2.service' in s
    assert 'json_ready "http://$HOST_IP:$PORT/portal/health"' in s
    assert '"NoNewPrivileges=true"' not in s  # systemd directives stay literal
    assert 'NoNewPrivileges=true' in s
    assert 'kill -TERM' not in s
    assert 'sudo npm' not in s
    assert 'nft flush' not in s
    assert 'wg-quick' not in s
    assert 'mon-three-site-router.service' not in s


def test_v2_uses_existing_password_verifier_and_requires_capture_json() -> None:
    s = SCRIPT.read_text()
    assert 'MON_PORTAL_PASSWORD_HASH=scrypt:' in s
    assert 'MON_PORTAL_ORIGIN=http://' in s
    assert 'data.get("state")=="READY"' in s
    assert 'data.get("capture")=="CAPTURING"' in s
    assert 'sudo cp -p -- "$BACKUP_ENV" "$PORTAL_ENV"' in s
    assert 'INSTALL_COMPLETE=1' in s
