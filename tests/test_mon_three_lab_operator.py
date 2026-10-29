"""Static regression checks for the conservative three-PC startup helper."""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "mon-three-lab-operator.sh"


def test_shell_syntax():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def test_help_has_no_side_effects():
    result = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 2
    assert "arm-reboot" in result.stdout


def test_script_never_recreates_live_db_or_flushes_network():
    content = SCRIPT.read_text()
    assert "mon-three-postgres" in content
    assert 'docker container inspect "$DB"' in content
    forbidden = (
        "docker run",
        "docker rm",
        "compose down",
        "docker volume rm",
        "nft flush",
        "wg set",
        "wg-quick down",
    )
    for command in forbidden:
        assert command not in content


def test_remote_actions_require_ssh_trust_and_sudo_safety():
    content = SCRIPT.read_text()
    assert "BatchMode=yes" in content
    assert "StrictHostKeyChecking=yes" in content
    assert "sudo -n systemctl start" in content
    assert "operator.jwt" not in content
