"""Static regression checks for the conservative three-PC startup helper."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "mon-three-lab-operator.sh"

def test_shell_syntax():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)

def test_help_has_no_side_effects():
    result = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 2
    assert "arm-reboot" in result.stdout

def test_script_never_recreates_live_db_or_flashes_network():
    text = SCRIPT.read_text()
    assert "mon-three-postgres" in text
    assert 'docker container inspect "$DB"' in text
    for forbidden in ("docker run", "docker rm", "compose down", "docker volume rm", "nft flush", "wg set", "wg-quick down"):
        assert forbidden not in text

def test_remote_actions_require_ssh_trust_and_sudo_safety():
    text = SCRIPT.read_text()
    assert "BatchMode=yes" in text
    assert "StrictHostKeyChecking=yes" in text
    assert "sudo -n systemctl start" in text
    assert "operator.jwt" not in text
