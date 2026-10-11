import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "mon-v2-local-ai-deploy.sh"


def test_mon_v2_ai_installer_shell_syntax() -> None:
    result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_mon_v2_ai_installer_is_read_only_to_control_network_services() -> None:
    source = SCRIPT.read_text()
    assert "console-v2" in source
    assert "mon_ai_analysis.py" in source
    assert "npm run build" in source
    assert "systemctl restart mon-three-lab-portal.service" in source
    assert '"/portal/ai/investigate"' not in source  # path is constructed as full URL
    assert "/portal/ai/investigate" in source
    assert '"read_only"' in source
    assert "wg-quick down" not in source
    assert "nft flush" not in source
    assert "systemctl restart mon-three-site" not in source
    assert "kill -TERM" not in source
    assert "sudo npm" not in source


def test_mon_v2_ai_installer_retains_rollback_backups() -> None:
    script = SCRIPT.read_text()
    assert "original-portal.py" in script
    assert "original-ai.py" in script
    assert "ai-backup." in script
    assert "trap rollback EXIT" in script
    assert "SUCCESS=1" in script
