import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "mon-three-ux-deploy.sh"


def test_mon_three_ux_deploy_shell_syntax() -> None:
    result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_mon_three_ux_deploy_isolated_to_console_and_local_portal() -> None:
    script = SCRIPT.read_text()
    assert "sudo systemctl enable --now" in script
    assert "AmbientCapabilities=CAP_NET_RAW" in script
    assert "MON_PORTAL_PASSWORD_HASH=" in script
    assert "npm run build" in script
    assert "tar czf" in script
    assert "mon-three-site-router.service" not in script
    assert "wg-quick down" not in script
    assert "nft flush ruleset" not in script
    assert "/api/v1/responses/execute" not in script


def test_mon_three_ux_recovers_stopped_frontend_before_upgrade() -> None:
    source = SCRIPT.read_text()
    assert "mon-console-ux" in source
    assert "tmux new-session -d" in source
    assert "--host 0.0.0.0 --port 5173 --strictPort" in source
    assert "mon-three-code/console" in source
    assert "Port 5173 is occupied" in source
    assert '[[ "$online" != 1 ]]' in source
