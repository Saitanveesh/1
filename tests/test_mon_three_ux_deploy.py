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
    assert "Port 5173 occupied and its PID cannot be read" in source
    assert '[[ "$online" != 1 ]]' in source


def test_frontend_uses_actual_bound_interface_before_restart() -> None:
    script = SCRIPT.read_text()
    assert "probe_console()" in script
    assert "100.75.116.62" in script
    assert 'CONSOLE_URL="http://$address:5173"' in script
    assert '$CONSOLE_URL/portal/health' in script
    assert 'cmd=$(tr' in script
    assert 'live_root=$(readlink -f' in script
    assert "unrecognized service; refusing to stop it" in script


def test_build_tool_recovery_requires_real_tsc_binary_and_dev_dependencies() -> None:
    source = SCRIPT.read_text()
    assert '"$FRONTEND/node_modules/.bin/tsc"' in source
    assert '"$FRONTEND/node_modules/.bin/vite"' in source
    assert "npm install --include=dev --no-audit --no-fund --no-save --package-lock=false" in source
    assert "npm run build" in source
    assert "set -euo pipefail" in source
    assert "set -Eeuo pipefail" not in source


def test_upgrade_repairs_mixed_console_ownership_before_npm() -> None:
    source = SCRIPT.read_text()
    assert 'EXPECTED_FRONTEND=$(realpath -e "$CODE/console")' in source
    assert '[[ "$FRONTEND" == "$EXPECTED_FRONTEND"' in source
    assert 'sudo chown -hR --' in source
    assert 'find "$FRONTEND/node_modules" -xdev' in source
    assert source.index("sudo chown -hR --") < source.index("npm install --include=dev")
    assert "sudo npm" not in source
    assert "chown -R pc-2:pc-2 $HOME" not in source
