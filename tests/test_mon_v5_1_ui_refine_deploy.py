from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "tools/mon-v5-1-ui-refine-deploy.sh"


def test_v5_1_shell_syntax_and_rollback():
    result = subprocess.run(["bash", "-n", str(DEPLOY)], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    s = DEPLOY.read_text()
    assert "trap on_exit EXIT" in s
    assert "MUTATED=1" in s
    assert "PASSED=1" in s
    assert "npm run build" in s


def test_v5_1_only_replaces_web_files_not_core_services():
    s = DEPLOY.read_text()
    assert "src/Incident3D.tsx" in s
    assert "src/styles.css" in s
    assert "src/PacketObservability.tsx" in s
    assert "src/SocGauges.css" in s
    assert "mon-three-console-v2.service" in s
    assert "systemctl restart mon-three-site" not in s
    assert "systemctl restart mon-three-lab-portal" not in s
    assert "wg-quick" not in s
    assert "nft flush" not in s
    assert "iptables -F" not in s
    assert "apt-get" not in s
    assert "docker compose" not in s


def test_ui_compact_command_desk_and_evidence_rail_exist():
    app = (ROOT / "console/src/App.tsx").read_text()
    scene = (ROOT / "console/src/Incident3D.tsx").read_text()
    css = (ROOT / "console/src/Incident3D.css").read_text()
    assert "mon-single-console" in app
    assert "mon-command-desk-grid" in app
    assert "compact />" in app
    assert "mon3d-studio-grid" in scene
    assert "scene-inspector" in scene
    assert "mon3d-rail-playback" in scene
    assert "ResizeObserver" in scene
    assert ".mon3d-rail" in css
