import subprocess
from pathlib import Path

DEPLOY = Path(__file__).resolve().parents[1] / "tools" / "mon-v2-ai-workspace-deploy.sh"


def test_ai_workspace_deployment_shell_syntax() -> None:
    result = subprocess.run(["bash", "-n", str(DEPLOY)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_ai_workspace_isolated_from_detection_and_containment() -> None:
    script = DEPLOY.read_text()
    assert "mon-three/console-v2" in script
    assert "src/AiAnalysis.tsx" in script
    assert "src/AiAnalysis.css" in script
    assert "npm run build" in script
    assert "AI Analysis" in script
    assert "mon-three-console-v2.service" in script
    assert "trap on_exit EXIT" in script
    assert "sudo systemctl restart \"$UNIT\"" in script
    assert "nft flush" not in script
    assert "wg-quick" not in script
    assert "systemctl restart mon-three-site" not in script
    assert "/api/v1/responses/execute" not in script


def test_verification_reads_complete_js_from_files() -> None:
    """Guard against partial pipe reads and silent Vite HTML fallbacks."""
    script = DEPLOY.read_text()
    assert 'Cache-Control: no-cache' in script
    assert '-D "$HEADERS" -o "$MODULE"' in script
    assert 'grep -Fq "$marker" "$MODULE"' in script
    assert 'printf \'%s\' "$html" | grep' not in script
    assert 'content-type:' in script
    assert 'operations-workspace' in script
    assert 'incident-chronology' in script
    assert 'ai-telemetry-tools' in script
    assert 'TRAFFIC OBSERVED NOW' in script
    assert 'lab_route_events' in script
