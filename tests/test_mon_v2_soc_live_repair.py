import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "mon-v2-soc-live-repair.sh"


def test_soc_repair_shell_is_parseable() -> None:
    result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_soc_repair_verifies_real_packet_events_and_preserves_live_controls() -> None:
    script = SCRIPT.read_text()
    assert 'mon_ai_analysis.py' in script
    assert 'mon-lab-portal.py' in script
    assert 'src/PacketObservability.tsx' in script
    assert 'capture.get("raw_frames",0)>0' in script
    assert 'capture.get("events")' in script
    assert "no fabricated packets" in script
    assert "GRAFANA STATUS:" in script
    assert "sudo docker compose" in script
    assert "will NOT be installed automatically" in script
    assert "nft flush" not in script
    assert "wg-quick" not in script
    assert "systemctl restart mon-three-site" not in script
    assert "kill -TERM" not in script
