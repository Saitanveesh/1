import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PC6 = ROOT / "tools" / "mon-pc6-baseline-traffic.sh"
V2 = ROOT / "tools" / "mon-v2-live-flow-update.sh"


def test_pc6_lab_generator_syntax_and_scope() -> None:
    result = subprocess.run(["bash", "-n", str(PC6)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    code = PC6.read_text()
    assert "10.77.0.60" in code and "10.77.0.50" in code
    assert " -i 2 " in code
    assert "ping -n -c 1 -W 2" in code
    assert "Restart=always" in code
    assert "StandardOutput=null" in code
    assert "ssh " not in code and "hydra" not in code
    assert "wg-quick down" not in code


def test_v2_chart_update_is_isolated_and_reversible() -> None:
    result = subprocess.run(["bash", "-n", str(V2)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    code = V2.read_text()
    assert "mon-three/console-v2" in code
    assert "tar -xzf" in code and "tar -czf" in code
    assert "npm run build" in code
    assert "SWAPPED=0" in code
    assert "kill -TERM" not in code
    assert "sudo npm" not in code
    assert "nft flush" not in code
