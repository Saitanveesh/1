import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "mon-three-one-shot.sh"


def test_mon_three_one_shot_bash_syntax() -> None:
    assert SCRIPT.is_file()
    result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_mon_three_one_shot_safety_boundaries() -> None:
    script = SCRIPT.read_text()
    assert "pc-5@10.77.0.50" in script
    assert "refs/heads/$FIX_BRANCH" in script
    assert "mon-pc5-endpoint" in script
    assert "SYSLOG_IDENTIFIER=unit" in script
    assert "ssh -tt" in script
    assert "WireGuard, certificates, firewall" in script
    assert "wg-quick down" not in script
    assert "iptables -F" not in script
    assert "nft flush ruleset" not in script
    assert "StrictHostKeyChecking=no" not in script
