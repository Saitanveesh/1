import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "mon-three-router-readiness.sh"


def test_mon_three_router_readiness_syntax() -> None:
    result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_mon_three_router_requires_explicit_policy_approval() -> None:
    source = SCRIPT.read_text()
    assert "mon-three-site" in source
    assert "AmbientCapabilities=CAP_NET_ADMIN" in source
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in source
    assert "NoNewPrivileges=true" in source
    assert "sudo systemctl disable --now" in source
    assert "/api/v1/responses/plan" in source
    assert "/api/v1/responses/execute" not in source
    assert "wg-quick down" not in source
    assert "iptables -F" not in source
    assert "nft flush ruleset" not in source
    assert "nft add rule" not in source
