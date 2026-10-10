import ast
import runpy
from pathlib import Path

from mon.connectors.nftables_router import _safe_token

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "mon-three-final-containment.py"


def test_mon_three_final_containment_python_syntax() -> None:
    ast.parse(SCRIPT.read_text())


def test_mon_three_final_containment_requires_operator_approval_and_rolls_back() -> None:
    content = SCRIPT.read_text()
    assert "APPROVE PC6 120S" in content
    assert "REQUIRE_APPROVAL" in content
    assert '"approve": True' in content
    assert "/api/v1/responses/execute" in content
    assert "/api/v1/responses/{EXECUTION_ID}/rollback" in content
    assert "finally:" in content
    assert "10.77.0.60" in content
    assert "10.77.0.50" in content
    assert "sudo\", \"-n\", \"nft" in content
    assert "nft flush ruleset" not in content
    assert "wg-quick down" not in content


def test_mon_three_matches_router_hashed_uuid_marker() -> None:
    globals_ = runpy.run_path(str(SCRIPT), run_name="mon_marker_regression")
    execution_id = "18e5da2f-2555-436a-821a-df7671230d17"
    marker = globals_["owned_marker"](execution_id)
    assert marker == f"mon:v1:mon-lab:site-a:{_safe_token(execution_id)}"
    assert marker != f"mon:v1:mon-lab:site-a:{execution_id}"
    assert globals_["matching_rules"](
        f'ip saddr 10.77.0.60 drop comment "{marker}"',
        marker=marker,
    )
