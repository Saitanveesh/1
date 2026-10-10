import ast
from pathlib import Path

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
