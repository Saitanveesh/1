from __future__ import annotations

import json
from pathlib import Path


SCENARIO_PATH = (
    Path(__file__).resolve().parents[1] / "demo" / "mon_cinematic" / "scenario.json"
)


def _scenario() -> dict[str, object]:
    return json.loads(SCENARIO_PATH.read_text(encoding="utf-8"))


def test_cinematic_demo_covers_full_mon_lifecycle_in_order() -> None:
    scenario = _scenario()
    stages = scenario["stages"]

    assert [stage["name"] for stage in stages] == [
        "DISCOVER",
        "DETECT",
        "CORRELATE",
        "TRACE",
        "CONTAIN",
        "VERIFY",
        "RECOVER",
    ]

    assert stages[0]["from"] == 0
    for previous, current in zip(stages, stages[1:], strict=True):
        assert previous["to"] == current["from"]
    assert stages[-1]["to"] == scenario["duration_seconds"]


def test_cinematic_demo_routes_reference_known_nodes_and_links() -> None:
    scenario = _scenario()
    node_ids = {node["id"] for node in scenario["nodes"]}
    links = {
        frozenset((link["from"], link["to"]))
        for link in scenario["links"]
    }

    for stage in scenario["stages"]:
        assert set(stage["focus"]) <= node_ids
        for route in stage["routes"]:
            assert set(route) <= node_ids
            for source, target in zip(route, route[1:], strict=True):
                assert frozenset((source, target)) in links


def test_cinematic_demo_preserves_response_safety_context() -> None:
    scenario = _scenario()

    for stage in scenario["stages"]:
        assert 0 <= stage["confidence"] <= 1
        assert stage["evidence"]
        assert stage["affected"]
        assert stage["decision"]
        assert stage["blast_radius"]
        assert "ttl" in stage

    contain = next(stage for stage in scenario["stages"] if stage["name"] == "CONTAIN")
    recover = next(stage for stage in scenario["stages"] if stage["name"] == "RECOVER")

    assert "rollback" in contain["plain"].lower()
    assert "ttl" in contain["plain"].lower()
    assert "rollback" in recover["plain"].lower()
    assert "0 remaining restrictions" == recover["blast_radius"]


def test_cinematic_demo_is_explicitly_synthetic() -> None:
    scenario = _scenario()
    assert "synthetic" in scenario["subtitle"].lower()
