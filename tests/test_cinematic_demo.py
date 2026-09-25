import json
from pathlib import Path

SCENARIO_PATH = (
    Path(__file__).resolve().parents[1] / "demo" / "mon_cinematic" / "scenario.json"
)


def _scenario() -> dict[str, object]:
    return json.loads(SCENARIO_PATH.read_text(encoding="utf-8"))


def test_narrated_demo_covers_full_mon_lifecycle_in_order() -> None:
    scenario = _scenario()
    scenes = scenario["scenes"]
    lifecycle = [
        "DISCOVER",
        "DETECT",
        "CORRELATE",
        "TRACE",
        "CONTAIN",
        "VERIFY",
        "RECOVER",
    ]

    chapters = [scene["chapter"] for scene in scenes]

    assert chapters[0] == "INTRO"
    assert "CASE" in chapters
    assert [chapter for chapter in chapters if chapter in lifecycle] == lifecycle
    assert chapters[-1] == "WHY MON"


def test_narrated_demo_routes_reference_known_nodes_and_links() -> None:
    scenario = _scenario()
    node_ids = {node["id"] for node in scenario["nodes"]}
    links = {
        frozenset((link["from"], link["to"]))
        for link in scenario["links"]
    }

    for scene in scenario["scenes"]:
        assert set(scene["focus"]) <= node_ids
        for route in scene["route"]:
            assert set(route) <= node_ids
            for source, target in zip(route, route[1:], strict=False):
                assert frozenset((source, target)) in links


def test_narrated_demo_is_content_first_and_explains_each_scene() -> None:
    scenario = _scenario()

    assert scenario["presentation"]["theme"] == "black-white"
    assert scenario["presentation"]["voice_rate"] <= 0.9

    for scene in scenario["scenes"]:
        assert scene["title"]
        assert scene["happening"]
        assert scene["mon_action"]
        assert scene["impact"]
        assert scene["term"]
        assert scene["term_definition"]
        assert len(scene["narration"].split()) >= 35
        assert scene["silent_seconds"] >= 20


def test_narrated_demo_preserves_response_safety_context() -> None:
    scenario = _scenario()
    scenes = {scene["chapter"]: scene for scene in scenario["scenes"]}

    contain_text = " ".join(
        [
            scenes["CONTAIN"]["happening"],
            scenes["CONTAIN"]["mon_action"],
            scenes["CONTAIN"]["impact"],
            scenes["CONTAIN"]["narration"],
        ]
    ).lower()
    verify_text = scenes["VERIFY"]["narration"].lower()
    recover_text = scenes["RECOVER"]["narration"].lower()

    assert "blast radius" in contain_text
    assert "ttl" in contain_text
    assert "rollback" in contain_text
    assert "critical application and database remain online" in contain_text
    assert "local site controller" in verify_text
    assert "saas" in verify_text
    assert "rollback" in recover_text
    assert "under observation" in recover_text


def test_narrated_demo_is_explicitly_synthetic() -> None:
    scenario = _scenario()

    assert "synthetic" in scenario["subtitle"].lower()
    case_scene = next(scene for scene in scenario["scenes"] if scene["chapter"] == "CASE")
    assert "synthetic" in case_scene["happening"].lower()
