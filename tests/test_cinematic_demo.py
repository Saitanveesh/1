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
    assert "ATTACK BEGINS" in chapters
    assert [chapter for chapter in chapters if chapter in lifecycle] == lifecycle
    assert chapters[-1] == "THE WHOLE IDEA"


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


def test_narrated_demo_uses_simple_story_copy() -> None:
    scenario = _scenario()

    assert scenario["presentation"]["theme"] == "black-white"
    assert scenario["presentation"]["voice_rate"] <= 0.9

    for scene in scenario["scenes"]:
        assert scene["headline"]
        assert scene["caption"]
        assert scene["lesson"]
        assert scene["term"]
        assert scene["term_definition"]
        assert len(scene["narration"].split()) >= 30
        assert scene["silent_seconds"] >= 20
        assert scene["view"] in {"map", "summary"}

        # The spoken explanation should not sound like product copy repeating
        # the product name in every sentence.
        assert scene["narration"].upper().split().count("MON") <= 1


def test_narrated_demo_preserves_response_safety_context() -> None:
    scenario = _scenario()
    scenes = {scene["chapter"]: scene for scene in scenario["scenes"]}

    contain_text = " ".join(
        [
            scenes["CONTAIN"]["caption"],
            scenes["CONTAIN"]["lesson"],
            scenes["CONTAIN"]["term"],
            scenes["CONTAIN"]["term_definition"],
            scenes["CONTAIN"]["narration"],
        ]
    ).lower()
    verify_text = scenes["VERIFY"]["narration"].lower()
    recover_text = scenes["RECOVER"]["narration"].lower()

    assert "blast radius" in contain_text
    assert "ttl" in contain_text
    assert "rollback" in contain_text
    assert "application and database online" in contain_text
    assert "local controller" in verify_text
    assert "cloud link" in verify_text
    assert "rollback" in recover_text
    assert "keeps watching" in recover_text


def test_narrated_demo_is_explicitly_a_non_operational_demo() -> None:
    scenario = _scenario()

    subtitle = scenario["subtitle"].lower()
    assert "demo" in subtitle
    assert "no real attack traffic" in subtitle

    final_scene = scenario["scenes"][-1]
    assert final_scene["view"] == "summary"
    assert not final_scene["route"]
