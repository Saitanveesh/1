"""MON local LLM analyzer: ensure grounded, read-only, bounded prompts."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ANALYST_PATH = Path(__file__).resolve().parents[1] / "tools" / "mon_ai_analysis.py"
PORTAL_PATH = Path(__file__).resolve().parents[1] / "tools" / "mon-lab-portal.py"


def load_analyst():
    spec = importlib.util.spec_from_file_location("mon_analysis_under_test", ANALYST_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample_investigation():
    return {
        "incident": {
            "incident_id": "9398913b-3fb4-4f01-874f-87f6d71ed646",
            "title": "Repeated endpoint authentication failures",
            "severity": "MEDIUM",
            "confidence": 0.72,
            "entities": ["10.77.0.60", "linux-host:lab-pc5"],
        },
        "evidence": [
            {
                "evidence_id": "mon-auth-ref-1",
                "evidence_class": "IDENTITY",
                "source": "endpoint:linux-journal:sshd-session",
                "summary": "8 authentication failures observed in 300s",
                "confidence": 0.75,
            }
        ],
        "findings": [
            {
                "finding_id": "finding1",
                "detector_id": "endpoint-auth-failure-pressure",
                "src_ip": "10.77.0.60",
            }
        ],
        "affected_assets": [
            {
                "asset_id": "linux-host:lab-pc5",
                "display_name": "lab-pc5",
                "ip_addresses": ["10.77.0.50"],
            }
        ],
    }


def test_analyzer_requires_grounded_evidence_and_limits_prompt_text():
    module = load_analyst()
    evidence = sample_investigation()
    evidence["evidence"][0]["summary"] = "X" * 10000
    bundle = module.evidence_bundle(evidence)
    assert len(bundle["evidence"][0]["summary"]) == 370
    assert "10.77.0.60" in bundle["incident"]["entities"]
    evidence["evidence"] = []
    with pytest.raises(module.AnalystUnavailable):
        module.evidence_bundle(evidence)


def test_analysis_is_local_and_never_calls_response_endpoints(monkeypatch):
    module = load_analyst()
    calls = []
    monkeypatch.setattr(module, "get_evidence", lambda *_args: sample_investigation())

    def fake_fetch(req, timeout):
        calls.append((req.full_url, timeout, json.loads(req.data)))
        return {
            "model": "qwen3:4b",
            "message": {"content": "Observed facts: 8 failures [mon-auth-ref-1]."},
        }

    monkeypatch.setattr(module, "_fetch_json", fake_fetch)
    result = module.analyze_incident(
        "9398913b-3fb4-4f01-874f-87f6d71ed646", "mon-lab", "site-a", "jwt"
    )
    assert result["read_only"] is True
    assert result["evidence_ids"] == ["mon-auth-ref-1"]
    assert calls[0][0] == "http://127.0.0.1:11434/api/chat"
    assert calls[0][2]["model"] == "qwen3:4b"
    assert calls[0][2]["think"] is False
    assert "mon-auth-ref-1" in calls[0][2]["messages"][1]["content"]
    assert "/responses/" not in ANALYST_PATH.read_text()
    assert "subprocess" not in ANALYST_PATH.read_text()
    assert "nft" not in ANALYST_PATH.read_text()


def test_scope_and_incident_id_are_validated_before_backend_request(monkeypatch):
    module = load_analyst()

    def unexpected(*_args, **_kwargs):
        raise AssertionError("invalid scope must not invoke MON API")

    monkeypatch.setattr(module, "_fetch_json", unexpected)
    with pytest.raises(ValueError):
        module.get_evidence("bad-id", "mon-lab", "site-a", "secret")
    with pytest.raises(ValueError):
        module.get_evidence("9398913b-3fb4-4f01-874f-87f6d71ed646", "../bad", "site-a", "secret")


def test_portal_keeps_ai_readonly_authenticated_and_origin_checked():
    source = PORTAL_PATH.read_text()
    assert 'path == "/portal/ai/investigate"' in source
    assert "if not self._session()" in source
    assert 'self.headers.get("Origin") != ORIGIN' in source
    assert "AI_BUSY.acquire(blocking=False)" in source
    assert "result = analyze_incident(" in source
    assert "/api/v1/responses" not in source


def test_compact_ai_result_never_exposes_model_instruction_echo(monkeypatch):
    module = load_analyst()
    monkeypatch.setattr(module, "get_evidence", lambda *_args: sample_investigation())

    def response_with_old_verbose_thoughts(_req, timeout):
        return {
            "model": "qwen3:4b",
            "message": {
                "content": (
                    "We are given a JSON evidence. "
                    "Steps: read the JSON and explain instructions."
                )
            },
        }

    monkeypatch.setattr(module, "_fetch_json", response_with_old_verbose_thoughts)
    outcome = module.analyze_incident(
        "9398913b-3fb4-4f01-874f-87f6d71ed646", "mon-lab", "site-a", "jwt"
    )
    assert outcome["headline"].startswith("10.77.0.60")
    assert "8 authentication failures observed in 300s" in outcome["headline"]
    assert outcome["assessment"] == "Cause not established from current evidence."
    assert "We are given" not in outcome["analysis"]


def test_compact_ai_result_accepts_only_short_structured_advice(monkeypatch):
    module = load_analyst()
    monkeypatch.setattr(module, "get_evidence", lambda *_args: sample_investigation())

    def good_json(_req, timeout):
        return {
            "model": "qwen3:4b",
            "message": {
                "content": json.dumps({
                    "assessment": "Repeated SSH failures may indicate credential guessing.",
                    "next_check": "Compare source IP with approved maintenance activity.",
                })
            },
        }

    monkeypatch.setattr(module, "_fetch_json", good_json)
    answer = module.analyze_incident(
        "9398913b-3fb4-4f01-874f-87f6d71ed646", "mon-lab", "site-a", "jwt"
    )
    assert answer["assessment"].startswith("Repeated SSH")
    assert answer["next_check"].startswith("Compare source IP")
    assert "steps" not in answer["analysis"].lower()
