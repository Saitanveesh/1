# ruff: noqa: E501
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from mon.production_readiness import (
    MUST_REMAIN_NOT_PROVEN,
    ReadinessError,
    build_report,
    load_ledger,
    main,
    render_markdown,
    validate_ledger,
)

ROOT = Path(__file__).resolve().parents[1]


def test_committed_ledger_is_valid_and_markdown_is_current() -> None:
    ledger = load_ledger(ROOT)
    validate_ledger(ledger, ROOT)
    rendered = render_markdown(ledger)
    committed = (ROOT / "docs/production-readiness.md").read_text(encoding="utf-8")
    assert committed.replace("\r\n", "\n") == rendered


def test_external_and_unvalidated_items_stay_not_proven() -> None:
    ledger = load_ledger(ROOT)
    statuses = {item["id"]: item["status"] for item in ledger["subsystems"]}
    for ident in MUST_REMAIN_NOT_PROVEN:
        assert statuses[ident] == "NOT_PROVEN"


def test_ledger_rejects_missing_evidence_and_false_external_claims() -> None:
    ledger = load_ledger(ROOT)

    broken = copy.deepcopy(ledger)
    broken["subsystems"][0]["evidence"] = ["tests/does_not_exist.py"]
    with pytest.raises(ReadinessError, match="does not exist"):
        validate_ledger(broken, ROOT)

    claimed = copy.deepcopy(ledger)
    for item in claimed["subsystems"]:
        if item["id"] == "production-code-signing":
            item["status"] = "PROVEN"
    with pytest.raises(ReadinessError, match="production-code-signing"):
        validate_ledger(claimed, ROOT)

    scored = copy.deepcopy(ledger)
    scored["subsystems"][0]["limitation"] += " Confidence 99%."
    with pytest.raises(ReadinessError, match="percentage"):
        validate_ledger(scored, ROOT)

    invalid = copy.deepcopy(ledger)
    invalid["subsystems"][0]["status"] = "PASSED"
    with pytest.raises(ReadinessError, match="invalid status"):
        validate_ledger(invalid, ROOT)


def test_final_report_separates_repository_and_external_conclusions(tmp_path: Path) -> None:
    output = tmp_path / "final-readiness-report.json"
    assert main(["--root", str(ROOT), "--report", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["repository_engineering"]["complete"] is True
    assert report["external_production_certification"]["complete"] is False
    external_ids = {item["id"] for item in report["external_production_certification"]["not_proven"]}
    assert set(MUST_REMAIN_NOT_PROVEN) <= external_ids
    assert "confidence" not in json.dumps(report).replace("no confidence scores", "")
    assert all(ref["sha256"] for item in report["subsystems"] for ref in item["evidence"])
    assert len(report["required_gates"]) >= 19


def test_report_marks_repository_not_proven_as_incomplete() -> None:
    ledger = load_ledger(ROOT)
    for item in ledger["subsystems"]:
        if item["id"] == "deployable-packages":
            item["status"] = "NOT_PROVEN"
    report = build_report(ledger, ROOT)
    assert report["repository_engineering"]["complete"] is False
    assert "deployable-packages" in report["repository_engineering"]["repository_items_not_proven"]
