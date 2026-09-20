"""Evidence-based production-readiness ledger validation, rendering and final report.

The ledger (docs/production-readiness.json) is the single source of truth. This module
refuses ledgers whose evidence files do not exist, whose external items claim PROVEN,
or that assign confidence percentages. It never invents a pass.
"""

# ruff: noqa: E501
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import httpx

STATUSES = ("PROVEN", "PARTIALLY_PROVEN", "NOT_PROVEN")
CATEGORIES = ("repository_controllable", "external")
MUST_REMAIN_NOT_PROVEN = (
    "production-code-signing",
    "enterprise-firewall-nac-appliances",
    "cloud-provider-enforcement",
    "upstream-isp-ddos-mitigation",
    "postgresql-ha-failover",
    "multi-region-disaster-recovery",
    "linux-distro-kernel-matrix",
    "windows-version-matrix",
    "customer-production-networks",
)
LEDGER_PATH = Path("docs/production-readiness.json")
MARKDOWN_PATH = Path("docs/production-readiness.md")


class ReadinessError(ValueError):
    pass


def load_ledger(root: Path) -> dict[str, Any]:
    try:
        ledger = json.loads((root / LEDGER_PATH).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReadinessError(f"ledger unreadable: {exc}") from exc
    if not isinstance(ledger, dict) or ledger.get("schema") != "mon.production-readiness-ledger.v1":
        raise ReadinessError("unexpected ledger schema")
    return ledger


def validate_ledger(ledger: dict[str, Any], root: Path) -> None:
    problems: list[str] = []
    seen: set[str] = set()
    subsystems = ledger.get("subsystems")
    if not isinstance(subsystems, list) or not subsystems:
        raise ReadinessError("ledger has no subsystems")
    for item in subsystems:
        ident = item.get("id", "<missing id>")
        if ident in seen:
            problems.append(f"duplicate subsystem id {ident}")
        seen.add(ident)
        for field in ("capability", "environment", "status", "limitation", "category"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                problems.append(f"{ident}: missing {field}")
        if item.get("status") not in STATUSES:
            problems.append(f"{ident}: invalid status {item.get('status')!r}")
        if item.get("category") not in CATEGORIES:
            problems.append(f"{ident}: invalid category")
        if item.get("category") == "external" and item.get("status") == "PROVEN":
            problems.append(f"{ident}: an external item cannot be PROVEN by repository evidence")
        evidence = item.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            problems.append(f"{ident}: no evidence references")
            continue
        for reference in evidence:
            if not (root / reference).is_file():
                problems.append(f"{ident}: evidence file does not exist: {reference}")
        if item.get("status") == "PROVEN" and not any(
            str(ref).startswith((".github/workflows/", "tests/", "e2e/")) for ref in evidence
        ):
            problems.append(f"{ident}: PROVEN requires a test or workflow reference")
    by_id = {item.get("id"): item for item in subsystems}
    for ident in MUST_REMAIN_NOT_PROVEN:
        entry = by_id.get(ident)
        if entry is None:
            problems.append(f"required external item missing: {ident}")
        elif entry.get("status") != "NOT_PROVEN":
            problems.append(f"{ident} must remain NOT_PROVEN")
    gates = ledger.get("required_gates")
    if not isinstance(gates, list) or not gates:
        problems.append("ledger has no required_gates")
    else:
        for gate in gates:
            if not (root / gate.get("workflow", "")).is_file():
                problems.append(f"gate workflow missing: {gate}")
    if re.search(r"\d+(\.\d+)?\s*%", json.dumps(ledger)):
        problems.append("ledger must not contain percentage confidence figures")
    if problems:
        raise ReadinessError("; ".join(problems))


def render_markdown(ledger: dict[str, Any]) -> str:
    lines = [
        "# MON production-readiness ledger",
        "",
        "<!-- Generated from docs/production-readiness.json by tools/final_readiness_report.py --render-md. Do not edit by hand. -->",
        "",
        ledger["statement"],
        "",
        "Status values: `PROVEN`, `PARTIALLY_PROVEN`, `NOT_PROVEN`.",
        "",
    ]
    for category, title in (
        ("repository_controllable", "Repository-controllable subsystems"),
        ("external", "External / not exercised by this repository"),
    ):
        lines += [f"## {title}", ""]
        lines += [
            "| Subsystem | Capability | Evidence | Last validated environment | Status | Limitation |",
            "|---|---|---|---|---|---|",
        ]
        for item in ledger["subsystems"]:
            if item["category"] != category:
                continue
            evidence = "<br>".join(f"`{ref}`" for ref in item["evidence"])
            lines.append(
                f"| `{item['id']}` | {item['capability']} | {evidence} | {item['environment']} "
                f"| **{item['status']}** | {item['limitation']} |"
            )
        lines.append("")
    lines += ["## Required release gates", "", "| Gate | Workflow |", "|---|---|"]
    lines += [f"| {gate['name']} | `{gate['workflow']}` |" for gate in ledger["required_gates"]]
    lines.append("")
    return "\n".join(lines)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _latest_run(repo: str, workflow_file: str, token: str) -> dict[str, Any]:
    name = Path(workflow_file).name
    response = httpx.get(
        f"https://api.github.com/repos/{repo}/actions/workflows/{name}/runs",
        params={"branch": "main", "per_page": 1, "status": "completed"},
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        timeout=20,
    )
    if response.status_code != 200:
        return {"observed": False, "reason": f"HTTP {response.status_code}"}
    runs = response.json().get("workflow_runs", [])
    if not runs:
        return {"observed": False, "reason": "no completed run on main"}
    run = runs[0]
    return {
        "observed": True,
        "conclusion": run["conclusion"],
        "head_sha": run["head_sha"],
        "run_url": run["html_url"],
        "event": run["event"],
    }


def build_report(
    ledger: dict[str, Any], root: Path, *, github_repo: str | None = None, token: str | None = None
) -> dict[str, Any]:
    validate_ledger(ledger, root)
    counts = {status: 0 for status in STATUSES}
    subsystems = []
    for item in ledger["subsystems"]:
        counts[item["status"]] += 1
        subsystems.append(
            {
                "id": item["id"],
                "category": item["category"],
                "status": item["status"],
                "limitation": item["limitation"],
                "environment": item["environment"],
                "evidence": [
                    {"path": ref, "sha256": _sha256(root / ref)} for ref in item["evidence"]
                ],
            }
        )
    gates = []
    for gate in ledger["required_gates"]:
        entry: dict[str, Any] = {"name": gate["name"], "workflow": gate["workflow"]}
        if github_repo and token:
            entry["latest_main_run"] = _latest_run(github_repo, gate["workflow"], token)
        gates.append(entry)
    repository = [s for s in ledger["subsystems"] if s["category"] == "repository_controllable"]
    external = [s for s in ledger["subsystems"] if s["category"] == "external"]
    repo_not_proven = [s["id"] for s in repository if s["status"] == "NOT_PROVEN"]
    return {
        "schema": "mon.final-readiness-report.v1",
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "ledger": str(LEDGER_PATH),
        "counts": counts,
        "repository_engineering": {
            "complete": not repo_not_proven,
            "repository_items_not_proven": repo_not_proven,
            "documented_partial_items": [
                s["id"] for s in repository if s["status"] == "PARTIALLY_PROVEN"
            ],
            "meaning": (
                "all planned repository-controllable implementation, testing, packaging, "
                "recovery and acceptance gates exist and are referenced; partial items carry "
                "their limitations in the ledger"
            ),
        },
        "external_production_certification": {
            "complete": False,
            "not_proven": [
                {"id": s["id"], "capability": s["capability"], "limitation": s["limitation"]}
                for s in external
            ],
        },
        "required_gates": gates,
        "subsystems": subsystems,
        "notice": "This report is not a production certification and contains no confidence scores.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MON production-readiness ledger tooling")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--render-md", action="store_true", help="write docs/production-readiness.md")
    parser.add_argument("--check-md", action="store_true", help="fail if the markdown is stale")
    parser.add_argument("--report", type=Path, help="write the machine-readable final report")
    parser.add_argument("--github-repo", help="owner/repo to query for latest main workflow runs")
    args = parser.parse_args(argv)
    ledger = load_ledger(args.root)
    validate_ledger(ledger, args.root)
    markdown = render_markdown(ledger)
    target = args.root / MARKDOWN_PATH
    if args.render_md:
        target.write_text(markdown, encoding="utf-8", newline="\n")
    if args.check_md and target.read_text(encoding="utf-8").replace("\r\n", "\n") != markdown:
        print("docs/production-readiness.md is stale; run --render-md", file=sys.stderr)
        return 1
    if args.report:
        token = os.environ.get("GITHUB_TOKEN")
        report = build_report(ledger, args.root, github_repo=args.github_repo, token=token)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
