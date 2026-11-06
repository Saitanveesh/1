#!/usr/bin/env python3
"""Conservative one-time retirement of documented, fully integrated GitHub branches.

Only deletes unchanged refs with a merged PR, no open PR, direct commit ancestry
in main and no references in the live repository. A dated manifest preserves
every reviewed ref SHA for restoration. No history rewriting.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

PROTECTED_PREFIXES = (
    "backup/",
    "release/",
    "ops/",
    "lab/",
    "design/",
    "feature/mon-",
    "fix/mon-",
    "feat/three-host-",
    "feature/ubuntu-",
    "pr-",
)
PROTECTED_NAMES = frozenset({"main", "master", "develop", "development"})
DEFAULT_MANIFEST = Path(
    "docs/repository-maintenance/branch-inventory-2026-11-06.json"
)


def classify(
    record: dict[str, Any],
    live_sha: str | None,
    open_pr_refs: set[str],
    is_ancestor: bool,
    is_referenced: bool,
) -> str:
    """Return 'eligible' only when all hard safety gates are satisfied."""
    name = record["name"]
    if name in PROTECTED_NAMES or name.startswith(PROTECTED_PREFIXES):
        return "protected branch"
    if record["category"] != "merged_pr":
        return "not a completed PR branch"
    if name in open_pr_refs:
        return "used by open PR"
    if live_sha is None:
        return "remote branch absent"
    if not record.get("sha") or live_sha != record["sha"]:
        return "head changed since inventory"
    if not is_ancestor:
        return "tip not already in main history"
    if is_referenced:
        return "referenced by tracked project files"
    return "eligible"


def api_request(repo: str, path: str, token: str, method: str = "GET") -> Any:
    url = f"https://api.github.com/repos/{repo}/{path}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "mon-branch-retirement",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method=method,
    )
    with urllib.request.urlopen(req, timeout=25) as response:
        body = response.read()
        return json.loads(body) if body else None


def paginated(repo: str, path: str, token: str) -> list[dict[str, Any]]:
    data = []
    for page in range(1, 21):
        separator = "&" if "?" in path else "?"
        records = api_request(
            repo, f"{path}{separator}per_page=100&page={page}", token
        )
        if not isinstance(records, list):
            raise RuntimeError(f"Unexpected API response for {path}")
        data.extend(records)
        if len(records) < 100:
            return data
    raise RuntimeError("Unexpectedly many pages; refusing incomplete audit")


def run_git(*args: str) -> int:
    result = subprocess.run(
        ["git", *args], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    return result.returncode


def check_ancestor(sha: str) -> bool:
    result = run_git("merge-base", "--is-ancestor", sha, "refs/remotes/origin/main")
    if result not in (0, 1):
        raise RuntimeError("Git ancestry query failed; refusing cleanup")
    return result == 0


def referenced_in_repository(name: str) -> bool:
    result = run_git(
        "grep", "-I", "-F", "-q", "-e", name, "--", ".",
        ":(exclude)docs/repository-maintenance/**",
    )
    if result not in (0, 1):
        raise RuntimeError("Git reference search failed; refusing cleanup")
    return result == 0


def remote_sha(repo: str, branch: str, token: str) -> str | None:
    ref = urllib.parse.quote(f"heads/{branch}", safe="/")
    try:
        return api_request(repo, f"git/ref/{ref}", token)["object"]["sha"]
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def delete_branch(repo: str, branch: str, token: str) -> None:
    ref = urllib.parse.quote(f"heads/{branch}", safe="/")
    api_request(repo, f"git/refs/{ref}", token, method="DELETE")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report", type=Path, default=Path("branch-retirement-report.json"))
    parser.add_argument("--apply", action="store_true", help="Delete eligible refs")
    parser.add_argument(
        "--confirm", default="",
        help="Must exactly match repository name for deletion",
    )
    args = parser.parse_args()

    inventory = json.loads(args.manifest.read_text(encoding="utf-8"))
    repo = inventory["repository"]
    if repo != "Saitanveesh/1" or inventory["baseline_branch"] != "main":
        raise SystemExit("Unexpected repo/branch; refusing retirement")

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise SystemExit("GITHUB_TOKEN is required to verify live refs and PRs")

    if args.apply and not (
        args.confirm == repo
        and os.environ.get("GITHUB_REPOSITORY") == repo
        and os.environ.get("GITHUB_REF") == "refs/heads/main"
    ):
        raise SystemExit("Apply requires exact repo confirmation on main in GitHub Actions")

    if not check_ancestor(inventory["baseline_sha"]):
        raise SystemExit("Inventory baseline is not in main; refusing retirement")

    live_branches = {
        b["name"]: b["commit"]["sha"]
        for b in paginated(repo, "branches", token)
    }
    open_prs = paginated(repo, "pulls?state=open", token)
    open_refs = set()
    for pr in open_prs:
        open_refs.add(pr["head"]["ref"])
        open_refs.add(pr["base"]["ref"])

    report: dict[str, Any] = {
        "repository": repo,
        "manifest_baseline_sha": inventory["baseline_sha"],
        "mode": "apply" if args.apply else "dry_run",
        "entries": [],
        "deleted": [],
        "errors": [],
    }
    for record in inventory["records"]:
        name = record["name"]
        # Run expensive Git checks only on viable non-protected completed branches.
        precheck = classify(record, live_branches.get(name), open_refs, False, False)
        if precheck == "tip not already in main history":
            reason = classify(
                record, live_branches.get(name), open_refs,
                check_ancestor(record["sha"]), referenced_in_repository(name),
            )
        else:
            reason = precheck
        report["entries"].append(
            {"name": name, "sha": record["sha"], "decision": reason}
        )
        if reason != "eligible":
            continue

        if not args.apply:
            print(f"PLAN  {name} @ {record['sha']}")
            continue

        try:
            # Re-read exact SHA immediately before each destructive operation.
            latest = remote_sha(repo, name, token)
            if latest != record["sha"]:
                print(f"SKIP  {name}: head moved before delete")
                report["entries"][-1]["decision"] = "head changed at delete time"
                continue
            delete_branch(repo, name, token)
            report["deleted"].append({"name": name, "sha": latest})
            print(f"DELETE {name} @ {latest}")
        except urllib.error.HTTPError as exc:
            msg = f"{name}: GitHub HTTP {exc.code}"
            report["errors"].append(msg)
            print(f"ERROR {msg}", file=sys.stderr)
        except (OSError, RuntimeError, ValueError, KeyError) as exc:
            msg = f"{name}: {type(exc).__name__}"
            report["errors"].append(msg)
            print(f"ERROR {msg}", file=sys.stderr)

    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    totals = {
        "recorded": len(report["entries"]),
        "eligible": sum(e["decision"] == "eligible" for e in report["entries"]),
        "deleted": len(report["deleted"]),
        "errors": len(report["errors"]),
    }
    print(f"SUMMARY {totals}")
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with Path(summary_file).open("a", encoding="utf-8") as stream:
            stream.write(
                f"### MON branch retirement ({report['mode']})\n"
                f"Recorded: {totals['recorded']}  "
                f"Eligible: {totals['eligible']}  "
                f"Deleted: {totals['deleted']}  "
                f"Errors: {totals['errors']}\n"
            )
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
