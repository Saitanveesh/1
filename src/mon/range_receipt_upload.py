"""Authenticated upload of bounded exercise receipts without shell-token exposure."""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from mon.range_evidence import ExerciseReceipt
from mon.topology_inventory_cli import _NoRedirect, _read_bearer


def _api_endpoint(origin: str, *, allow_local_http: bool) -> str:
    parts = urllib.parse.urlsplit(origin)
    if (
        parts.username or parts.password or parts.query or parts.fragment
        or parts.path not in {"", "/"} or not parts.hostname
    ):
        raise ValueError("MON API origin must not contain credentials, path or query")
    if parts.scheme != "https" and not (
        allow_local_http
        and parts.scheme == "http"
        and parts.hostname in {"127.0.0.1", "localhost", "::1"}
    ):
        raise ValueError("MON exercise evidence upload requires HTTPS")
    return origin.rstrip("/") + "/api/v1/range/exercises"


def read_receipt(path: Path) -> ExerciseReceipt:
    if path.stat().st_size > 131072:
        raise ValueError("exercise receipt file exceeds size limit")
    return ExerciseReceipt.model_validate_json(path.read_text(encoding="utf-8"))


def upload_receipt(
    path: Path, *,
    api_url: str,
    token_file: Path,
    allow_local_http: bool = False,
) -> dict[str, object]:
    endpoint = _api_endpoint(api_url, allow_local_http=allow_local_http)
    receipt = read_receipt(path)
    token = _read_bearer(token_file)
    request = urllib.request.Request(
        endpoint,
        data=receipt.model_dump_json(exclude={"provenance"}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    # Never send the bearer token via environment proxies or HTTP redirects.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect,
    )
    with opener.open(request, timeout=10) as response:
        data = json.load(response)
    if (
        not isinstance(data, dict)
        or data.get("exercise_id") != receipt.exercise_id
        or data.get("provenance") != "SELF_REPORTED_EXERCISE"
        or not isinstance(data.get("stored"), bool)
    ):
        raise ValueError("MON receipt acknowledgement invalid")
    return {
        "exercise_id": receipt.exercise_id,
        "sha256": receipt.sha256,
        "stored": data["stored"],
        "provenance": "SELF_REPORTED_EXERCISE",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MON authenticated range evidence uploader")
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--api-url")
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--allow-local-http", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.api_url:
            if args.token_file is not None:
                raise ValueError("--token-file requires --api-url")
            receipt = read_receipt(args.receipt)
            print(json.dumps({
                "exercise_id": receipt.exercise_id,
                "sha256": receipt.sha256, "verified": True,
                "provenance": "SELF_REPORTED_EXERCISE",
            }))
        else:
            if args.token_file is None:
                raise ValueError("--token-file is required to upload")
            print(json.dumps(upload_receipt(
                args.receipt, api_url=args.api_url,
                token_file=args.token_file,
                allow_local_http=args.allow_local_http,
            )))
        return 0
    except (OSError, ValueError, urllib.error.URLError) as exc:
        print(
            f"range evidence upload refused: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
