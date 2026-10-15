"""Bounded, auditable real-request ERP exercise for an isolated range.

Not a DDoS/MITM tool. One station, limited HTTP GET traffic against a
verified synthetic MON ERP only; does not scan or target campus devices.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import os
import stat
import sys
import time
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

_MARKER = "MON SYNTHETIC ERP — NO REAL STUDENT DATA"


class ExercisePermit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    exercise_id: str = Field(min_length=4, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    target_ip: str
    target_port: int = Field(default=8081, ge=8081, le=8081)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    approved_by: str = Field(min_length=3, max_length=128)
    expires_at: dt.datetime
    rps: int = Field(default=2, ge=1, le=3)
    duration_seconds: int = Field(default=15, ge=1, le=45)

    @model_validator(mode="after")
    def validate_permit(self) -> ExercisePermit:
        address = ipaddress.ip_address(self.target_ip)
        if address.version != 4:
            raise ValueError("only explicit isolated IPv4 endpoints are supported")
        if not (address.is_private or address.is_loopback):
            raise ValueError("target must be private or loopback")
        if address.is_multicast or address.is_unspecified or address.is_link_local:
            raise ValueError("unsafe target IP")
        if self.expires_at.utcoffset() is None:
            raise ValueError("expiry must be timezone aware")
        return self


def read_permit(path: Path, *, now: dt.datetime | None = None) -> ExercisePermit:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("permit must be a regular file")
    if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("permit must have mode 0600")
    if info.st_size > 8192:
        raise ValueError("permit too large")
    permit = ExercisePermit.model_validate_json(path.read_text(encoding="utf-8"))
    instant = now or dt.datetime.now(dt.UTC)
    if not instant < permit.expires_at <= instant + dt.timedelta(hours=2):
        raise ValueError("permit expired or expires too far in the future")
    return permit


def _get(ip: str, port: int, path: str) -> tuple[int | None, float, bytes]:
    started = time.monotonic()
    connection = http.client.HTTPConnection(ip, port, timeout=2)
    try:
        connection.request("GET", path, headers={"Accept": "application/json",
                                                 "Connection": "close"})
        response = connection.getresponse()
        body = response.read(4096)
        return response.status, time.monotonic() - started, body
    finally:
        connection.close()


def verify_test_only_target(permit: ExercisePermit) -> None:
    status, _, data = _get(permit.target_ip, permit.target_port, "/health/live")
    if status != 200:
        raise ValueError("test-only ERP verification failed")
    try:
        content = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError("test-only ERP verification failed") from exc
    if (
        content.get("environment") != "isolated-range"
        or content.get("service") != _MARKER
    ):
        raise ValueError("target is not a verified MON synthetic ERP")


def execute_exercise(
    permit: ExercisePermit, *,
    monotonic=time.monotonic,
    sleep=time.sleep,
    get=_get,
    verify=verify_test_only_target,
) -> dict[str, object]:
    """Measure real bounded requests; never claim compromise or containment."""
    verify(permit)
    if dt.datetime.now(dt.UTC) >= permit.expires_at:
        raise ValueError("authorization expired before execution")
    started_utc = dt.datetime.now(dt.UTC).isoformat()
    interval = 1.0 / permit.rps
    deadline = monotonic() + permit.duration_seconds
    next_due = monotonic()
    attempts = 0
    successes = 0
    failed = 0
    samples: list[dict[str, object]] = []
    max_requests = permit.rps * permit.duration_seconds
    while attempts < max_requests and monotonic() < deadline:
        if dt.datetime.now(dt.UTC) >= permit.expires_at:
            break
        sleep(max(0.0, next_due - monotonic()))
        if monotonic() >= deadline:
            break
        observed = dt.datetime.now(dt.UTC).isoformat()
        try:
            status, latency, _ = get(
                permit.target_ip, permit.target_port, "/api/students?limit=1"
            )
        except (OSError, http.client.HTTPException, TimeoutError):
            status, latency = None, None
        attempts += 1
        if status == 200:
            successes += 1
        else:
            failed += 1
        samples.append({
            "observed_at": observed, "http_status": status,
            "latency_seconds": round(latency, 6) if latency is not None else None,
        })
        # Fixed cadence; no catch-up bursts after delayed responses.
        next_due = max(next_due + interval, monotonic() + interval)
    result = {
        "exercise_id": permit.exercise_id,
        "tenant_id": permit.tenant_id,
        "site_id": permit.site_id,
        "approved_by": permit.approved_by,
        "target_ip": permit.target_ip,
        "started_at": started_utc,
        "finished_at": dt.datetime.now(dt.UTC).isoformat(),
        "scenario": "BOUNDED_SINGLE_SOURCE_HTTP_REQUESTS",
        "attack_claim": "NONE",
        "containment_claim": "NONE",
        "attempts": attempts, "http_200": successes, "other_or_failed": failed,
        "samples": samples,
    }
    raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    result["sha256"] = hashlib.sha256(raw).hexdigest()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MON authorized bounded ERP requests")
    parser.add_argument("--permit-file", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--confirm-isolated-range", action="store_true")
    args = parser.parse_args(argv)
    if not args.confirm_isolated_range:
        print("explicit verified isolation confirmation required", file=sys.stderr)
        return 2
    try:
        permit = read_permit(args.permit_file)
        if args.out.exists():
            raise ValueError("refusing to overwrite an existing evidence file")
        result = execute_exercise(permit)
        args.out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as handle:
            os.chmod(args.out, 0o600)
            json.dump(result, handle, indent=2)
        print(json.dumps({
            "exercise_id": result["exercise_id"], "attempts": result["attempts"],
            "other_or_failed": result["other_or_failed"],
            "evidence_sha256": result["sha256"], "output_file": str(args.out),
        }))
        return 0
    except (OSError, ValueError, http.client.HTTPException) as exc:
        # Do not claim that an attempted exercise ran to completion on errors.
        print(f"exercise aborted: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
