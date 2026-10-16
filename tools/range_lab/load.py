"""Tiny multi-namespace traffic exercise; fixed internal victim subnet only."""
from __future__ import annotations

import argparse
import datetime as dt
import http.client
import json
import time


def run(target: str, *, duration: int = 6, rps: int = 5) -> dict[str, object]:
    if target not in {"10.253.42.20", "10.253.42.21"}:
        raise ValueError("target must be one of two disposable namespaces")
    if not 1 <= duration <= 8 or not 1 <= rps <= 5:
        raise ValueError("bounded lab rates only")
    started = time.monotonic()
    next_at = started
    samples: list[dict[str, object]] = []
    while len(samples) < duration * rps and time.monotonic() < started + duration:
        time.sleep(max(0.0, next_at - time.monotonic()))
        if time.monotonic() >= started + duration:
            break
        current = time.monotonic()
        status = None
        try:
            connection = http.client.HTTPConnection(target, 8081, timeout=1.5)
            try:
                connection.request("GET", "/api/students?limit=1")
                response = connection.getresponse()
                status = response.status
                response.read(1024)
            finally:
                connection.close()
        except (OSError, http.client.HTTPException):
            pass
        samples.append({
            "at": dt.datetime.now(dt.UTC).isoformat(),
            "http_status": status,
            "elapsed_ms": round((time.monotonic() - current) * 1000, 3),
        })
        next_at = max(next_at + 1 / rps, time.monotonic())
    return {
        "source": "real HTTP from isolated Linux network namespace",
        "destination": target,
        "requested_rps": rps,
        "duration_limit_seconds": duration,
        "sent": len(samples),
        "succeeded": sum(item["http_status"] == 200 for item in samples),
        "samples": samples,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=["10.253.42.20", "10.253.42.21"],
                        required=True)
    parser.add_argument("--duration", type=int, default=6)
    parser.add_argument("--rps", type=int, default=5)
    args = parser.parse_args()
    print(json.dumps(run(args.target, duration=args.duration, rps=args.rps)))
