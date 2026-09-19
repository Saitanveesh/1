from __future__ import annotations

import argparse
import asyncio
import json
import math
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx


@dataclass(frozen=True, slots=True)
class ProbeResult:
    attempted: int
    succeeded: int
    failed: int
    duration_seconds: float
    requests_per_second: float
    latency_ms_p50: float
    latency_ms_p95: float
    latency_ms_p99: float
    status_counts: dict[str, int]


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * fraction) - 1)
    return ordered[index]


def load_envelopes(path: Path) -> list[bytes]:
    envelopes: list[bytes] = []
    for line_number, raw_line in enumerate(path.read_bytes().splitlines(), start=1):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            value: Any = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON on line {line_number}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"line {line_number} must contain a JSON object")
        envelopes.append(raw_line)
    if not envelopes:
        raise ValueError("input contains no event-fabric envelopes")
    return envelopes


async def run_probe(
    *,
    url: str,
    envelopes: list[bytes],
    concurrency: int,
    authorization: str | None,
    timeout_seconds: float,
    verify: str | bool,
    cert: tuple[str, str] | None,
) -> ProbeResult:
    if concurrency < 1:
        raise ValueError("concurrency must be positive")
    if not url.startswith("https://"):
        raise ValueError("load probe requires an HTTPS target")

    queue: asyncio.Queue[bytes] = asyncio.Queue()
    for envelope in envelopes:
        queue.put_nowait(envelope)

    latencies: list[float] = []
    status_counts: dict[str, int] = {}
    succeeded = 0
    failed = 0
    lock = asyncio.Lock()
    headers = {"Content-Type": "application/json"}
    if authorization:
        headers["Authorization"] = authorization

    async with httpx.AsyncClient(
        timeout=timeout_seconds,
        verify=verify,
        cert=cert,
        trust_env=False,
    ) as client:
        async def worker() -> None:
            nonlocal succeeded, failed
            while True:
                try:
                    envelope = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                started = time.perf_counter()
                status = "transport_error"
                ok = False
                try:
                    response = await client.post(url, content=envelope, headers=headers)
                    status = str(response.status_code)
                    ok = 200 <= response.status_code < 300
                except httpx.HTTPError:
                    pass
                elapsed_ms = (time.perf_counter() - started) * 1000
                async with lock:
                    latencies.append(elapsed_ms)
                    status_counts[status] = status_counts.get(status, 0) + 1
                    if ok:
                        succeeded += 1
                    else:
                        failed += 1
                queue.task_done()

        started = time.perf_counter()
        await asyncio.gather(*(worker() for _ in range(concurrency)))
        duration = time.perf_counter() - started

    attempted = len(envelopes)
    return ProbeResult(
        attempted=attempted,
        succeeded=succeeded,
        failed=failed,
        duration_seconds=duration,
        requests_per_second=(attempted / duration) if duration else 0.0,
        latency_ms_p50=percentile(latencies, 0.50),
        latency_ms_p95=percentile(latencies, 0.95),
        latency_ms_p99=percentile(latencies, 0.99),
        status_counts=status_counts,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Replay caller-supplied canonical fabric envelopes against a disposable "
            "HTTPS environment and emit measured latency/throughput JSON."
        )
    )
    parser.add_argument("--url", required=True)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    parser.add_argument("--authorization")
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--client-cert", type=Path)
    parser.add_argument("--client-key", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if (args.client_cert is None) != (args.client_key is None):
        raise SystemExit("--client-cert and --client-key must be supplied together")
    verify: str | bool = str(args.ca_file) if args.ca_file else True
    cert = (
        (str(args.client_cert), str(args.client_key))
        if args.client_cert is not None
        else None
    )
    result = asyncio.run(
        run_probe(
            url=args.url,
            envelopes=load_envelopes(args.input),
            concurrency=args.concurrency,
            authorization=args.authorization,
            timeout_seconds=args.timeout_seconds,
            verify=verify,
            cert=cert,
        )
    )
    print(json.dumps(asdict(result), sort_keys=True))
    if result.failed:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
