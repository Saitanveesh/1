from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import hashlib
import json
import math
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx

PROBE_VERSION = "mon-fabric-load-probe/2"


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


@dataclass(frozen=True, slots=True)
class ResourceSamplerConfig:
    command: tuple[str, ...]
    sampler_id: str
    timeout_seconds: float = 5.0
    max_output_bytes: int = 16_384


@dataclass(frozen=True, slots=True)
class ResourceSample:
    sampled_at: str
    sampler_id: str
    returncode: int
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool


@dataclass(frozen=True, slots=True)
class SoakIntervalResult:
    interval_index: int
    started_at: str
    ended_at: str
    attempted: int
    succeeded: int
    failed: int
    duration_seconds: float
    requests_per_second: float
    latency_ms_p50: float
    latency_ms_p95: float
    latency_ms_p99: float
    status_counts: dict[str, int]


@dataclass(frozen=True, slots=True)
class SoakAggregateResult:
    attempted: int
    succeeded: int
    failed: int
    duration_seconds: float
    requests_per_second: float
    status_counts: dict[str, int]


@dataclass(frozen=True, slots=True)
class SoakResult:
    successful: bool
    failure_reasons: list[str]
    corpus_sha256: str
    target_url: str
    concurrency: int
    requested_duration_seconds: float
    interval_seconds: float
    started_at: str
    ended_at: str
    probe_version: str
    deployment_topology: str
    aggregate: SoakAggregateResult
    intervals: list[SoakIntervalResult]
    resource_samples: list[ResourceSample]


class ProbeRunner(Protocol):
    async def __call__(
        self,
        *,
        url: str,
        envelopes: list[bytes],
        concurrency: int,
        authorization: str | None,
        timeout_seconds: float,
        verify: str | bool,
        cert: tuple[str, str] | None,
    ) -> ProbeResult: ...


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * fraction) - 1)
    return ordered[index]


def load_envelopes(path: Path) -> list[bytes]:
    envelopes: list[bytes] = []
    for line_number, raw_line in enumerate(path.read_bytes().splitlines(), start=1):
        if not raw_line.strip():
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


def corpus_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.UTC).isoformat()


def _bounded_text(value: bytes, limit: int) -> tuple[str, bool]:
    if limit < 1:
        raise ValueError("max output bytes must be positive")
    truncated = len(value) > limit
    bounded = value[:limit]
    return bounded.decode("utf-8", errors="replace"), truncated


async def sample_resources(config: ResourceSamplerConfig) -> ResourceSample:
    if not config.command:
        raise ValueError("resource sampler command is required")
    if config.timeout_seconds <= 0:
        raise ValueError("resource sampler timeout must be positive")
    if config.max_output_bytes <= 0:
        raise ValueError("resource sampler output bound must be positive")

    sampled_at = _iso(_utc_now())

    def run() -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            list(config.command),
            shell=False,
            capture_output=True,
            timeout=config.timeout_seconds,
            check=False,
        )

    try:
        completed = await asyncio.to_thread(run)
    except subprocess.TimeoutExpired as exc:
        stdout, stdout_truncated = _bounded_text(exc.stdout or b"", config.max_output_bytes)
        stderr, stderr_truncated = _bounded_text(exc.stderr or b"", config.max_output_bytes)
        return ResourceSample(
            sampled_at=sampled_at,
            sampler_id=config.sampler_id,
            returncode=-1,
            stdout=stdout,
            stderr=stderr or "resource sampler timed out",
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )

    stdout, stdout_truncated = _bounded_text(completed.stdout, config.max_output_bytes)
    stderr, stderr_truncated = _bounded_text(completed.stderr, config.max_output_bytes)
    return ResourceSample(
        sampled_at=sampled_at,
        sampler_id=config.sampler_id,
        returncode=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
    )


def _aggregate(intervals: list[SoakIntervalResult]) -> SoakAggregateResult:
    attempted = sum(item.attempted for item in intervals)
    succeeded = sum(item.succeeded for item in intervals)
    failed = sum(item.failed for item in intervals)
    duration = sum(item.duration_seconds for item in intervals)
    status_counts: dict[str, int] = {}
    for interval in intervals:
        for status, count in interval.status_counts.items():
            status_counts[status] = status_counts.get(status, 0) + count
    return SoakAggregateResult(
        attempted=attempted,
        succeeded=succeeded,
        failed=failed,
        duration_seconds=duration,
        requests_per_second=(attempted / duration) if duration else 0.0,
        status_counts=status_counts,
    )


async def run_soak(
    *,
    url: str,
    input_path: Path,
    concurrency: int,
    duration_seconds: float,
    interval_seconds: float,
    deployment_topology: str,
    authorization: str | None,
    timeout_seconds: float,
    verify: str | bool,
    cert: tuple[str, str] | None,
    resource_sampler: ResourceSamplerConfig | None = None,
    probe_runner: ProbeRunner = run_probe,
) -> SoakResult:
    if concurrency < 1:
        raise ValueError("concurrency must be positive")
    if duration_seconds <= 0:
        raise ValueError("soak duration must be positive")
    if interval_seconds <= 0:
        raise ValueError("soak interval must be positive")
    if not deployment_topology.strip():
        raise ValueError("deployment topology label is required")
    if not url.startswith("https://"):
        raise ValueError("load probe requires an HTTPS target")

    corpus_digest = corpus_sha256(input_path)
    envelopes = load_envelopes(input_path)
    started = _utc_now()
    deadline = time.monotonic() + duration_seconds
    interval_count = math.ceil(duration_seconds / interval_seconds)
    intervals: list[SoakIntervalResult] = []
    resource_samples: list[ResourceSample] = []
    failure_reasons: list[str] = []

    try:
        for interval_index in range(1, interval_count + 1):
            if corpus_sha256(input_path) != corpus_digest:
                failure_reasons.append("corpus changed before interval")
                break

            interval_started = _utc_now()
            probe = await probe_runner(
                url=url,
                envelopes=envelopes,
                concurrency=concurrency,
                authorization=authorization,
                timeout_seconds=timeout_seconds,
                verify=verify,
                cert=cert,
            )
            interval_ended = _utc_now()
            intervals.append(
                SoakIntervalResult(
                    interval_index=interval_index,
                    started_at=_iso(interval_started),
                    ended_at=_iso(interval_ended),
                    attempted=probe.attempted,
                    succeeded=probe.succeeded,
                    failed=probe.failed,
                    duration_seconds=probe.duration_seconds,
                    requests_per_second=probe.requests_per_second,
                    latency_ms_p50=probe.latency_ms_p50,
                    latency_ms_p95=probe.latency_ms_p95,
                    latency_ms_p99=probe.latency_ms_p99,
                    status_counts=dict(probe.status_counts),
                )
            )
            if probe.failed:
                failure_reasons.append(f"interval {interval_index} reported failures")

            if resource_sampler is not None:
                sample = await sample_resources(resource_sampler)
                resource_samples.append(sample)
                if sample.returncode != 0:
                    failure_reasons.append(
                        f"resource sampler {resource_sampler.sampler_id} failed"
                    )

            if corpus_sha256(input_path) != corpus_digest:
                failure_reasons.append("corpus changed during interval")
                break

            elapsed = (interval_ended - interval_started).total_seconds()
            deadline_remaining = max(0.0, deadline - time.monotonic())
            sleep_for = min(
                max(0.0, interval_seconds - elapsed),
                deadline_remaining,
            )
            if sleep_for > 0 and interval_index < interval_count:
                await asyncio.sleep(sleep_for)
    except asyncio.CancelledError:
        raise

    ended = _utc_now()
    aggregate = _aggregate(intervals)
    return SoakResult(
        successful=not failure_reasons,
        failure_reasons=failure_reasons,
        corpus_sha256=corpus_digest,
        target_url=url,
        concurrency=concurrency,
        requested_duration_seconds=duration_seconds,
        interval_seconds=interval_seconds,
        started_at=_iso(started),
        ended_at=_iso(ended),
        probe_version=PROBE_VERSION,
        deployment_topology=deployment_topology,
        aggregate=aggregate,
        intervals=intervals,
        resource_samples=resource_samples,
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
    parser.add_argument("--soak-duration-seconds", type=float)
    parser.add_argument("--soak-interval-seconds", type=float)
    parser.add_argument("--deployment-topology")
    parser.add_argument("--resource-sampler-id")
    parser.add_argument("--resource-sampler-timeout-seconds", type=float, default=5.0)
    parser.add_argument("--resource-sampler-max-output-bytes", type=int, default=16_384)
    parser.add_argument(
        "--resource-sampler-command",
        nargs="+",
        help=(
            "Explicit command and arguments for one bounded resource sample per "
            "soak interval. Do not include secrets."
        ),
    )
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
    if args.soak_duration_seconds is not None:
        if args.soak_interval_seconds is None:
            raise SystemExit("--soak-interval-seconds is required for soak mode")
        if not args.deployment_topology:
            raise SystemExit("--deployment-topology is required for soak mode")
        sampler = None
        if args.resource_sampler_command:
            sampler = ResourceSamplerConfig(
                command=tuple(args.resource_sampler_command),
                sampler_id=args.resource_sampler_id or args.resource_sampler_command[0],
                timeout_seconds=args.resource_sampler_timeout_seconds,
                max_output_bytes=args.resource_sampler_max_output_bytes,
            )
        result = asyncio.run(
            run_soak(
                url=args.url,
                input_path=args.input,
                concurrency=args.concurrency,
                duration_seconds=args.soak_duration_seconds,
                interval_seconds=args.soak_interval_seconds,
                deployment_topology=args.deployment_topology,
                authorization=args.authorization,
                timeout_seconds=args.timeout_seconds,
                verify=verify,
                cert=cert,
                resource_sampler=sampler,
            )
        )
        print(json.dumps(asdict(result), sort_keys=True))
        if not result.successful:
            raise SystemExit(2)
        return

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
