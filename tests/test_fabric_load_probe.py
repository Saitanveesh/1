from __future__ import annotations

import asyncio
import json
import subprocess
from dataclasses import asdict
from pathlib import Path

import pytest

from mon import fabric_load_probe as probe


def test_load_envelopes_preserves_exact_nonempty_lines(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    path.write_bytes(b'{"event_id":"a"}\n\n {"event_id":"b"} \n')

    assert probe.load_envelopes(path) == [
        b'{"event_id":"a"}',
        b' {"event_id":"b"} ',
    ]


def test_load_envelopes_rejects_invalid_or_empty_input(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.ndjson"
    invalid.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON on line 1"):
        probe.load_envelopes(invalid)

    empty = tmp_path / "empty.ndjson"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no event-fabric envelopes"):
        probe.load_envelopes(empty)


def test_percentile_uses_nearest_rank() -> None:
    values = [1.0, 2.0, 3.0, 4.0, 100.0]
    assert probe.percentile(values, 0.50) == 3.0
    assert probe.percentile(values, 0.95) == 100.0
    assert probe.percentile([], 0.99) == 0.0


@pytest.mark.asyncio
async def test_probe_rejects_plaintext_target_before_network_io() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        await probe.run_probe(
            url="http://127.0.0.1:8080/api/v1/site/fabric/events",
            envelopes=[b"{}"],
            concurrency=1,
            authorization=None,
            timeout_seconds=1.0,
            verify=True,
            cert=None,
        )


@pytest.mark.asyncio
async def test_probe_rejects_nonpositive_concurrency() -> None:
    with pytest.raises(ValueError, match="concurrency"):
        await probe.run_probe(
            url="https://127.0.0.1/api/v1/site/fabric/events",
            envelopes=[b"{}"],
            concurrency=0,
            authorization=None,
            timeout_seconds=1.0,
            verify=True,
            cert=None,
        )


def test_corpus_sha256_uses_exact_file_bytes(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    path.write_bytes(b'{"event_id":"a"}\n')
    first = probe.corpus_sha256(path)
    path.write_bytes(b'{"event_id":"a"}\n ')

    assert first != probe.corpus_sha256(path)


@pytest.mark.asyncio
async def test_probe_disables_ambient_proxy(monkeypatch) -> None:
    observed: dict[str, object] = {}

    class Response:
        status_code = 200

    class Client:
        def __init__(self, **kwargs):
            observed.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, *, content, headers):
            return Response()

    monkeypatch.setattr(probe.httpx, "AsyncClient", Client)

    result = await probe.run_probe(
        url="https://example.test/api/v1/site/fabric/events",
        envelopes=[b"{}"],
        concurrency=1,
        authorization="Bearer secret",
        timeout_seconds=1.0,
        verify=True,
        cert=None,
    )

    assert result.succeeded == 1
    assert observed["trust_env"] is False


def interval_runner(*results: probe.ProbeResult):
    calls = {"count": 0}

    async def run(**kwargs):
        index = calls["count"]
        calls["count"] += 1
        return results[min(index, len(results) - 1)]

    run.calls = calls
    return run


def ok_probe(attempted: int = 2) -> probe.ProbeResult:
    return probe.ProbeResult(
        attempted=attempted,
        succeeded=attempted,
        failed=0,
        duration_seconds=0.001,
        requests_per_second=attempted / 0.001,
        latency_ms_p50=1.0,
        latency_ms_p95=2.0,
        latency_ms_p99=3.0,
        status_counts={"200": attempted},
    )


def failed_probe() -> probe.ProbeResult:
    return probe.ProbeResult(
        attempted=2,
        succeeded=1,
        failed=1,
        duration_seconds=0.001,
        requests_per_second=2000.0,
        latency_ms_p50=1.0,
        latency_ms_p95=2.0,
        latency_ms_p99=3.0,
        status_counts={"200": 1, "500": 1},
    )


@pytest.mark.asyncio
async def test_soak_splits_duration_and_retains_raw_intervals(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    path.write_bytes(b'{"event_id":"a"}\n')

    result = await probe.run_soak(
        url="https://example.test/fabric",
        input_path=path,
        concurrency=2,
        duration_seconds=0.03,
        interval_seconds=0.01,
        deployment_topology="single-site-ci",
        authorization=None,
        timeout_seconds=1.0,
        verify=True,
        cert=None,
        probe_runner=interval_runner(ok_probe()),
    )

    assert result.successful is True
    assert result.deployment_topology == "single-site-ci"
    assert len(result.intervals) >= 2
    assert result.aggregate.attempted == sum(item.attempted for item in result.intervals)
    assert result.aggregate.succeeded == sum(item.succeeded for item in result.intervals)
    assert result.aggregate.failed == 0
    assert result.intervals[0].status_counts == {"200": 2}


@pytest.mark.asyncio
async def test_soak_detects_corpus_modification_during_run(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    path.write_bytes(b'{"event_id":"a"}\n')

    async def modifying_runner(**kwargs):
        path.write_bytes(b'{"event_id":"changed"}\n')
        return ok_probe()

    result = await probe.run_soak(
        url="https://example.test/fabric",
        input_path=path,
        concurrency=1,
        duration_seconds=1.0,
        interval_seconds=1.0,
        deployment_topology="mutation-test",
        authorization=None,
        timeout_seconds=1.0,
        verify=True,
        cert=None,
        probe_runner=modifying_runner,
    )

    assert result.successful is False
    assert "corpus changed during interval" in result.failure_reasons


@pytest.mark.asyncio
async def test_failed_interval_makes_soak_unsuccessful(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    path.write_bytes(b'{"event_id":"a"}\n')

    result = await probe.run_soak(
        url="https://example.test/fabric",
        input_path=path,
        concurrency=1,
        duration_seconds=0.01,
        interval_seconds=0.01,
        deployment_topology="failure-test",
        authorization=None,
        timeout_seconds=1.0,
        verify=True,
        cert=None,
        probe_runner=interval_runner(failed_probe()),
    )

    assert result.successful is False
    assert result.aggregate.failed == 1
    assert any("reported failures" in reason for reason in result.failure_reasons)


@pytest.mark.asyncio
async def test_resource_sampler_success_and_no_shell(monkeypatch) -> None:
    observed: dict[str, object] = {}

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed["shell"] = kwargs["shell"]
        return subprocess.CompletedProcess(command, 0, stdout=b'{"rss": 1}', stderr=b"")

    monkeypatch.setattr(probe.subprocess, "run", fake_run)

    sample = await probe.sample_resources(
        probe.ResourceSamplerConfig(command=("sampler", "--json"), sampler_id="sampler")
    )

    assert observed["command"] == ["sampler", "--json"]
    assert observed["shell"] is False
    assert sample.returncode == 0
    assert sample.stdout == '{"rss": 1}'


@pytest.mark.asyncio
async def test_resource_sampler_failures_affect_soak(monkeypatch, tmp_path: Path) -> None:
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 7, stdout=b"", stderr=b"failed")

    monkeypatch.setattr(probe.subprocess, "run", fake_run)
    path = tmp_path / "events.ndjson"
    path.write_bytes(b'{"event_id":"a"}\n')

    result = await probe.run_soak(
        url="https://example.test/fabric",
        input_path=path,
        concurrency=1,
        duration_seconds=0.01,
        interval_seconds=0.01,
        deployment_topology="sampler-failure",
        authorization=None,
        timeout_seconds=1.0,
        verify=True,
        cert=None,
        resource_sampler=probe.ResourceSamplerConfig(
            command=("sampler",),
            sampler_id="sampler",
        ),
        probe_runner=interval_runner(ok_probe()),
    )

    assert result.successful is False
    assert result.resource_samples[0].stderr == "failed"
    assert any("resource sampler" in reason for reason in result.failure_reasons)


@pytest.mark.asyncio
async def test_resource_sampler_timeout_and_output_bound(monkeypatch) -> None:
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, timeout=1.0, output=b"abcdef", stderr=b"")

    monkeypatch.setattr(probe.subprocess, "run", fake_run)

    sample = await probe.sample_resources(
        probe.ResourceSamplerConfig(
            command=("sampler",),
            sampler_id="sampler",
            timeout_seconds=1.0,
            max_output_bytes=3,
        )
    )

    assert sample.returncode == -1
    assert sample.stdout == "abc"
    assert sample.stdout_truncated is True
    assert "timed out" in sample.stderr


def test_serialized_soak_result_omits_authorization_value(tmp_path: Path) -> None:
    result = probe.SoakResult(
        successful=True,
        failure_reasons=[],
        corpus_sha256="a" * 64,
        target_url="https://example.test/fabric",
        concurrency=1,
        requested_duration_seconds=1.0,
        interval_seconds=1.0,
        started_at="2026-09-19T00:00:00+00:00",
        ended_at="2026-09-19T00:00:01+00:00",
        probe_version=probe.PROBE_VERSION,
        deployment_topology="topology-a",
        aggregate=probe.SoakAggregateResult(
            attempted=1,
            succeeded=1,
            failed=0,
            duration_seconds=0.1,
            requests_per_second=10.0,
            status_counts={"200": 1},
        ),
        intervals=[],
        resource_samples=[],
    )

    assert "Bearer secret" not in json.dumps(asdict(result), sort_keys=True)


@pytest.mark.asyncio
async def test_soak_rejects_invalid_inputs(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    path.write_bytes(b'{"event_id":"a"}\n')
    with pytest.raises(ValueError, match="duration"):
        await probe.run_soak(
            url="https://example.test/fabric",
            input_path=path,
            concurrency=1,
            duration_seconds=0,
            interval_seconds=1,
            deployment_topology="topology",
            authorization=None,
            timeout_seconds=1,
            verify=True,
            cert=None,
        )
    with pytest.raises(ValueError, match="interval"):
        await probe.run_soak(
            url="https://example.test/fabric",
            input_path=path,
            concurrency=1,
            duration_seconds=1,
            interval_seconds=0,
            deployment_topology="topology",
            authorization=None,
            timeout_seconds=1,
            verify=True,
            cert=None,
        )
    with pytest.raises(ValueError, match="concurrency"):
        await probe.run_soak(
            url="https://example.test/fabric",
            input_path=path,
            concurrency=0,
            duration_seconds=1,
            interval_seconds=1,
            deployment_topology="topology",
            authorization=None,
            timeout_seconds=1,
            verify=True,
            cert=None,
        )
    with pytest.raises(ValueError, match="HTTPS"):
        await probe.run_soak(
            url="http://example.test/fabric",
            input_path=path,
            concurrency=1,
            duration_seconds=1,
            interval_seconds=1,
            deployment_topology="topology",
            authorization=None,
            timeout_seconds=1,
            verify=True,
            cert=None,
        )


@pytest.mark.asyncio
async def test_soak_cancellation_propagates(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    path.write_bytes(b'{"event_id":"a"}\n')

    async def cancelled_runner(**kwargs):
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await probe.run_soak(
            url="https://example.test/fabric",
            input_path=path,
            concurrency=1,
            duration_seconds=1,
            interval_seconds=1,
            deployment_topology="cancel-test",
            authorization=None,
            timeout_seconds=1.0,
            verify=True,
            cert=None,
            probe_runner=cancelled_runner,
        )
