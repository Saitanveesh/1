from __future__ import annotations

import datetime as dt
import json

import httpx
import pytest

from mon.event_fabric import FabricEnvelope, FabricIngestResult
from mon.event_fabric_transport import HttpFabricPublisher


def _envelope() -> FabricEnvelope:
    now = dt.datetime(2026, 9, 19, 6, 30, tzinfo=dt.UTC)
    return FabricEnvelope(
        event_id="event-1",
        tenant_id="tenant-a",
        site_id="site-a",
        event_type="telemetry.normalized.security_event",
        schema_version=1,
        observed_at=now,
        produced_at=now + dt.timedelta(seconds=1),
        source="sensor-a",
        payload={"event_id": "event-1", "value": 7},
    )


@pytest.mark.asyncio
async def test_http_publisher_sends_exact_canonical_envelope() -> None:
    envelope = _envelope()
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            201,
            json=FabricIngestResult(
                event_id=envelope.event_id,
                duplicate=False,
                envelope_sha256=envelope.canonical_sha256,
            ).model_dump(mode="json"),
        )

    publisher = HttpFabricPublisher(
        "https://fabric.example.test",
        bearer_token="site-token",
        transport=httpx.MockTransport(handler),
    )
    await publisher.publish(envelope)

    assert len(seen) == 1
    request = seen[0]
    assert request.url.path == "/api/v1/site/fabric/events"
    assert request.headers["authorization"] == "Bearer site-token"
    assert request.headers["content-type"] == "application/json"
    assert request.content == envelope.canonical_json().encode("utf-8")
    assert json.loads(request.content) == envelope.model_dump(mode="json")


@pytest.mark.asyncio
async def test_http_publisher_surfaces_rejection_for_durable_retry() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, request=request)

    publisher = HttpFabricPublisher(
        "https://fabric.example.test",
        bearer_token="site-token",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(httpx.HTTPStatusError):
        await publisher.publish(_envelope())


def test_http_publisher_rejects_plaintext_production_url() -> None:
    with pytest.raises(ValueError, match="requires HTTPS"):
        HttpFabricPublisher(
            "http://fabric.example.test",
            bearer_token="site-token",
        )


def test_http_publisher_requires_authentication() -> None:
    with pytest.raises(ValueError, match="bearer token"):
        HttpFabricPublisher(
            "https://fabric.example.test",
            bearer_token="",
        )


@pytest.mark.asyncio
async def test_http_publisher_rejects_mismatched_acknowledgement() -> None:
    envelope = _envelope()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            201,
            json=FabricIngestResult(
                event_id=envelope.event_id,
                duplicate=False,
                envelope_sha256="0" * 64,
            ).model_dump(mode="json"),
            request=request,
        )

    publisher = HttpFabricPublisher(
        "https://fabric.example.test",
        bearer_token="site-token",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(RuntimeError, match="digest"):
        await publisher.publish(envelope)
