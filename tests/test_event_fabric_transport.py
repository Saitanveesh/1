import datetime as dt
import ssl

import pytest

from mon.domain import SecurityEvent
from mon.event_fabric import FabricIngestResult, security_event_envelope
from mon.event_fabric_transport import HttpFabricPublisher


class FakeResponse:
    def __init__(self, payload: dict[str, object], status_code: int = 201) -> None:
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import httpx

            request = httpx.Request("POST", "https://control.example")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError(
                "rejected",
                request=request,
                response=response,
            )

    def json(self) -> dict[str, object]:
        return self._payload


class FakeAsyncClient:
    instances: list["FakeAsyncClient"] = []
    response_payload: dict[str, object] = {}

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.post_calls: list[tuple[str, bytes]] = []
        type(self).instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def post(self, path: str, *, content: bytes):
        self.post_calls.append((path, content))
        return FakeResponse(type(self).response_payload)


def envelope():
    event = SecurityEvent(
        event_id="event-http-1",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="sensor-1",
        observed_at=dt.datetime(2026, 9, 19, 10, 0, tzinfo=dt.UTC),
        category="network.connection",
    )
    return security_event_envelope(
        event,
        produced_at=dt.datetime(2026, 9, 19, 10, 1, tzinfo=dt.UTC),
    )


@pytest.mark.asyncio
async def test_http_fabric_publisher_sends_exact_canonical_envelope(
    monkeypatch,
) -> None:
    item = envelope()
    FakeAsyncClient.instances.clear()
    FakeAsyncClient.response_payload = FabricIngestResult(
        event_id=item.event_id,
        duplicate=False,
        envelope_sha256=item.canonical_sha256,
    ).model_dump(mode="json")
    monkeypatch.setattr(
        "mon.event_fabric_transport.httpx.AsyncClient",
        FakeAsyncClient,
    )
    context = ssl.create_default_context()
    publisher = HttpFabricPublisher(
        "https://control.example",
        bearer_token="site-token",
        ssl_context=context,
    )

    await publisher.publish(item)

    assert len(FakeAsyncClient.instances) == 1
    client = FakeAsyncClient.instances[0]
    assert client.kwargs["base_url"] == "https://control.example"
    assert client.kwargs["verify"] is context
    assert client.kwargs["trust_env"] is False
    assert client.kwargs["headers"]["Authorization"] == "Bearer site-token"
    assert client.post_calls == [
        (
            "/api/v1/fabric/events",
            item.canonical_json().encode("utf-8"),
        )
    ]


@pytest.mark.asyncio
async def test_http_fabric_publisher_rejects_mismatched_acknowledgement(
    monkeypatch,
) -> None:
    item = envelope()
    FakeAsyncClient.instances.clear()
    FakeAsyncClient.response_payload = FabricIngestResult(
        event_id=item.event_id,
        duplicate=False,
        envelope_sha256="0" * 64,
    ).model_dump(mode="json")
    monkeypatch.setattr(
        "mon.event_fabric_transport.httpx.AsyncClient",
        FakeAsyncClient,
    )
    publisher = HttpFabricPublisher(
        "https://control.example",
        bearer_token="site-token",
        ssl_context=ssl.create_default_context(),
    )

    with pytest.raises(RuntimeError, match="digest"):
        await publisher.publish(item)


def test_http_fabric_publisher_requires_https_and_authentication() -> None:
    context = ssl.create_default_context()
    with pytest.raises(ValueError, match="https"):
        HttpFabricPublisher(
            "http://control.example",
            bearer_token="token",
            ssl_context=context,
        )
    with pytest.raises(ValueError, match="bearer"):
        HttpFabricPublisher(
            "https://control.example",
            bearer_token="",
            ssl_context=context,
        )
