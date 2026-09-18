import httpx
import pytest

from mon.domain import SecurityEvent
from mon.site_controller import HttpControlPlaneSender


@pytest.mark.asyncio
async def test_control_plane_sender_attaches_bearer_token(monkeypatch) -> None:
    observed: dict[str, object] = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"accepted_event_ids": ["event-1"]}

    class FakeClient:
        def __init__(self, **kwargs) -> None:
            observed.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

        async def post(self, path: str, json: object):
            observed["path"] = path
            observed["json"] = json
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    sender = HttpControlPlaneSender(
        "https://control.example",
        bearer_token="site-token",
    )
    accepted = await sender.send_batch(
        [
            SecurityEvent(
                event_id="event-1",
                tenant_id="tenant-a",
                site_id="site-1",
                sensor_id="sensor-1",
                category="network.connection",
            )
        ]
    )

    assert accepted == {"event-1"}
    assert observed["headers"] == {"Authorization": "Bearer site-token"}
    assert observed["verify"] is True
    assert observed["path"] == "/api/v1/events/batch"
