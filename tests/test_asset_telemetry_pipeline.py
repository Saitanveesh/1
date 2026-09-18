import datetime as dt

from mon.domain import SecurityEvent
from mon.pipeline import SecurityPipeline
from mon.store import InMemoryStore


def test_pipeline_updates_asset_and_telemetry_from_same_event() -> None:
    store = InMemoryStore()
    pipeline = SecurityPipeline(store=store)
    result = pipeline.process_event(
        SecurityEvent(
            event_id="asset-event-1",
            tenant_id="t1",
            site_id="s1",
            sensor_id="sensor",
            observed_at=dt.datetime(2026, 9, 18, 12, 0, tzinfo=dt.UTC),
            category="network.connection",
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            protocol="tcp",
            attributes={
                "src_mac": "00:11:22:33:44:55",
                "packets": 3,
                "bytes": 240,
            },
        )
    )

    assert result.duplicate is False
    assert len(result.asset_updates) == 1
    assert result.asset_updates[0].asset_id == "mac:00:11:22:33:44:55"
    assert result.telemetry is not None
    assert result.telemetry.observation_count == 1
    assert store.list_assets("t1", "s1")[0].measured_bytes == 240
