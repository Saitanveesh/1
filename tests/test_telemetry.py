import datetime as dt

from mon.domain import SecurityEvent
from mon.telemetry import TelemetryEngine


BASE = dt.datetime(2026, 9, 18, 12, 0, tzinfo=dt.UTC)


def observed(index: int, **attributes: object) -> SecurityEvent:
    return SecurityEvent(
        tenant_id="t1",
        site_id="s1",
        sensor_id="sensor",
        observed_at=BASE + dt.timedelta(seconds=index),
        category="network.connection",
        src_ip=f"10.0.0.{index + 1}",
        dst_ip="10.0.1.1",
        protocol="TCP",
        attributes=attributes,
    )


def test_missing_packet_and_byte_measurements_remain_unknown() -> None:
    engine = TelemetryEngine(window_seconds=60)
    engine.observe(observed(0))
    snapshot = engine.observe(observed(2))

    assert snapshot.observation_count == 2
    assert snapshot.events_per_second == 1.0
    assert snapshot.measured_packets is None
    assert snapshot.measured_bytes is None
    assert snapshot.measured_packets_per_second is None
    assert snapshot.measured_bytes_per_second is None


def test_supplied_measurements_are_aggregated_without_inventing_missing_values() -> None:
    engine = TelemetryEngine(window_seconds=60)
    engine.observe(observed(0, packets=10, bytes=1000))
    engine.observe(observed(2))
    snapshot = engine.observe(observed(4, packets=6, bytes=600))

    assert snapshot.measured_packets == 16
    assert snapshot.measured_bytes == 1600
    assert snapshot.measured_packets_per_second == 4.0
    assert snapshot.measured_bytes_per_second == 400.0
    assert snapshot.protocol_counts == {"tcp": 3}
    assert snapshot.unique_src_ips == 3
