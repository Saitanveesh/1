import datetime as dt

from mon.detection import DetectionEngine
from mon.domain import SecurityEvent


def test_out_of_order_events_do_not_expand_recon_window_backwards() -> None:
    engine = DetectionEngine()
    base = dt.datetime(2026, 9, 18, 12, 0, tzinfo=dt.UTC)

    newer = SecurityEvent(
        tenant_id="t1",
        site_id="s1",
        sensor_id="sensor",
        observed_at=base + dt.timedelta(seconds=30),
        category="network.connection",
        src_ip="10.0.0.5",
        dst_ip="10.0.0.20",
        protocol="tcp",
        attributes={"tcp_syn": True, "tcp_ack": False, "dst_port": 80},
    )
    older = newer.model_copy(
        update={
            "event_id": "older",
            "observed_at": base,
            "dst_ip": "10.0.0.21",
        }
    )

    engine.process(newer)
    engine.process(older)

    key = ("tcp-syn-recon", "t1", "s1", "10.0.0.5")
    window = engine._windows[key]
    assert len(window) == 1
    assert window[0].observed_at == newer.observed_at
