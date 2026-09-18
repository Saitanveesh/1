import datetime as dt

from mon.asset_engine import AssetEngine
from mon.domain import SecurityEvent
from mon.store import InMemoryStore


def event(index: int, **attributes: object) -> SecurityEvent:
    return SecurityEvent(
        tenant_id="tenant-a",
        site_id="site-1",
        sensor_id="sensor-1",
        observed_at=dt.datetime(2026, 9, 18, 12, 0, tzinfo=dt.UTC)
        + dt.timedelta(seconds=index),
        category="network.connection",
        src_ip="10.0.0.17",
        dst_ip="10.0.0.20",
        protocol="tcp",
        attributes=attributes,
    )


def test_mac_identity_accumulates_only_observed_metadata() -> None:
    store = InMemoryStore()
    engine = AssetEngine(store)

    first = engine.observe(
        event(
            0,
            src_mac="00:11:22:33:44:55",
            dhcp_hostname="workstation-17",
            src_vendor="Example Vendor",
            packets=4,
            bytes=800,
        )
    )
    second = engine.observe(
        event(
            1,
            src_mac="00:11:22:33:44:55",
            tcp_syn=True,
            tcp_ack=True,
            src_port=445,
            packets=2,
            bytes=300,
        )
    )

    assert first is not None
    assert second is not None
    assert second.asset_id == "mac:00:11:22:33:44:55"
    assert second.display_name == "workstation-17"
    assert second.hostnames == {"workstation-17"}
    assert second.vendor == "Example Vendor"
    assert second.observed_tcp_services == {445}
    assert second.measured_packets == 6
    assert second.measured_bytes == 1100
    assert "PASSIVE_SOURCE_MAC" in second.identity_evidence
    assert "PASSIVE_DHCP_HOSTNAME" in second.identity_evidence


def test_ip_only_identity_is_explicitly_weak() -> None:
    store = InMemoryStore()
    asset = AssetEngine(store).observe(event(0))
    assert asset is not None
    assert asset.asset_id == "ip:10.0.0.17"
    assert asset.identity_evidence == {"SOURCE_IP_OBSERVATION_ONLY"}
    assert asset.measured_packets is None
    assert asset.measured_bytes is None


def test_asset_ids_are_isolated_by_tenant_and_site() -> None:
    store = InMemoryStore()
    engine = AssetEngine(store)
    first = engine.observe(event(0, src_mac="00:11:22:33:44:55"))
    other = event(1, src_mac="00:11:22:33:44:55").model_copy(
        update={"tenant_id": "tenant-b"}
    )
    second = engine.observe(other)

    assert first is not None and second is not None
    assert len(store.list_assets("tenant-a", "site-1")) == 1
    assert len(store.list_assets("tenant-b", "site-1")) == 1
