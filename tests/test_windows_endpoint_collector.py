from __future__ import annotations

import datetime as dt

import pytest

from mon.domain import SecurityEvent
from mon.endpoint import normalize_endpoint_event
from mon.windows_endpoint_collector import (
    SQLiteWindowsEventBuffer,
    WindowsCollectorCheckpointError,
    WindowsCollectorState,
    WindowsEndpointCollector,
    WindowsEventCheckpointStore,
    WindowsEventPermissionDenied,
    WindowsEventSourceUnavailable,
    deterministic_event_id,
    normalize_windows_event,
    parse_windows_event_xml,
)


def security_xml(event_id: int, record_id: int, fields: dict[str, str]) -> str:
    data = "\n".join(
        f'<Data Name="{name}">{value}</Data>'
        for name, value in fields.items()
    )
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="2026-09-20T00:00:00.000000Z" />
    <EventRecordID>{record_id}</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WORKSTATION-1</Computer>
  </System>
  <EventData>{data}</EventData>
</Event>"""


def sysmon_xml(event_id: int, record_id: int, fields: dict[str, str]) -> str:
    data = "\n".join(
        f'<Data Name="{name}">{value}</Data>'
        for name, value in fields.items()
    )
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="2026-09-20T00:00:00.000000Z" />
    <EventRecordID>{record_id}</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WORKSTATION-1</Computer>
  </System>
  <EventData>{data}</EventData>
</Event>"""


def endpoint(record_xml: str):
    record = parse_windows_event_xml(record_xml)
    value = normalize_windows_event(
        record,
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="windows-sensor-1",
    )
    assert value is not None
    return value


def test_auth_success_normalization_preserves_sid_and_logon_evidence() -> None:
    item = endpoint(
        security_xml(
            4624,
            100,
            {
                "TargetUserSid": "S-1-5-21-1000",
                "TargetUserName": "alice",
                "TargetDomainName": "MON",
                "TargetLogonId": "0x123",
                "IpAddress": "10.0.0.5",
            },
        )
    )

    assert item.kind.value == "AUTH_SUCCESS"
    assert item.user_sid == "S-1-5-21-1000"
    assert item.user_domain == "MON"
    assert item.session_id == "0x123"
    event = item.event_id
    assert event.startswith("windows-endpoint:")
    normalized = item.model_dump()
    assert "password" not in str(normalized).casefold()


def test_auth_failure_and_deterministic_event_id_replay() -> None:
    raw = security_xml(
        4625,
        101,
        {
            "TargetUserSid": "S-1-5-21-1000",
            "TargetUserName": "alice",
            "TargetDomainName": "MON",
            "TargetLogonId": "0x124",
            "IpAddress": "10.0.0.6",
        },
    )
    first = parse_windows_event_xml(raw)
    second = parse_windows_event_xml(raw)

    assert first == second
    assert deterministic_event_id(
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="windows-sensor-1",
        record=first,
    ) == deterministic_event_id(
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="windows-sensor-1",
        record=second,
    )
    assert endpoint(raw).kind.value == "AUTH_FAILURE"


def test_process_event_normalization_and_pid_reuse_protection() -> None:
    first = endpoint(
        security_xml(
            4688,
            200,
            {
                "SubjectUserSid": "S-1-5-21-1000",
                "SubjectUserName": "alice",
                "SubjectDomainName": "MON",
                "SubjectLogonId": "0x123",
                "NewProcessId": "0x1000",
                "CreatorProcessId": "0x100",
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
            },
        )
    )
    second = endpoint(
        security_xml(
            4688,
            201,
            {
                "SubjectUserSid": "S-1-5-21-1000",
                "SubjectUserName": "alice",
                "SubjectDomainName": "MON",
                "SubjectLogonId": "0x123",
                "NewProcessId": "0x1000",
                "CreatorProcessId": "0x100",
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c hostname",
            },
        )
    )

    assert first.kind.value == "PROCESS_START"
    assert first.process_pid == 4096
    assert first.process_guid is None
    assert first.event_id != second.event_id


def test_optional_sysmon_process_network_record_is_not_inferred_from_security() -> None:
    security = endpoint(
        security_xml(
            4688,
            300,
            {
                "SubjectUserName": "alice",
                "NewProcessId": "0x1000",
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            },
        )
    )
    assert security.dst_ip is None
    assert security.dst_port is None

    sysmon = endpoint(
        sysmon_xml(
            3,
            301,
            {
                "User": "MON\\alice",
                "ProcessGuid": "{guid-1}",
                "ProcessId": "4096",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "SourceIp": "10.0.0.5",
                "DestinationIp": "10.0.0.9",
                "DestinationPort": "445",
                "Protocol": "tcp",
            },
        )
    )
    assert sysmon.kind.value == "NETWORK_CONNECTION"
    assert sysmon.process_guid == "{guid-1}"
    assert sysmon.dst_ip == "10.0.0.9"
    assert sysmon.dst_port == 445


def test_absent_fields_remain_absent_and_malformed_input_is_rejected() -> None:
    item = endpoint(security_xml(4624, 400, {"TargetUserName": "alice"}))
    assert item.user_sid is None
    assert item.src_ip is None

    with pytest.raises(ValueError, match="exceeds"):
        parse_windows_event_xml("<Event>" + ("x" * 600_000) + "</Event>")


def test_checkpoint_restart_and_corruption_behavior(tmp_path) -> None:
    path = tmp_path / "checkpoint.json"
    store = WindowsEventCheckpointStore(path, channel="Security")
    assert store.load() is None
    store.save(last_record_id=123, now=dt.datetime(2026, 9, 20, tzinfo=dt.UTC))
    assert store.load().last_record_id == 123

    path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(WindowsCollectorCheckpointError, match="corrupt"):
        store.load()


def test_buffer_scope_retry_and_transport_failure(tmp_path) -> None:
    buffer = SQLiteWindowsEventBuffer(
        tmp_path / "buffer.db",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="windows-sensor-1",
    )
    try:
        event = endpoint(security_xml(4624, 500, {"TargetUserName": "alice"}))
        security_event = SecurityEvent.model_validate(normalize_endpoint_event(event))
        assert buffer.enqueue(security_event)
        assert buffer.enqueue(security_event) is False
        assert buffer.count() == 1
        with pytest.raises(ValueError, match="scope"):
            buffer.enqueue(
                security_event.model_copy(update={"tenant_id": "tenant-b"})
            )
    finally:
        buffer.close()


@pytest.mark.asyncio
async def test_collector_health_buffering_and_transport_failure(tmp_path) -> None:
    class Source:
        def read_after(self, last_record_id, *, limit):
            return [security_xml(4624, 600, {"TargetUserName": "alice"})]

    class FailingSender:
        async def send(self, event):
            raise OSError("site unavailable")

    buffer = SQLiteWindowsEventBuffer(
        tmp_path / "buffer.db",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="windows-sensor-1",
    )
    collector = WindowsEndpointCollector(
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="windows-sensor-1",
        channel="Security",
        source=Source(),
        checkpoint_store=WindowsEventCheckpointStore(
            tmp_path / "checkpoint.json",
            channel="Security",
        ),
        buffer=buffer,
        sender=FailingSender(),
    )
    try:
        health = await collector.collect_once()
        assert health.state is WindowsCollectorState.TRANSPORT_UNAVAILABLE
        assert health.buffered_events == 1
        assert health.last_record_id == 600
    finally:
        buffer.close()


@pytest.mark.asyncio
async def test_collector_health_reports_source_and_permission_failures(tmp_path) -> None:
    class UnavailableSource:
        def read_after(self, last_record_id, *, limit):
            raise WindowsEventSourceUnavailable("Security channel unavailable")

    class PermissionSource:
        def read_after(self, last_record_id, *, limit):
            raise WindowsEventPermissionDenied("access denied")

    class Sender:
        async def send(self, event):
            return None

    for source, expected in (
        (UnavailableSource(), WindowsCollectorState.SOURCE_UNAVAILABLE),
        (PermissionSource(), WindowsCollectorState.PERMISSION_DENIED),
    ):
        buffer = SQLiteWindowsEventBuffer(
            tmp_path / f"{expected.value}.db",
            tenant_id="tenant-a",
            site_id="site-a",
            sensor_id="windows-sensor-1",
        )
        collector = WindowsEndpointCollector(
            tenant_id="tenant-a",
            site_id="site-a",
            sensor_id="windows-sensor-1",
            channel="Security",
            source=source,
            checkpoint_store=WindowsEventCheckpointStore(
                tmp_path / f"{expected.value}.json",
                channel="Security",
            ),
            buffer=buffer,
            sender=Sender(),
        )
        try:
            health = await collector.collect_once()
            assert health.state is expected
            assert health.buffered_events == 0
        finally:
            buffer.close()
