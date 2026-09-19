import json

import pytest

from mon.sensor_collector import (
    SensorDeliveryError,
    SQLiteSensorCursorStore,
    SuricataFileCollector,
    ZeekFileCollector,
)


class FakeSensorClient:
    def __init__(self) -> None:
        self.zeek_batches: list[tuple[str, list[dict[str, object]]]] = []
        self.suricata_batches: list[list[dict[str, object]]] = []
        self.fail = False

    async def send_zeek(
        self,
        log_type: str,
        records: list[dict[str, object]],
    ) -> None:
        if self.fail:
            raise SensorDeliveryError("simulated ingress outage")
        self.zeek_batches.append((log_type, records))

    async def send_suricata(
        self,
        records: list[dict[str, object]],
    ) -> None:
        if self.fail:
            raise SensorDeliveryError("simulated ingress outage")
        self.suricata_batches.append(records)


def write_json_lines(path, records, *, final_newline: bool = True) -> None:
    payload = "\n".join(json.dumps(record) for record in records)
    if final_newline:
        payload += "\n"
    path.write_text(payload, encoding="utf-8")


def suricata_record(
    event_type: str,
    *,
    timestamp: str = "2026-09-19T04:00:00+00:00",
) -> dict[str, object]:
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "src_ip": "10.0.0.10",
        "dest_ip": "10.0.0.20",
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 1,
            "pkts_toclient": 1,
        },
    }


def zeek_record(uid: str) -> dict[str, object]:
    return {
        "ts": 1774911641.78917,
        "uid": uid,
        "id.orig_h": "10.0.0.10",
        "id.resp_h": "10.0.0.20",
        "proto": "tcp",
    }


def test_cursor_store_is_bound_to_sensor_identity(tmp_path) -> None:
    path = tmp_path / "cursors.db"
    first = SQLiteSensorCursorStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="sensor-a",
    )
    first.close()

    reopened = SQLiteSensorCursorStore(path, sensor_id="sensor-a")
    reopened.close()

    with pytest.raises(ValueError, match="sensor_id mismatch"):
        SQLiteSensorCursorStore(
            path,
            tenant_id="tenant-a",
            site_id="site-a",
            sensor_id="sensor-b",
        )


@pytest.mark.asyncio
async def test_zeek_collector_commits_only_complete_lines(tmp_path) -> None:
    log_dir = tmp_path / "zeek"
    log_dir.mkdir()
    conn_log = log_dir / "conn.log"
    first = json.dumps(zeek_record("one")) + "\n"
    second = json.dumps(zeek_record("two"))
    conn_log.write_text(first + second[:20], encoding="utf-8")

    store = SQLiteSensorCursorStore(
        tmp_path / "zeek-cursors.db",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="zeek-1",
    )
    client = FakeSensorClient()
    collector = ZeekFileCollector(log_dir, store, client)
    try:
        result = await collector.poll_once()
        assert result["state"] == "READY"
        assert result["sent"] == 1
        assert client.zeek_batches[0][0] == "conn"
        assert client.zeek_batches[0][1][0]["uid"] == "one"

        with conn_log.open("a", encoding="utf-8") as handle:
            handle.write(second[20:] + "\n")

        result = await collector.poll_once()
        assert result["sent"] == 1
        assert client.zeek_batches[1][1][0]["uid"] == "two"
    finally:
        store.close()


@pytest.mark.asyncio
async def test_suricata_collector_filters_unsupported_eve_types_without_stalling(
    tmp_path,
) -> None:
    eve = tmp_path / "eve.json"
    write_json_lines(
        eve,
        [
            suricata_record("alert"),
            suricata_record("stats"),
            suricata_record(
                "flow",
                timestamp="2026-09-19T04:00:01+00:00",
            ),
        ],
    )
    store = SQLiteSensorCursorStore(
        tmp_path / "suricata-cursors.db",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="suricata-1",
    )
    client = FakeSensorClient()
    collector = SuricataFileCollector(
        eve,
        store,
        client,
        batch_size=3,
    )
    try:
        result = await collector.poll_once()

        assert result["state"] == "READY"
        assert result["sent"] == 2
        assert result["filtered"] == 1
        assert len(client.suricata_batches) == 1
        assert [
            item["event_type"]
            for item in client.suricata_batches[0]
        ] == ["alert", "flow"]
        diagnostics = store.diagnostics()
        assert diagnostics["sources"][0]["filtered_records"] == 1
    finally:
        store.close()


@pytest.mark.asyncio
async def test_delivery_failure_does_not_advance_file_cursor(tmp_path) -> None:
    eve = tmp_path / "eve.json"
    write_json_lines(eve, [suricata_record("flow")])
    store = SQLiteSensorCursorStore(
        tmp_path / "cursors.db",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="suricata-1",
    )
    client = FakeSensorClient()
    client.fail = True
    collector = SuricataFileCollector(eve, store, client)
    try:
        first = await collector.poll_once()
        assert first["state"] == "DEGRADED"
        assert store.get("suricata:eve") is None

        client.fail = False
        second = await collector.poll_once()
        assert second["state"] == "READY"
        assert second["sent"] == 1
        cursor = store.get("suricata:eve")
        assert cursor is not None
        assert cursor.offset == eve.stat().st_size
    finally:
        store.close()


@pytest.mark.asyncio
async def test_rotation_drains_old_inode_before_new_file(tmp_path) -> None:
    eve = tmp_path / "eve.json"
    first_record = suricata_record("flow")
    second_record = suricata_record(
        "alert",
        timestamp="2026-09-19T04:00:01+00:00",
    )
    write_json_lines(eve, [first_record])

    store = SQLiteSensorCursorStore(
        tmp_path / "cursors.db",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="suricata-1",
    )
    client = FakeSensorClient()
    collector = SuricataFileCollector(eve, store, client)
    try:
        first = await collector.poll_once()
        assert first["sent"] == 1

        rotated = tmp_path / "eve.json.1"
        eve.rename(rotated)
        write_json_lines(eve, [second_record])

        transition = await collector.poll_once()
        assert transition["sent"] == 0

        second = await collector.poll_once()
        assert second["sent"] == 1
        assert [
            batch[0]["event_type"]
            for batch in client.suricata_batches
        ] == ["flow", "alert"]
    finally:
        store.close()


@pytest.mark.asyncio
async def test_missing_rotated_inode_is_reported_as_gap_not_silently_reset(
    tmp_path,
) -> None:
    eve = tmp_path / "eve.json"
    write_json_lines(eve, [suricata_record("flow")])
    store = SQLiteSensorCursorStore(
        tmp_path / "cursors.db",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="suricata-1",
    )
    client = FakeSensorClient()
    collector = SuricataFileCollector(eve, store, client)
    try:
        assert (await collector.poll_once())["sent"] == 1

        eve.unlink()
        write_json_lines(
            eve,
            [
                suricata_record(
                    "alert",
                    timestamp="2026-09-19T04:00:02+00:00",
                )
            ],
        )

        result = await collector.poll_once()
        assert result["state"] == "DEGRADED"
        assert "cannot locate prior inode" in result["error"]
        cursor = store.get("suricata:eve")
        assert cursor is not None
        assert cursor.offset > 0
    finally:
        store.close()


@pytest.mark.asyncio
async def test_same_inode_truncation_is_reported_as_gap(tmp_path) -> None:
    eve = tmp_path / "eve.json"
    write_json_lines(
        eve,
        [
            suricata_record("flow"),
            suricata_record(
                "alert",
                timestamp="2026-09-19T04:00:01+00:00",
            ),
        ],
    )
    store = SQLiteSensorCursorStore(
        tmp_path / "cursors.db",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="suricata-1",
    )
    client = FakeSensorClient()
    collector = SuricataFileCollector(eve, store, client)
    try:
        assert (await collector.poll_once())["sent"] == 2

        with eve.open("w", encoding="utf-8") as handle:
            handle.write("{}\n")

        result = await collector.poll_once()
        assert result["state"] == "DEGRADED"
        assert "truncated below committed offset" in result["error"]
    finally:
        store.close()


@pytest.mark.asyncio
async def test_missing_core_sensor_sources_report_degraded(tmp_path) -> None:
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    zeek_store = SQLiteSensorCursorStore(
        tmp_path / "zeek-missing.db",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="zeek-1",
    )
    suricata_store = SQLiteSensorCursorStore(
        tmp_path / "suricata-missing.db",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="suricata-1",
    )
    client = FakeSensorClient()
    try:
        zeek = ZeekFileCollector(zeek_dir, zeek_store, client)
        zeek_result = await zeek.poll_once()
        assert zeek_result["state"] == "DEGRADED"
        assert zeek_result["required_source_missing"] is True

        suricata = SuricataFileCollector(
            tmp_path / "missing-eve.json",
            suricata_store,
            client,
        )
        suricata_result = await suricata.poll_once()
        assert suricata_result["state"] == "DEGRADED"
        assert suricata_result["source_missing"] is True
    finally:
        zeek_store.close()
        suricata_store.close()
