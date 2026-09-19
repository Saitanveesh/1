import datetime as dt

import pytest

from mon.domain import EvidenceClass
from mon.pipeline import SecurityPipeline
from mon.sensors.common import SensorNormalizationError
from mon.sensors.suricata import SuricataEveNormalizer
from mon.sensors.zeek import ZeekJsonNormalizer


def test_zeek_conn_normalization_preserves_measured_totals_and_tcp_history() -> None:
    normalizer = ZeekJsonNormalizer("tenant-a", "site-a", "zeek-1")
    record = {
        "ts": 1774911641.78917,
        "uid": "CHhAvVGS1DHFjwGM9",
        "id.orig_h": "172.17.0.2",
        "id.orig_p": 36844,
        "id.resp_h": "1.1.1.1",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "orig_pkts": 4,
        "resp_pkts": 3,
        "orig_ip_bytes": 400,
        "resp_ip_bytes": 900,
        "history": "ShADadFf",
    }

    first = normalizer.normalize("conn", record)
    second = normalizer.normalize("conn.log", dict(record))

    assert first == second
    assert first.category == "network.connection"
    assert first.src_ip == "172.17.0.2"
    assert first.dst_ip == "1.1.1.1"
    assert first.protocol == "tcp"
    assert first.attributes["src_port"] == 36844
    assert first.attributes["dst_port"] == 443
    assert first.attributes["packets"] == 7
    assert first.attributes["bytes"] == 1300
    assert first.attributes["tcp_syn"] is True
    assert first.attributes["tcp_ack"] is True
    assert first.evidence[0].evidence_class is EvidenceClass.NETWORK_FLOW
    assert first.evidence[0].raw_reference == "zeek:conn:CHhAvVGS1DHFjwGM9"


def test_zeek_does_not_invent_total_when_one_counter_side_is_missing() -> None:
    event = ZeekJsonNormalizer("tenant-a", "site-a", "zeek-1").normalize(
        "conn",
        {
            "ts": 1774911641.78917,
            "uid": "uid-1",
            "id.orig_h": "10.0.0.10",
            "id.resp_h": "10.0.0.20",
            "proto": "tcp",
            "orig_pkts": 4,
            "orig_ip_bytes": 400,
        },
    )

    assert event.attributes["orig_packets"] == 4
    assert "packets" not in event.attributes
    assert "bytes" not in event.attributes


def test_zeek_dns_record_maps_query_without_reversing_originator() -> None:
    event = ZeekJsonNormalizer("tenant-a", "site-a", "zeek-1").normalize(
        "dns",
        {
            "ts": 1774911641.803041,
            "uid": "dns-uid",
            "id.orig_h": "172.17.0.2",
            "id.orig_p": 36844,
            "id.resp_h": "1.1.1.1",
            "id.resp_p": 53,
            "proto": "udp",
            "query": "zeek.org",
            "qtype_name": "A",
            "rcode_name": "NOERROR",
            "rejected": False,
        },
    )

    assert event.category == "dns.query"
    assert event.src_ip == "172.17.0.2"
    assert event.dst_ip == "1.1.1.1"
    assert event.attributes["dns_query"] == "zeek.org"
    assert event.attributes["dns_qtype"] == "A"
    assert event.attributes["dns_rcode"] == "NOERROR"


def test_suricata_alert_normalizes_into_existing_ids_detector_contract() -> None:
    record = {
        "timestamp": "2026-09-19T04:00:00.123456+0000",
        "flow_id": 1676750115612680,
        "event_type": "alert",
        "src_ip": "198.51.100.10",
        "src_port": 35361,
        "dest_ip": "10.0.0.20",
        "dest_port": 443,
        "proto": "TCP",
        "app_proto": "tls",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2024056,
            "rev": 4,
            "signature": "ET TEST suspicious session",
            "category": "Potentially Bad Traffic",
            "severity": 1,
        },
    }
    event = SuricataEveNormalizer(
        "tenant-a",
        "site-a",
        "suricata-1",
    ).normalize(record)

    assert event.category == "suricata.alert"
    assert event.attributes["signature"] == "ET TEST suspicious session"
    assert event.attributes["signature_id"] == 2024056
    assert event.attributes["severity"] == 1
    assert event.attributes["engine"] == "suricata"
    assert event.evidence[0].evidence_class is EvidenceClass.IDS_ALERT

    result = SecurityPipeline().process_event(event)
    assert len(result.findings) == 1
    assert result.findings[0].detector_id == "network-ids-signature"
    assert result.findings[0].confidence == 0.95


def test_suricata_flow_preserves_bidirectional_measurements_and_tcp_flags() -> None:
    event = SuricataEveNormalizer(
        "tenant-a",
        "site-a",
        "suricata-1",
    ).normalize(
        {
            "timestamp": "2026-09-19T04:00:00.123456+0000",
            "flow_id": 1676750115612680,
            "event_type": "flow",
            "src_ip": "10.0.0.20",
            "src_port": 49175,
            "dest_ip": "198.51.100.10",
            "dest_port": 443,
            "proto": "TCP",
            "app_proto": "tls",
            "flow": {
                "pkts_toserver": 3869,
                "pkts_toclient": 1523,
                "bytes_toserver": 3536402,
                "bytes_toclient": 94102,
                "age": 40,
                "state": "closed",
                "reason": "shutdown",
                "alerted": True,
            },
            "tcp": {
                "syn": True,
                "ack": True,
                "rst": True,
                "state": "closed",
            },
        }
    )

    assert event.category == "network.connection"
    assert event.attributes["packets"] == 5392
    assert event.attributes["bytes"] == 3630504
    assert event.attributes["tcp_syn"] is True
    assert event.attributes["tcp_ack"] is True
    assert event.attributes["flow_alerted"] is True


def test_suricata_dns_v3_preserves_request_response_direction() -> None:
    normalizer = SuricataEveNormalizer("tenant-a", "site-a", "suricata-1")
    request = normalizer.normalize(
        {
            "timestamp": "2026-09-19T04:00:00+00:00",
            "event_type": "dns",
            "src_ip": "10.0.0.10",
            "src_port": 54000,
            "dest_ip": "1.1.1.1",
            "dest_port": 53,
            "proto": "UDP",
            "dns": {
                "version": 3,
                "type": "request",
                "id": 7,
                "rcode": "NOERROR",
                "queries": [{"rrname": "example.com", "rrtype": "A"}],
            },
        }
    )
    response = normalizer.normalize(
        {
            "timestamp": "2026-09-19T04:00:00.010000+00:00",
            "event_type": "dns",
            "src_ip": "1.1.1.1",
            "src_port": 53,
            "dest_ip": "10.0.0.10",
            "dest_port": 54000,
            "proto": "UDP",
            "dns": {
                "version": 3,
                "type": "response",
                "id": 7,
                "rcode": "NOERROR",
                "queries": [{"rrname": "example.com", "rrtype": "A"}],
                "answers": [{"rrname": "example.com", "rrtype": "A", "rdata": "203.0.113.8"}],
            },
        }
    )

    assert request.category == "dns.query"
    assert request.src_ip == "10.0.0.10"
    assert request.attributes["dns_query"] == "example.com"
    assert response.category == "dns.response"
    assert response.src_ip == "1.1.1.1"
    assert response.attributes["dns_answer_count"] == 1


def test_suricata_partial_flow_does_not_invent_aggregate_counters() -> None:
    event = SuricataEveNormalizer(
        "tenant-a",
        "site-a",
        "suricata-1",
    ).normalize(
        {
            "timestamp": "2026-09-19T04:00:00+00:00",
            "event_type": "flow",
            "src_ip": "10.0.0.10",
            "dest_ip": "10.0.0.20",
            "proto": "UDP",
            "flow": {"pkts_toserver": 5, "bytes_toserver": 500},
        }
    )

    assert event.attributes["packets_to_server"] == 5
    assert event.attributes["bytes_to_server"] == 500
    assert "packets" not in event.attributes
    assert "bytes" not in event.attributes


def test_normalizer_ids_are_deterministic_but_bound_to_sensor_scope() -> None:
    record = {
        "timestamp": "2026-09-19T04:00:00+00:00",
        "event_type": "tls",
        "src_ip": "10.0.0.10",
        "dest_ip": "10.0.0.20",
        "proto": "TCP",
        "tls": {"sni": "example.com", "version": "TLS 1.3"},
    }
    first = SuricataEveNormalizer("tenant-a", "site-a", "sensor-1").normalize(record)
    replay = SuricataEveNormalizer("tenant-a", "site-a", "sensor-1").normalize(dict(record))
    other_sensor = SuricataEveNormalizer(
        "tenant-a",
        "site-a",
        "sensor-2",
    ).normalize(record)

    assert first.event_id == replay.event_id
    assert first.evidence[0].evidence_id == replay.evidence[0].evidence_id
    assert first.event_id != other_sensor.event_id


@pytest.mark.parametrize(
    ("normalizer", "args", "message"),
    [
        (
            ZeekJsonNormalizer("tenant-a", "site-a", "zeek-1"),
            ("conn", {"ts": "not-an-epoch", "id.orig_h": "10.0.0.1"}),
            "numeric epoch",
        ),
        (
            ZeekJsonNormalizer("tenant-a", "site-a", "zeek-1"),
            ("conn", {"ts": 1.0, "id.orig_h": "not-an-ip"}),
            "valid IP",
        ),
        (
            SuricataEveNormalizer("tenant-a", "site-a", "suricata-1"),
            ({"timestamp": "2026-09-19T04:00:00", "event_type": "flow"},),
            "timezone offset",
        ),
        (
            SuricataEveNormalizer("tenant-a", "site-a", "suricata-1"),
            (
                {
                    "timestamp": "2026-09-19T04:00:00+00:00",
                    "event_type": "stats",
                },
            ),
            "unsupported",
        ),
    ],
)
def test_sensor_normalizers_fail_closed_on_invalid_or_unsupported_records(
    normalizer,
    args,
    message,
) -> None:
    with pytest.raises(SensorNormalizationError, match=message):
        normalizer.normalize(*args)


def test_suricata_preserves_packet_reference_when_eve_supplies_pcap_location() -> None:
    event = SuricataEveNormalizer(
        "tenant-a",
        "site-a",
        "suricata-1",
    ).normalize(
        {
            "timestamp": "2026-09-19T04:00:00+00:00",
            "flow_id": 42,
            "pcap_cnt": 53381,
            "pcap_filename": "/evidence/capture-001.pcap",
            "event_type": "alert",
            "src_ip": "198.51.100.10",
            "dest_ip": "10.0.0.20",
            "proto": "TCP",
            "alert": {
                "signature_id": 7,
                "signature": "TEST packet reference",
                "severity": 2,
            },
        }
    )

    assert (
        event.evidence[0].raw_reference
        == "pcap:/evidence/capture-001.pcap#packet=53381"
    )


def test_sensor_normalizer_rejects_oversized_raw_record() -> None:
    normalizer = SuricataEveNormalizer("tenant-a", "site-a", "suricata-1")
    with pytest.raises(SensorNormalizationError, match="1 MiB"):
        normalizer.normalize(
            {
                "timestamp": "2026-09-19T04:00:00+00:00",
                "event_type": "flow",
                "src_ip": "10.0.0.10",
                "dest_ip": "10.0.0.20",
                "proto": "TCP",
                "padding": "x" * (1024 * 1024),
            }
        )
