from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from mon.domain import EvidenceClass, SecurityEvent
from mon.sensors.common import (
    SensorNormalizationError,
    add_if_present,
    bool_value,
    complete_sum,
    deterministic_event_id,
    evidence,
    floating,
    integer,
    ip,
    mapping,
    parse_iso_timestamp,
    port,
    text,
)

_SUPPORTED_EVENT_TYPES = {
    "alert",
    "flow",
    "dns",
    "http",
    "tls",
}


class SuricataEveNormalizer:
    """Normalize selected Suricata EVE records without fabricating telemetry."""

    def __init__(self, tenant_id: str, site_id: str, sensor_id: str) -> None:
        if not tenant_id or not site_id or not sensor_id:
            raise ValueError("tenant_id, site_id and sensor_id are required")
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.sensor_id = sensor_id

    @staticmethod
    def _common_attributes(record: Mapping[str, Any]) -> dict[str, Any]:
        attributes: dict[str, Any] = {}
        add_if_present(attributes, "flow_id", integer(record.get("flow_id")))
        add_if_present(attributes, "tx_id", integer(record.get("tx_id")))
        add_if_present(attributes, "src_port", port(record.get("src_port")))
        add_if_present(attributes, "dst_port", port(record.get("dest_port")))
        add_if_present(
            attributes,
            "app_proto",
            text(record.get("app_proto"), limit=64),
        )
        add_if_present(
            attributes,
            "community_id",
            text(record.get("community_id"), limit=256),
        )
        add_if_present(
            attributes,
            "interface",
            text(record.get("in_iface"), limit=128),
        )
        add_if_present(attributes, "pcap_count", integer(record.get("pcap_cnt")))
        add_if_present(
            attributes,
            "pcap_filename",
            text(record.get("pcap_filename"), limit=1000),
        )
        return attributes

    def _alert_attributes(self, record: Mapping[str, Any]) -> dict[str, Any]:
        attributes = self._common_attributes(record)
        alert = mapping(record.get("alert"))
        add_if_present(
            attributes,
            "signature",
            text(alert.get("signature"), limit=300),
        )
        add_if_present(
            attributes,
            "signature_id",
            integer(alert.get("signature_id")),
        )
        add_if_present(attributes, "rule_id", integer(alert.get("signature_id")))
        add_if_present(attributes, "gid", integer(alert.get("gid")))
        add_if_present(attributes, "revision", integer(alert.get("rev")))
        add_if_present(
            attributes,
            "severity",
            integer(alert.get("severity"), minimum=0),
        )
        add_if_present(
            attributes,
            "signature_category",
            text(alert.get("category"), limit=300),
        )
        add_if_present(
            attributes,
            "alert_action",
            text(alert.get("action"), limit=64),
        )
        add_if_present(
            attributes,
            "alert_engine",
            text(alert.get("engine"), limit=64),
        )
        # DetectionEngine expects "engine" for IDS evidence. Keep it explicit
        # and vendor-neutral at the normalized event layer.
        attributes["engine"] = "suricata"
        return attributes

    def _flow_attributes(self, record: Mapping[str, Any]) -> dict[str, Any]:
        attributes = self._common_attributes(record)
        flow = mapping(record.get("flow"))
        packets_to_server = integer(flow.get("pkts_toserver"))
        packets_to_client = integer(flow.get("pkts_toclient"))
        bytes_to_server = integer(flow.get("bytes_toserver"))
        bytes_to_client = integer(flow.get("bytes_toclient"))
        add_if_present(attributes, "packets_to_server", packets_to_server)
        add_if_present(attributes, "packets_to_client", packets_to_client)
        add_if_present(attributes, "bytes_to_server", bytes_to_server)
        add_if_present(attributes, "bytes_to_client", bytes_to_client)
        add_if_present(
            attributes,
            "packets",
            complete_sum(packets_to_server, packets_to_client),
        )
        add_if_present(
            attributes,
            "bytes",
            complete_sum(bytes_to_server, bytes_to_client),
        )
        add_if_present(
            attributes,
            "duration_seconds",
            floating(flow.get("age")),
        )
        add_if_present(
            attributes,
            "flow_state",
            text(flow.get("state"), limit=64),
        )
        add_if_present(
            attributes,
            "flow_reason",
            text(flow.get("reason"), limit=64),
        )
        add_if_present(
            attributes,
            "flow_alerted",
            bool_value(flow.get("alerted")),
        )

        tcp = mapping(record.get("tcp"))
        add_if_present(attributes, "tcp_syn", bool_value(tcp.get("syn")))
        add_if_present(attributes, "tcp_ack", bool_value(tcp.get("ack")))
        add_if_present(attributes, "tcp_rst", bool_value(tcp.get("rst")))
        add_if_present(attributes, "tcp_fin", bool_value(tcp.get("fin")))
        add_if_present(attributes, "tcp_psh", bool_value(tcp.get("psh")))
        add_if_present(
            attributes,
            "tcp_state",
            text(tcp.get("state"), limit=64),
        )
        return attributes

    @staticmethod
    def _first_dns_query(dns: Mapping[str, Any]) -> Mapping[str, Any]:
        queries = dns.get("queries")
        if isinstance(queries, Sequence) and not isinstance(
            queries,
            (str, bytes, bytearray),
        ):
            for item in queries:
                if isinstance(item, Mapping):
                    return item
        return {}

    def _dns_attributes(self, record: Mapping[str, Any]) -> dict[str, Any]:
        attributes = self._common_attributes(record)
        dns = mapping(record.get("dns"))
        query = self._first_dns_query(dns)

        dns_type = text(dns.get("type"), limit=32)
        add_if_present(attributes, "dns_type", dns_type)
        add_if_present(
            attributes,
            "dns_version",
            integer(dns.get("version"), minimum=1),
        )
        add_if_present(attributes, "dns_id", integer(dns.get("id")))
        add_if_present(
            attributes,
            "dns_rcode",
            text(dns.get("rcode"), limit=64),
        )

        # Suricata 8+ DNS v3 places requests in queries[]. Version 2 uses
        # top-level rrname/rrtype. Preserve both without inventing a value.
        dns_query = (
            text(query.get("rrname"), limit=1024)
            or text(dns.get("rrname"), limit=1024)
        )
        dns_qtype = (
            text(query.get("rrtype"), limit=64)
            or text(dns.get("rrtype"), limit=64)
        )
        add_if_present(attributes, "dns_query", dns_query)
        add_if_present(attributes, "dns_qtype", dns_qtype)

        answers = dns.get("answers")
        if isinstance(answers, Sequence) and not isinstance(
            answers,
            (str, bytes, bytearray),
        ):
            attributes["dns_answer_count"] = sum(
                1 for item in answers if isinstance(item, Mapping)
            )
        return attributes

    def _http_attributes(self, record: Mapping[str, Any]) -> dict[str, Any]:
        attributes = self._common_attributes(record)
        http = mapping(record.get("http"))
        add_if_present(
            attributes,
            "http_method",
            text(http.get("http_method"), limit=32),
        )
        add_if_present(
            attributes,
            "http_host",
            text(http.get("hostname"), limit=512),
        )
        add_if_present(
            attributes,
            "http_uri",
            text(http.get("url"), limit=2048),
        )
        add_if_present(
            attributes,
            "http_status",
            integer(http.get("status"), maximum=999),
        )
        add_if_present(
            attributes,
            "http_user_agent",
            text(http.get("http_user_agent"), limit=512),
        )
        add_if_present(
            attributes,
            "http_content_type",
            text(http.get("http_content_type"), limit=256),
        )
        add_if_present(
            attributes,
            "http_response_length",
            integer(http.get("length")),
        )
        add_if_present(
            attributes,
            "http_protocol",
            text(http.get("protocol"), limit=64),
        )
        return attributes

    def _tls_attributes(self, record: Mapping[str, Any]) -> dict[str, Any]:
        attributes = self._common_attributes(record)
        tls = mapping(record.get("tls"))
        add_if_present(
            attributes,
            "tls_server_name",
            text(tls.get("sni"), limit=512),
        )
        add_if_present(
            attributes,
            "tls_version",
            text(tls.get("version"), limit=64),
        )
        add_if_present(
            attributes,
            "tls_subject",
            text(tls.get("subject"), limit=512),
        )
        add_if_present(
            attributes,
            "tls_issuer",
            (
                text(tls.get("issuerdn"), limit=512)
                or text(tls.get("issuer"), limit=512)
            ),
        )
        add_if_present(
            attributes,
            "tls_session_resumed",
            bool_value(tls.get("session_resumed")),
        )
        add_if_present(
            attributes,
            "tls_fingerprint_sha1",
            text(tls.get("fingerprint"), limit=256),
        )
        ja3 = mapping(tls.get("ja3"))
        ja3s = mapping(tls.get("ja3s"))
        add_if_present(
            attributes,
            "tls_ja3_hash",
            text(ja3.get("hash"), limit=128),
        )
        add_if_present(
            attributes,
            "tls_ja3s_hash",
            text(ja3s.get("hash"), limit=128),
        )
        ja4 = tls.get("ja4")
        if isinstance(ja4, str):
            add_if_present(attributes, "tls_ja4", text(ja4, limit=256))
        elif isinstance(ja4, Mapping):
            add_if_present(
                attributes,
                "tls_ja4",
                text(ja4.get("hash"), limit=256),
            )
        return attributes

    def normalize(self, record: Mapping[str, Any]) -> SecurityEvent:
        if not isinstance(record, Mapping):
            raise SensorNormalizationError("Suricata EVE record must be a JSON object")
        event_type = text(record.get("event_type"), limit=64)
        if event_type is None:
            raise SensorNormalizationError("Suricata event_type is required")
        event_type = event_type.casefold()
        if event_type not in _SUPPORTED_EVENT_TYPES:
            raise SensorNormalizationError(
                f"unsupported Suricata EVE event_type: {event_type}"
            )

        observed_at = parse_iso_timestamp(
            record.get("timestamp"),
            field_name="Suricata timestamp",
        )
        event_id = deterministic_event_id(
            engine="suricata",
            tenant_id=self.tenant_id,
            site_id=self.site_id,
            sensor_id=self.sensor_id,
            record_type=event_type,
            record=record,
        )
        src_ip = ip(
            record.get("src_ip"),
            field_name="Suricata source address",
        )
        dst_ip = ip(
            record.get("dest_ip"),
            field_name="Suricata destination address",
        )
        protocol = text(record.get("proto"), limit=32)
        flow_id = integer(record.get("flow_id"))
        raw_reference = (
            f"suricata:{event_type}:flow:{flow_id}"
            if flow_id is not None
            else f"suricata:{event_type}:{event_id}"
        )

        if event_type == "alert":
            category = "suricata.alert"
            attributes = self._alert_attributes(record)
            alert = mapping(record.get("alert"))
            signature = text(alert.get("signature"), limit=300)
            summary = (
                f"Suricata IDS signature match: {signature}"
                if signature
                else "Suricata IDS alert"
            )
            evidence_class = EvidenceClass.IDS_ALERT
            confidence = 0.98
        elif event_type == "flow":
            category = "network.connection"
            attributes = self._flow_attributes(record)
            summary = "Suricata bidirectional flow telemetry"
            evidence_class = EvidenceClass.NETWORK_FLOW
            confidence = 0.95
        elif event_type == "dns":
            attributes = self._dns_attributes(record)
            dns_type = str(attributes.get("dns_type") or "").casefold()
            if dns_type in {"request", "query"}:
                category = "dns.query"
            elif dns_type in {"response", "answer"}:
                category = "dns.response"
            else:
                category = "dns.transaction"
            query = attributes.get("dns_query")
            summary = (
                f"Suricata DNS telemetry for {query}"
                if query
                else "Suricata DNS transaction telemetry"
            )
            evidence_class = EvidenceClass.NETWORK_FLOW
            confidence = 0.95
        elif event_type == "http":
            category = "http.transaction"
            attributes = self._http_attributes(record)
            summary = "Suricata HTTP transaction telemetry"
            evidence_class = EvidenceClass.NETWORK_FLOW
            confidence = 0.95
        else:
            category = "tls.handshake"
            attributes = self._tls_attributes(record)
            summary = "Suricata TLS session telemetry"
            evidence_class = EvidenceClass.NETWORK_FLOW
            confidence = 0.95

        return SecurityEvent(
            event_id=event_id,
            tenant_id=self.tenant_id,
            site_id=self.site_id,
            sensor_id=self.sensor_id,
            observed_at=observed_at,
            category=category,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            attributes=attributes,
            evidence=[
                evidence(
                    event_id=event_id,
                    evidence_class=evidence_class,
                    source=f"suricata:{event_type}",
                    summary=summary,
                    confidence=confidence,
                    observed_at=observed_at,
                    raw_reference=raw_reference,
                )
            ],
        )
