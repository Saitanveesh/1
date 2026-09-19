from __future__ import annotations

from collections.abc import Mapping
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
    parse_epoch_timestamp,
    port,
    text,
)

_SUPPORTED_LOGS = {
    "conn",
    "dns",
    "http",
    "ssl",
    "notice",
    "weird",
}


class ZeekJsonNormalizer:
    """Normalize selected Zeek JSON logs without inventing missing telemetry."""

    def __init__(self, tenant_id: str, site_id: str, sensor_id: str) -> None:
        if not tenant_id or not site_id or not sensor_id:
            raise ValueError("tenant_id, site_id and sensor_id are required")
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.sensor_id = sensor_id

    @staticmethod
    def _field(record: Mapping[str, Any], name: str) -> object:
        if name in record:
            return record[name]
        if "." not in name:
            return None
        head, tail = name.split(".", 1)
        nested = mapping(record.get(head))
        return nested.get(tail)

    @staticmethod
    def _endpoint_attributes(record: Mapping[str, Any]) -> dict[str, Any]:
        attributes: dict[str, Any] = {}
        add_if_present(
            attributes,
            "src_port",
            port(ZeekJsonNormalizer._field(record, "id.orig_p")),
        )
        add_if_present(
            attributes,
            "dst_port",
            port(ZeekJsonNormalizer._field(record, "id.resp_p")),
        )
        add_if_present(attributes, "community_id", text(record.get("community_id")))
        return attributes

    def _conn_attributes(self, record: Mapping[str, Any]) -> dict[str, Any]:
        attributes = self._endpoint_attributes(record)
        add_if_present(attributes, "uid", text(record.get("uid"), limit=256))
        add_if_present(attributes, "service", text(record.get("service"), limit=128))
        add_if_present(
            attributes,
            "conn_state",
            text(record.get("conn_state"), limit=32),
        )
        add_if_present(
            attributes,
            "duration_seconds",
            floating(record.get("duration")),
        )
        add_if_present(
            attributes,
            "local_orig",
            bool_value(record.get("local_orig")),
        )
        add_if_present(
            attributes,
            "local_resp",
            bool_value(record.get("local_resp")),
        )
        add_if_present(
            attributes,
            "missed_bytes",
            integer(record.get("missed_bytes")),
        )

        orig_pkts = integer(record.get("orig_pkts"))
        resp_pkts = integer(record.get("resp_pkts"))
        orig_ip_bytes = integer(record.get("orig_ip_bytes"))
        resp_ip_bytes = integer(record.get("resp_ip_bytes"))
        add_if_present(attributes, "orig_packets", orig_pkts)
        add_if_present(attributes, "resp_packets", resp_pkts)
        add_if_present(attributes, "orig_ip_bytes", orig_ip_bytes)
        add_if_present(attributes, "resp_ip_bytes", resp_ip_bytes)
        add_if_present(
            attributes,
            "packets",
            complete_sum(orig_pkts, resp_pkts),
        )
        add_if_present(
            attributes,
            "bytes",
            complete_sum(orig_ip_bytes, resp_ip_bytes),
        )

        history = text(record.get("history"), limit=256)
        add_if_present(attributes, "zeek_history", history)
        protocol = text(record.get("proto"), limit=32)
        if protocol and protocol.casefold() == "tcp" and history is not None:
            # Zeek history uses upper-case letters for originator events:
            # S = SYN without ACK, A = pure ACK.
            attributes["tcp_syn"] = "S" in history
            attributes["tcp_ack"] = "A" in history
        return attributes

    def _dns_attributes(self, record: Mapping[str, Any]) -> dict[str, Any]:
        attributes = self._endpoint_attributes(record)
        add_if_present(attributes, "uid", text(record.get("uid"), limit=256))
        add_if_present(
            attributes,
            "dns_query",
            text(record.get("query"), limit=1024),
        )
        add_if_present(
            attributes,
            "dns_qtype",
            text(record.get("qtype_name"), limit=64),
        )
        add_if_present(
            attributes,
            "dns_rcode",
            text(record.get("rcode_name"), limit=64),
        )
        add_if_present(
            attributes,
            "dns_rejected",
            bool_value(record.get("rejected")),
        )
        return attributes

    def _http_attributes(self, record: Mapping[str, Any]) -> dict[str, Any]:
        attributes = self._endpoint_attributes(record)
        add_if_present(attributes, "uid", text(record.get("uid"), limit=256))
        add_if_present(
            attributes,
            "http_method",
            text(record.get("method"), limit=32),
        )
        add_if_present(
            attributes,
            "http_host",
            text(record.get("host"), limit=512),
        )
        add_if_present(
            attributes,
            "http_uri",
            text(record.get("uri"), limit=2048),
        )
        add_if_present(
            attributes,
            "http_status",
            integer(record.get("status_code"), maximum=999),
        )
        add_if_present(
            attributes,
            "http_user_agent",
            text(record.get("user_agent"), limit=512),
        )
        add_if_present(
            attributes,
            "transaction_depth",
            integer(record.get("trans_depth")),
        )
        return attributes

    def _ssl_attributes(self, record: Mapping[str, Any]) -> dict[str, Any]:
        attributes = self._endpoint_attributes(record)
        add_if_present(attributes, "uid", text(record.get("uid"), limit=256))
        add_if_present(
            attributes,
            "tls_server_name",
            text(record.get("server_name"), limit=512),
        )
        add_if_present(
            attributes,
            "tls_version",
            text(record.get("version"), limit=64),
        )
        add_if_present(
            attributes,
            "tls_cipher",
            text(record.get("cipher"), limit=256),
        )
        add_if_present(
            attributes,
            "tls_established",
            bool_value(record.get("established")),
        )
        add_if_present(
            attributes,
            "tls_resumed",
            bool_value(record.get("resumed")),
        )
        add_if_present(
            attributes,
            "tls_subject",
            text(record.get("subject"), limit=512),
        )
        add_if_present(
            attributes,
            "tls_issuer",
            text(record.get("issuer"), limit=512),
        )
        return attributes

    @staticmethod
    def _notice_attributes(record: Mapping[str, Any]) -> dict[str, Any]:
        attributes: dict[str, Any] = {}
        add_if_present(attributes, "uid", text(record.get("uid"), limit=256))
        add_if_present(
            attributes,
            "notice_type",
            text(record.get("note"), limit=256),
        )
        add_if_present(
            attributes,
            "notice_message",
            text(record.get("msg"), limit=1000),
        )
        add_if_present(
            attributes,
            "notice_sub",
            text(record.get("sub"), limit=512),
        )
        return attributes

    @staticmethod
    def _weird_attributes(record: Mapping[str, Any]) -> dict[str, Any]:
        attributes: dict[str, Any] = {}
        add_if_present(attributes, "uid", text(record.get("uid"), limit=256))
        add_if_present(
            attributes,
            "weird_name",
            text(record.get("name"), limit=256),
        )
        add_if_present(
            attributes,
            "weird_additional",
            text(record.get("addl"), limit=512),
        )
        add_if_present(
            attributes,
            "weird_notice",
            bool_value(record.get("notice")),
        )
        return attributes

    def normalize(
        self,
        log_type: str,
        record: Mapping[str, Any],
    ) -> SecurityEvent:
        normalized_type = log_type.strip().casefold()
        if normalized_type.endswith(".log"):
            normalized_type = normalized_type[:-4]
        if normalized_type not in _SUPPORTED_LOGS:
            raise SensorNormalizationError(
                f"unsupported Zeek JSON log type: {log_type}"
            )
        if not isinstance(record, Mapping):
            raise SensorNormalizationError("Zeek record must be a JSON object")

        observed_at = parse_epoch_timestamp(
            record.get("ts"),
            field_name="Zeek ts",
        )
        event_id = deterministic_event_id(
            engine="zeek",
            tenant_id=self.tenant_id,
            site_id=self.site_id,
            sensor_id=self.sensor_id,
            record_type=normalized_type,
            record=record,
        )

        src_ip = ip(
            self._field(record, "id.orig_h"),
            field_name="Zeek originator address",
        )
        dst_ip = ip(
            self._field(record, "id.resp_h"),
            field_name="Zeek responder address",
        )
        if normalized_type == "notice":
            src_ip = src_ip or ip(
                record.get("src"),
                field_name="Zeek notice source address",
            )
            dst_ip = dst_ip or ip(
                record.get("dst"),
                field_name="Zeek notice destination address",
            )

        protocol = text(record.get("proto"), limit=32)
        uid = text(record.get("uid"), limit=256)
        raw_reference = (
            f"zeek:{normalized_type}:{uid}"
            if uid
            else f"zeek:{normalized_type}:{event_id}"
        )

        if normalized_type == "conn":
            category = "network.connection"
            attributes = self._conn_attributes(record)
            summary = (
                f"Zeek connection metadata for UID {uid}"
                if uid
                else "Zeek connection metadata"
            )
        elif normalized_type == "dns":
            category = "dns.query"
            attributes = self._dns_attributes(record)
            query = attributes.get("dns_query")
            summary = (
                f"Zeek DNS metadata for query {query}"
                if query
                else "Zeek DNS transaction metadata"
            )
        elif normalized_type == "http":
            category = "http.transaction"
            attributes = self._http_attributes(record)
            summary = "Zeek HTTP transaction metadata"
        elif normalized_type == "ssl":
            category = "tls.handshake"
            attributes = self._ssl_attributes(record)
            summary = "Zeek TLS session metadata"
        elif normalized_type == "notice":
            category = "zeek.notice"
            attributes = self._notice_attributes(record)
            summary = "Zeek notice telemetry"
        else:
            category = "zeek.weird"
            attributes = self._weird_attributes(record)
            summary = "Zeek protocol-anomaly telemetry"

        source = f"zeek:{normalized_type}"
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
                    evidence_class=EvidenceClass.NETWORK_FLOW,
                    source=source,
                    summary=summary,
                    confidence=0.95,
                    observed_at=observed_at,
                    raw_reference=raw_reference,
                )
            ],
        )
