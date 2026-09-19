from __future__ import annotations

import ipaddress
import re
import threading
from collections.abc import Iterable

from mon.domain import Asset, SecurityEvent
from mon.store import PipelineStore

_MAC_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
_HOSTNAME_KEYS = (
    ("dhcp_hostname", "PASSIVE_DHCP_HOSTNAME"),
    ("mdns_name", "PASSIVE_MDNS_NAME"),
    ("llmnr_name", "PASSIVE_LLMNR_NAME"),
    ("nbns_name", "PASSIVE_NBNS_NAME"),
)


def _bounded_text(value: object, limit: int = 256) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(character for character in value.strip() if character.isprintable())
    if not cleaned:
        return None
    return cleaned[:limit]


def _normalize_mac(value: object) -> str | None:
    text = _bounded_text(value, 32)
    if text is None or not _MAC_PATTERN.match(text):
        return None
    normalized = text.replace("-", ":").lower()
    octets = [int(part, 16) for part in normalized.split(":")]
    if normalized in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        return None
    if octets[0] & 1:
        return None
    return normalized


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _positive_int(value: object, *, maximum: int | None = None) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    if result < 0 or (maximum is not None and result > maximum):
        return None
    return result


def _hostnames(event: SecurityEvent) -> tuple[set[str], set[str]]:
    names: set[str] = set()
    evidence: set[str] = set()
    for key, source in _HOSTNAME_KEYS:
        value = _bounded_text(event.attributes.get(key), 255)
        if value:
            names.add(value.rstrip("."))
            evidence.add(source)

    endpoint_name = _bounded_text(event.attributes.get("endpoint_hostname"), 255)
    if endpoint_name:
        names.add(endpoint_name.rstrip("."))
        evidence.add("ENDPOINT_REPORTED_HOSTNAME")
    return names, evidence


def _increment(mapping: dict[str, int], keys: Iterable[str]) -> dict[str, int]:
    updated = dict(mapping)
    for key in keys:
        updated[key] = updated.get(key, 0) + 1
    if len(updated) > 64:
        updated = dict(
            sorted(updated.items(), key=lambda item: (-item[1], item[0]))[:64]
        )
    return updated


class AssetEngine:
    """Resolve source observations into evidence-labelled assets.

    MAC-backed identities are preferred. IP-only assets are deliberately marked as
    weaker observations because DHCP/re-addressing can change ownership over time.
    """

    def __init__(self, store: PipelineStore) -> None:
        self.store = store
        self._lock = threading.RLock()

    @staticmethod
    def _identity(event: SecurityEvent) -> tuple[str, str] | None:
        if event.asset_id:
            return event.asset_id, "SENSOR_ASSERTED_ASSET_ID"

        source_mac = _normalize_mac(event.attributes.get("src_mac"))
        if source_mac:
            return f"mac:{source_mac}", "PASSIVE_SOURCE_MAC"

        source_ip = _valid_ip(event.src_ip)
        if source_ip:
            return f"ip:{source_ip}", "SOURCE_IP_OBSERVATION_ONLY"
        return None

    def observe(self, event: SecurityEvent) -> Asset | None:
        identity = self._identity(event)
        if identity is None:
            return None

        asset_id, identity_source = identity
        source_ip = _valid_ip(event.src_ip)
        source_mac = _normalize_mac(event.attributes.get("src_mac"))
        hostnames, hostname_evidence = _hostnames(event)
        vendor = _bounded_text(
            event.attributes.get("src_vendor") or event.attributes.get("mac_vendor"),
            256,
        )
        peer = _valid_ip(event.dst_ip)
        protocol = _bounded_text(event.protocol, 64)
        measured_packets = _positive_int(event.attributes.get("packets"))
        measured_bytes = _positive_int(event.attributes.get("bytes"))

        service: int | None = None
        if (
            protocol
            and protocol.casefold() == "tcp"
            and bool(event.attributes.get("tcp_syn"))
            and bool(event.attributes.get("tcp_ack"))
        ):
            service = _positive_int(event.attributes.get("src_port"), maximum=65535)
            if service == 0:
                service = None

        with self._lock:
            existing = self.store.get_asset(
                event.tenant_id,
                event.site_id,
                asset_id,
            )
            if existing is None:
                display_name = (
                    sorted(hostnames)[0]
                    if hostnames
                    else source_ip
                    or source_mac
                    or asset_id
                )
                asset = Asset(
                    asset_id=asset_id,
                    tenant_id=event.tenant_id,
                    site_id=event.site_id,
                    display_name=display_name,
                    ip_addresses={source_ip} if source_ip else set(),
                    mac_addresses={source_mac} if source_mac else set(),
                    hostnames=hostnames,
                    vendor=vendor,
                    observed_tcp_services={service} if service else set(),
                    peer_counts={peer: 1} if peer else {},
                    protocol_counts={protocol.casefold(): 1} if protocol else {},
                    identity_evidence={identity_source, *hostname_evidence},
                    measured_packets=measured_packets,
                    measured_bytes=measured_bytes,
                    first_seen=event.observed_at,
                    last_seen=event.observed_at,
                )
                return self.store.add_asset(asset)

            ip_addresses = set(existing.ip_addresses)
            mac_addresses = set(existing.mac_addresses)
            names = set(existing.hostnames)
            services = set(existing.observed_tcp_services)
            evidence = set(existing.identity_evidence)
            if source_ip:
                ip_addresses.add(source_ip)
            if source_mac:
                mac_addresses.add(source_mac)
            names.update(hostnames)
            if service:
                services.add(service)
            evidence.add(identity_source)
            evidence.update(hostname_evidence)

            display_name = existing.display_name
            weak_names = {asset_id, *existing.ip_addresses, *existing.mac_addresses}
            if names and display_name in weak_names:
                display_name = sorted(names)[0]

            packet_total = existing.measured_packets
            if measured_packets is not None:
                packet_total = (packet_total or 0) + measured_packets

            byte_total = existing.measured_bytes
            if measured_bytes is not None:
                byte_total = (byte_total or 0) + measured_bytes
            attributes = dict(existing.attributes)
            if hostnames and existing.hostnames and not hostnames <= existing.hostnames:
                attributes["hostname_conflict_observed"] = True
                attributes["hostname_conflict_values"] = sorted(
                    set(existing.hostnames) | hostnames
                )[:16]

            updated = existing.model_copy(
                update={
                    "display_name": display_name,
                    "ip_addresses": ip_addresses,
                    "mac_addresses": mac_addresses,
                    "hostnames": names,
                    "vendor": existing.vendor or vendor,
                    "observed_tcp_services": services,
                    "peer_counts": _increment(
                        existing.peer_counts,
                        [peer] if peer else [],
                    ),
                    "protocol_counts": _increment(
                        existing.protocol_counts,
                        [protocol.casefold()] if protocol else [],
                    ),
                    "identity_evidence": evidence,
                    "measured_packets": packet_total,
                    "measured_bytes": byte_total,
                    "first_seen": min(existing.first_seen, event.observed_at),
                    "last_seen": max(existing.last_seen, event.observed_at),
                    "attributes": attributes,
                }
            )
            return self.store.add_asset(updated)
