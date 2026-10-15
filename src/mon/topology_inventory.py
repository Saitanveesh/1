"""Read-only adapters for observed neighbor and managed-switch inventory.

Input is evidence, not an instruction to scan, exploit or reconfigure a network.
No Lab-A/B assumptions and no physical location is synthesized.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mon.topology import TopologyKind, TopologyLayer, TopologyObservation, TopologyRelationship

_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")


def _mac(value: str) -> str:
    if not _MAC_RE.fullmatch(value):
        raise ValueError("invalid MAC address")
    normalized = value.lower()
    first = int(normalized[:2], 16)
    if (first & 1) or normalized == "00:00:00:00:00:00":
        raise ValueError("multicast, broadcast or zero MAC is not an endpoint")
    return normalized


def _identifier(kind: str, *parts: object) -> str:
    data = json.dumps([kind, *parts], separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class LearnedMac(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mac: str
    vlan: int | None = Field(default=None, ge=1, le=4094)

    @field_validator("mac")
    @classmethod
    def valid_mac(cls, value: str) -> str:
        return _mac(value)


class SwitchPort(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=128)
    learned_macs: list[LearnedMac] = Field(default_factory=list, max_length=1024)


class LldpNeighbor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    local_port: str = Field(min_length=1, max_length=128)
    remote_node_id: str = Field(min_length=1, max_length=256)
    remote_port: str | None = Field(default=None, max_length=128)


class SwitchInventory(BaseModel):
    """Explicit normalized export from an authorized read-only switch source.

    This is NOT raw vendor SNMP output. Every populated field must originate
    from the queried device; absence is represented as missing data.
    """

    model_config = ConfigDict(extra="forbid")
    switch_id: str = Field(min_length=1, max_length=256)
    collected_at: dt.datetime
    ttl_seconds: int = Field(default=120, ge=1, le=3600)
    display_name: str | None = Field(default=None, max_length=256)
    ports: list[SwitchPort] = Field(default_factory=list, max_length=4096)
    lldp_neighbors: list[LldpNeighbor] = Field(default_factory=list, max_length=4096)

    @model_validator(mode="after")
    def valid_timestamp(self) -> SwitchInventory:
        if self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValueError("collected_at must include timezone")
        return self


def switch_inventory_observations(
    inventory: SwitchInventory,
    *,
    tenant_id: str,
    site_id: str,
    sensor_id: str,
) -> list[TopologyObservation]:
    """Normalize actual FDB learning and LLDP observations with stable IDs.

    An FDB edge is never upgraded to a physical LLDP hop. MAC locations can
    move and may represent hypervisors, bridges or shared access points.
    """
    instant = inventory.collected_at.isoformat()
    common = {
        "tenant_id": tenant_id,
        "site_id": site_id,
        "sensor_id": sensor_id,
        "observed_at": inventory.collected_at,
        "ttl_seconds": inventory.ttl_seconds,
    }
    result: list[TopologyObservation] = []

    def add(kind: TopologyKind, node_id: str, *, discriminator: str, **attributes: object) -> None:
        unique = _identifier(
            "topology-switch", tenant_id, site_id, sensor_id,
            inventory.switch_id, instant, discriminator,
        )
        result.append(
            TopologyObservation(
                observation_id=unique,
                evidence_id=unique,
                kind=kind,
                node_id=node_id,
                **common,
                **attributes,
            )
        )

    add(
        TopologyKind.NODE, inventory.switch_id, discriminator="switch",
        node_type="SWITCH", display_name=inventory.display_name,
    )
    ports_seen: set[str] = set()
    mac_seen: set[tuple[str, str, int | None]] = set()
    for port in inventory.ports:
        if port.name in ports_seen:
            raise ValueError("duplicate switch port")
        ports_seen.add(port.name)
        for item in port.learned_macs:
            key = (port.name, item.mac, item.vlan)
            if key in mac_seen:
                continue
            mac_seen.add(key)
            node = f"mac:{item.mac}"
            add(
                TopologyKind.LINK, inventory.switch_id,
                discriminator=f"fdb:{port.name}:{item.mac}:{item.vlan}",
                node_type="SWITCH", interface_name=port.name,
                vlan_id=item.vlan, peer_node_id=node,
                relationship=TopologyRelationship.FDB_LEARNED,
                layer=TopologyLayer.L2, mac_address=item.mac,
            )
    neighbors_seen: set[tuple[str, str]] = set()
    for neighbor in inventory.lldp_neighbors:
        key = (neighbor.local_port, neighbor.remote_node_id)
        if key in neighbors_seen:
            continue
        neighbors_seen.add(key)
        add(
            TopologyKind.LINK, inventory.switch_id,
            discriminator=f"lldp:{neighbor.local_port}:{neighbor.remote_node_id}",
            node_type="SWITCH", interface_name=neighbor.local_port,
            peer_node_id=neighbor.remote_node_id,
            relationship=TopologyRelationship.LLDP_NEIGHBOR, layer=TopologyLayer.L2,
        )
    return result


def linux_neighbors_observations(
    raw: str,
    *,
    tenant_id: str,
    site_id: str,
    sensor_id: str,
    collected_at: dt.datetime,
    ttl_seconds: int = 60,
) -> list[TopologyObservation]:
    """Convert 'ip -j neigh show' output into weak, IP-scoped NODE evidence.

    Linux neighbor cache is NOT an asset census or proof of physical adjacency.
    STALE/INCOMPLETE entries are skipped because they do not prove current reachability.
    """
    if collected_at.tzinfo is None or collected_at.utcoffset() is None:
        raise ValueError("collected_at must include timezone")
    if not 1 <= ttl_seconds <= 3600:
        raise ValueError("ttl_seconds out of range")
    data = json.loads(raw)
    if not isinstance(data, list) or len(data) > 20000:
        raise ValueError("expected bounded iproute2 neighbor JSON array")
    observed: list[TopologyObservation] = []
    already: set[str] = set()
    for row in data:
        if not isinstance(row, dict):
            continue
        if str(row.get("state", "")).upper() != "REACHABLE":
            continue
        addr, device, mac = row.get("dst"), row.get("dev"), row.get("lladdr")
        if not all(isinstance(x, str) for x in (addr, device, mac)):
            continue
        if not device or len(device) > 128:
            continue
        try:
            ip = ipaddress.ip_address(addr)
            normalized_mac = _mac(mac)
        except ValueError:
            continue
        if ip.is_multicast or ip.is_unspecified or ip.is_loopback:
            continue
        # A neighbor entry might be virtual, proxied or spoofed. IP-scoped
        # identity avoids assigning a verified physical device or switch port.
        node_id = f"ip:{ip}"
        evidence = _identifier(
            "linux-neighbor", tenant_id, site_id, sensor_id,
            collected_at.isoformat(), device, str(ip), normalized_mac,
        )
        if evidence in already:
            continue
        already.add(evidence)
        observed.append(
            TopologyObservation(
                observation_id=evidence,
                evidence_id=evidence,
                tenant_id=tenant_id,
                site_id=site_id,
                sensor_id=sensor_id,
                observed_at=collected_at,
                ttl_seconds=ttl_seconds,
                kind=TopologyKind.NODE,
                node_id=node_id,
                node_type="UNVERIFIED_NEIGHBOR",
                display_name=str(ip),
                ip_address=str(ip),
                mac_address=normalized_mac,
                interface_name=device,
            )
        )
    return observed
