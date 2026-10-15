"""Read-only SNMPv3 managed-switch inventory polling.

Reads narrowly scoped LLDP / BRIDGE-MIB / IF-MIB OIDs. Never sends SET,
never probes hosts, never assumes a default bridge FDB covers all VLANs.
Only permit explicit authorized literal management addresses.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
from collections.abc import Awaitable, Callable
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mon.topology_inventory import (
    LearnedMac,
    LldpNeighbor,
    SwitchInventory,
    SwitchPort,
)
from mon.topology_inventory_cli import _read_bearer

# Numeric OIDs are intentional: poll only documented read-only MIB columns.
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
BRIDGE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
BRIDGE_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
LLDP_LOCAL_PORT_DESC = "1.0.8802.1.1.2.1.3.7.1.4"
LLDP_REMOTE_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"
OIDS = (
    IF_NAME, BRIDGE_PORT_IFINDEX, BRIDGE_FDB_PORT,
    LLDP_LOCAL_PORT_DESC, LLDP_REMOTE_SYSNAME,
)
MAX_ROWS = 8192


class SnmpV3SwitchConfig(BaseModel):
    """An explicit, approved management endpoint; passwords loaded from mode-0600 file."""

    model_config = ConfigDict(extra="forbid")
    switch_id: str = Field(min_length=1, max_length=256)
    address: str = Field(min_length=1, max_length=45)
    port: int = Field(default=161, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=64)
    auth_passphrase: str = Field(min_length=8)
    priv_passphrase: str = Field(min_length=8)
    ttl_seconds: int = Field(default=120, ge=30, le=3600)

    @model_validator(mode="after")
    def private_management_host(self) -> "SnmpV3SwitchConfig":
        try:
            address = ipaddress.ip_address(self.address)
        except ValueError as exc:
            raise ValueError("management address must be an explicit IP literal") from exc
        if (
            not address.is_private or address.is_loopback or address.is_link_local
            or address.is_multicast or address.is_unspecified or address.is_reserved
        ):
            raise ValueError("management address must be an approved private unicast IP")
        return self


def load_switch_config(path: Path) -> SnmpV3SwitchConfig:
    # Reuse mode-0600 regular-file permissions check, not the token's format.
    # A single-line JSON object avoids accidental multiline diagnostic logging.
    return SnmpV3SwitchConfig.model_validate_json(_read_bearer(path))


def _tail(oid: str, base: str) -> tuple[int, ...] | None:
    if not oid.startswith(base + "."):
        return None
    parts = oid[len(base) + 1:].split(".")
    try:
        return tuple(int(part) for part in parts)
    except ValueError:
        return None


def _indexed(rows: list[tuple[str, str]], prefix: str) -> dict[tuple[int, ...], str]:
    result: dict[tuple[int, ...], str] = {}
    for oid, val in rows:
        idx = _tail(oid, prefix)
        if idx is not None and len(result) < MAX_ROWS:
            result[idx] = val
    return result


def normalize_switch_mib(
    switch_id: str,
    tables: dict[str, list[tuple[str, str]]],
    *,
    at: dt.datetime,
    ttl_seconds: int = 120,
) -> SwitchInventory:
    """Build safe switch inventory only from explicit SNMP MIB observations.

    The standard BRIDGE-MIB FDB is not per-VLAN. VLAN remains unknown.
    Missing IF-MIB port mappings are skipped rather than guessed.
    LLDP sysName is a peer-asserted label, not a trusted identity.
    """
    if_names = _indexed(tables.get(IF_NAME, []), IF_NAME)
    bridge_indices = _indexed(tables.get(BRIDGE_PORT_IFINDEX, []), BRIDGE_PORT_IFINDEX)
    learned = _indexed(tables.get(BRIDGE_FDB_PORT, []), BRIDGE_FDB_PORT)
    local_ports = _indexed(tables.get(LLDP_LOCAL_PORT_DESC, []), LLDP_LOCAL_PORT_DESC)
    remote_names = _indexed(tables.get(LLDP_REMOTE_SYSNAME, []), LLDP_REMOTE_SYSNAME)

    by_name: dict[str, set[str]] = {}
    for mac_index, bridge_port in learned.items():
        if len(mac_index) != 6 or any(not 0 <= x <= 255 for x in mac_index):
            continue
        if not bridge_port.isdecimal() or not 0 < int(bridge_port) <= 4096:
            continue
        if_index = bridge_indices.get((int(bridge_port),))
        if if_index is None or not if_index.isdecimal():
            continue
        port_name = if_names.get((int(if_index),))
        if not port_name or len(port_name) > 128:
            continue
        octets = bytes(mac_index)
        if octets[0] & 1 or all(x == 0 for x in octets):
            continue
        mac = ":".join(f"{byte:02x}" for byte in octets)
        by_name.setdefault(port_name, set()).add(mac)

    lldp: list[LldpNeighbor] = []
    for index, remote in sorted(remote_names.items()):
        # lldpRemEntry indexes are timemark, local port number, remote index
        if len(index) != 3 or not 1 <= index[1] <= 4096:
            continue
        if not remote or len(remote) > 200 or not remote.isprintable():
            continue
        local_port = local_ports.get((index[1],))
        if not local_port or not local_port.isprintable() or len(local_port) > 128:
            local_port = f"lldp-local-port-{index[1]}"
        # Keep the remote name explicitly unverified; never silently merge with
        # an authenticated switch inventory record or enforcement identity.
        remote_id = f"lldp-unverified:{remote}"
        lldp.append(
            LldpNeighbor(local_port=local_port, remote_node_id=remote_id)
        )
    return SwitchInventory(
        switch_id=switch_id,
        collected_at=at,
        ttl_seconds=ttl_seconds,
        ports=[
            SwitchPort(
                name=name,
                learned_macs=[LearnedMac(mac=mac, vlan=None) for mac in sorted(macs)],
            )
            for name, macs in sorted(by_name.items())
        ],
        lldp_neighbors=lldp,
    )


async def _walk_with_pysnmp(config: SnmpV3SwitchConfig, oid: str) -> list[tuple[str, str]]:
    """Optional PySNMP 7.1 asyncio backend; SHA-256 auth and AES128 privacy."""
    try:
        from pysnmp.hlapi.v3arch.asyncio import (
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            UsmUserData,
            USM_AUTH_HMAC192_SHA256,
            USM_PRIV_CFB128_AES,
            bulk_walk_cmd,
        )
    except ImportError as exc:
        raise RuntimeError("install MON with optional [switch] dependencies") from exc

    engine = SnmpEngine()
    try:
        identity = UsmUserData(
            config.username,
            authKey=config.auth_passphrase,
            privKey=config.priv_passphrase,
            authProtocol=USM_AUTH_HMAC192_SHA256,
            privProtocol=USM_PRIV_CFB128_AES,
        )
        target = await UdpTransportTarget.create(
            (config.address, config.port), timeout=1.5, retries=1,
        )
        result: list[tuple[str, str]] = []
        async for error, status, _, binds in bulk_walk_cmd(
            engine, identity, target, ContextData(), 0, 20,
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
            lookupMib=False,
            maxRows=MAX_ROWS,
            maxCalls=512,
        ):
            if error or status:
                raise RuntimeError("SNMPv3 read-only query failed")
            for name, value in binds:
                key = name.prettyPrint().lstrip(".")
                if _tail(key, oid) is None:
                    continue
                result.append((key, value.prettyPrint()))
                if len(result) > MAX_ROWS:
                    raise RuntimeError("SNMPv3 response exceeded bounded MIB rows")
        return result
    finally:
        engine.close_dispatcher()


async def poll_switch(
    config: SnmpV3SwitchConfig,
    *,
    walk: Callable[[SnmpV3SwitchConfig, str], Awaitable[list[tuple[str, str]]]] = (
        _walk_with_pysnmp
    ),
    at: dt.datetime | None = None,
) -> SwitchInventory:
    """Read switch tables serially, fail closed on any missing/failed walk."""
    tables: dict[str, list[tuple[str, str]]] = {}
    for oid in OIDS:
        tables[oid] = await asyncio.wait_for(walk(config, oid), timeout=15.0)
    return normalize_switch_mib(
        config.switch_id, tables,
        at=at or dt.datetime.now(dt.UTC), ttl_seconds=config.ttl_seconds,
    )
