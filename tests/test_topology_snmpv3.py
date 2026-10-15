"""SNMPv3 read-only switch normalization and fail-closed tests."""
import asyncio
import datetime as dt
import json

import pytest
from pydantic import ValidationError

from mon.topology_inventory import switch_inventory_observations
from mon.topology_snmpv3 import (
    BRIDGE_FDB_PORT,
    BRIDGE_PORT_IFINDEX,
    IF_NAME,
    LLDP_LOCAL_PORT_DESC,
    LLDP_REMOTE_SYSNAME,
    OIDS,
    SnmpV3SwitchConfig,
    load_switch_config,
    normalize_switch_mib,
    poll_switch,
)

TIME = dt.datetime(2026, 10, 15, tzinfo=dt.UTC)


def config() -> SnmpV3SwitchConfig:
    return SnmpV3SwitchConfig(
        switch_id="managed-example", address="192.168.100.10",
        username="readonly-usm", auth_passphrase="test-auth-only",
        priv_passphrase="test-privacy-only",
    )


def sample_tables() -> dict[str, list[tuple[str, str]]]:
    return {
        IF_NAME: [(f"{IF_NAME}.101", "Gi1/0/1")],
        BRIDGE_PORT_IFINDEX: [(f"{BRIDGE_PORT_IFINDEX}.7", "101")],
        BRIDGE_FDB_PORT: [
            (f"{BRIDGE_FDB_PORT}.2.17.34.51.68.85", "7"),
            (f"{BRIDGE_FDB_PORT}.255.255.255.255.255.255", "7"),
            (f"{BRIDGE_FDB_PORT}.2.17.34.51.68.102", "55"),
        ],
        LLDP_LOCAL_PORT_DESC: [(f"{LLDP_LOCAL_PORT_DESC}.12", "Gi1/0/24")],
        LLDP_REMOTE_SYSNAME: [
            (f"{LLDP_REMOTE_SYSNAME}.2.12.1", "switch-upstream"),
        ],
    }


def test_snmp_normalizer_produces_real_fdb_and_lldp_evidence_only() -> None:
    snap = normalize_switch_mib("managed-example", sample_tables(), at=TIME)
    assert snap.switch_id == "managed-example"
    assert len(snap.ports) == 1
    assert snap.ports[0].name == "Gi1/0/1"
    assert snap.ports[0].learned_macs[0].mac == "02:11:22:33:44:55"
    assert snap.ports[0].learned_macs[0].vlan is None
    assert snap.lldp_neighbors[0].local_port == "Gi1/0/24"
    assert snap.lldp_neighbors[0].remote_node_id == "lldp-unverified:switch-upstream"
    records = switch_inventory_observations(
        snap, tenant_id="tenant", site_id="site", sensor_id="approved-switch",
    )
    assert len(records) == 4  # switch node, learned MAC node, FDB link, LLDP link
    assert len({o.observation_id for o in records}) == len(records)


def test_no_fake_port_or_neighbor_when_switch_tables_are_incomplete() -> None:
    tables = sample_tables()
    tables[BRIDGE_PORT_IFINDEX] = []
    tables[LLDP_LOCAL_PORT_DESC] = []
    snap = normalize_switch_mib("x", tables, at=TIME)
    assert not snap.ports
    assert snap.lldp_neighbors[0].local_port == "lldp-local-port-12"


def test_management_scope_rejects_public_loopback_dns_and_bad_auth() -> None:
    for address in ["8.8.8.8", "127.0.0.1", "169.254.10.1", "example.com"]:
        with pytest.raises(ValidationError):
            SnmpV3SwitchConfig.model_validate({
                **config().model_dump(), "address": address,
            })
    with pytest.raises(ValidationError):
        SnmpV3SwitchConfig(
            switch_id="x", address="192.168.0.1", username="u",
            auth_passphrase="bad", priv_passphrase="privacy-good",
        )


def test_load_auth_priv_config_from_mode_0600_file(tmp_path) -> None:
    path = tmp_path / "switch.json"
    path.write_text(json.dumps(config().model_dump()), encoding="utf-8")
    path.chmod(0o600)
    assert load_switch_config(path) == config()
    path.chmod(0o644)
    with pytest.raises(ValueError, match="group/other"):
        load_switch_config(path)


def test_async_snmp_poller_reads_only_bounded_configured_oids() -> None:
    requested = []
    async def fake_walk(cfg: SnmpV3SwitchConfig, oid: str) -> list[tuple[str, str]]:
        assert cfg == config()
        requested.append(oid)
        return sample_tables()[oid]
    found = asyncio.run(poll_switch(config(), walk=fake_walk, at=TIME))
    assert set(requested) == set(OIDS)
    assert found.switch_id == "managed-example"


def test_snmp_collection_fails_closed_if_one_read_fails() -> None:
    async def failing(cfg: SnmpV3SwitchConfig, oid: str) -> list[tuple[str, str]]:
        if oid == BRIDGE_FDB_PORT:
            raise TimeoutError("temporary switch timeout")
        return []
    with pytest.raises(TimeoutError):
        asyncio.run(poll_switch(config(), walk=failing, at=TIME))
