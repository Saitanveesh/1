from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "lab_three_hub.py"
PUBLIC_A = "A" * 43 + "="
PUBLIC_B = "B" * 43 + "="
PUBLIC_C = "C" * 43 + "="


def load():
    spec = importlib.util.spec_from_file_location("lab_three_hub", SCRIPT)
    assert spec and spec.loader
    instance = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = instance
    spec.loader.exec_module(instance)
    return instance


def test_guard_scopes_forwarding_and_blocks_attacker_from_hub() -> None:
    hub = load()
    commands = hub.guard_script()
    assert "add table inet mon_three_guard" in commands
    assert 'iifname "wg0" ip saddr 10.77.0.60 drop' in commands
    assert 'iifname "wg0" oifname != "wg0" drop' in commands
    assert 'oifname "wg0" iifname != "wg0" drop' in commands
    assert "ip daddr != 10.77.0.50 drop" in commands
    assert "ip daddr != 10.77.0.60 drop" in commands
    assert "flush ruleset" not in commands
    assert "flush table" not in commands
    assert "policy drop" not in commands


def test_rendered_hub_config_is_only_specific_overlay_and_two_peers() -> None:
    hub = load()
    config = hub.rendered_config(PUBLIC_A, PUBLIC_B, PUBLIC_C)
    assert config.startswith(hub.MARKER)
    assert "10.77.0.1/24" in config
    assert "ListenPort = 51820" in config
    assert "PrivateKey = " + PUBLIC_A in config
    assert "PublicKey = " + PUBLIC_B in config
    assert "PublicKey = " + PUBLIC_C in config
    assert "AllowedIPs = 10.77.0.50/32" in config
    assert "AllowedIPs = 10.77.0.60/32" in config
    assert "AllowedIPs = 0.0.0.0/0" not in config
    assert "10.5.112." not in config


def test_prepare_rejects_wrong_peers_before_any_root_mutations(monkeypatch) -> None:
    hub = load()

    def reject_commands(*args, **kwargs):
        raise AssertionError("did not reject before any mutations")

    monkeypatch.setattr(hub, "checked", reject_commands)
    monkeypatch.setattr(hub, "require_root", lambda: None)

    class Args:
        hub_public_key = PUBLIC_A
        victim_public_key = PUBLIC_A
        attacker_public_key = PUBLIC_C

    with pytest.raises(hub.HubSafetyError, match="unique"):
        hub.prepare(Args())


def test_management_route_qualification_fails_on_wrong_network(monkeypatch) -> None:
    hub = load()
    monkeypatch.setattr(
        hub, "checked", lambda *_: "10.5.112.23 dev enp128s31f6 src 10.5.112.94"
    )
    with pytest.raises(hub.HubSafetyError, match="unexpected"):
        hub.check_management_routes(("192.168.1.1",))
    with pytest.raises(hub.HubSafetyError, match="unexpected"):
        hub.check_management_routes(("100.75.116.62",))


def test_management_route_refuses_tunnel_for_ssh(monkeypatch) -> None:
    hub = load()
    monkeypatch.setattr(
        hub, "checked", lambda *_: "10.5.112.23 dev wg0 src 10.77.0.1"
    )
    with pytest.raises(hub.HubSafetyError, match="may not use wg0"):
        hub.check_management_routes(("10.5.112.23",))


def test_hub_without_root_cannot_start_or_rollback(monkeypatch) -> None:
    hub = load()
    monkeypatch.setattr(hub.os, "geteuid", lambda: 1000)
    with pytest.raises(hub.HubSafetyError, match="root required"):
        hub.require_root()
    with pytest.raises(hub.HubSafetyError, match="root required"):
        hub.rollback()


def test_checked_does_not_use_shell_and_fails_closed(monkeypatch) -> None:
    hub = load()
    called = []

    def fake_run(args, **kwargs):
        called.append((args, kwargs))
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr(hub.subprocess, "run", fake_run)
    with pytest.raises(subprocess.CalledProcessError):
        hub.checked("wg", "show", "wg0", "listen-port")
    args, kwargs = called[0]
    assert args == ("wg", "show", "wg0", "listen-port")
    assert kwargs["check"] is True
    assert kwargs["capture_output"] is True
    assert "shell" not in kwargs


def test_no_in_use_hub_rollback_if_peer_has_handshaken(monkeypatch) -> None:
    hub = load()
    monkeypatch.setattr(hub, "require_root", lambda: None)
    monkeypatch.setattr(hub, "assert_prepared", lambda: None)
    commands = []

    def fake_checked(*cmd: str, **kwargs):
        commands.append(cmd)
        if cmd == ("wg", "show", "wg0", "latest-handshakes"):
            return PUBLIC_B + " 1791617876\n" + PUBLIC_C + " 0"
        raise AssertionError("rollback must stop before changing services or firewall")

    monkeypatch.setattr(hub, "checked", fake_checked)
    with pytest.raises(hub.HubSafetyError, match="in-use"):
        hub.rollback()
    assert commands == [("wg", "show", "wg0", "latest-handshakes")]


def test_rollback_order_stops_hub_before_removing_its_guard(monkeypatch) -> None:
    hub = load()
    monkeypatch.setattr(hub, "require_root", lambda: None)
    monkeypatch.setattr(hub, "assert_prepared", lambda: None)
    commands = []

    def fake_checked(*cmd: str, **kwargs):
        commands.append(cmd)
        if cmd == ("wg", "show", "wg0", "latest-handshakes"):
            return PUBLIC_B + " 0\n" + PUBLIC_C + " 0"
        return ""

    class FakeConf:
        def unlink(self):
            commands.append(("delete", "mon-owned-config"))

    monkeypatch.setattr(hub, "checked", fake_checked)
    monkeypatch.setattr(hub, "is_active", lambda: False)
    monkeypatch.setattr(hub, "WG_CONF", FakeConf())
    hub.rollback()
    assert commands.index(("systemctl", "disable", "--now", "wg-quick@wg0")) \
        < commands.index(("delete", "mon-owned-config")) \
        < commands.index(("nft", "delete", "table", "inet", "mon_three_guard"))



def test_volatile_firewall_guard_precedes_manual_hub_start_only() -> None:
    """Never enable auto-start if nft guard has no guard-first boot persistence."""
    import inspect

    hub = load()
    source = inspect.getsource(hub.prepare)
    assert source.index('checked("nft", "-f", str(guard_staging))') \
        < source.index('checked("systemctl", "start", "wg-quick@wg0")')
    assert 'checked("systemctl", "enable"' not in source
    check_source = inspect.getsource(hub.assert_prepared)
    assert '"is-enabled", "wg-quick@wg0"' in check_source
