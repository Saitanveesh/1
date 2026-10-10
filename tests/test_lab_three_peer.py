from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "lab_three_peer.py"
OLD = "A" * 43 + "="
NEW = "B" * 43 + "="
PEER = "C" * 43 + "="


def load():
    spec = importlib.util.spec_from_file_location("mon_lab_three_peer", SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_only_known_peers_and_management_route_outside_wg(monkeypatch) -> None:
    mod = load()
    monkeypatch.setattr(mod.os, "geteuid", lambda: 1000)
    with pytest.raises(mod.PeerSafetyError, match="root"):
        mod.check_root("victim")
    with pytest.raises(mod.PeerSafetyError, match="root"):
        mod.check_root("attacker")
    assert mod.VALID_ROLES == {"victim": "10.77.0.50/32", "attacker": "10.77.0.60/32"}
    assert mod.NEW_HUB == "10.5.112.94:51820"
    assert mod.ORIGINAL_HUB == "10.5.115.5:51820"


def test_original_config_must_have_one_peer_correct_route() -> None:
    mod = load()
    correct = (
        "[Interface]\nPrivateKey = REDACTED\n"
        "[Peer]\nPublicKey = " + OLD + "\n"
        "AllowedIPs = 10.77.0.0/24\nEndpoint = 10.5.115.5:51820\n"
    )
    assert mod.config_peer(correct) == (OLD, mod.ORIGINAL_HUB)
    with pytest.raises(mod.PeerSafetyError, match="exactly one peer"):
        mod.config_peer(correct + "[Peer]\n")
    with pytest.raises(mod.PeerSafetyError, match="outside lab scope"):
        mod.config_peer(correct.replace("10.77.0.0/24", "0.0.0.0/0"))


def test_missing_verified_backup_refuses_early(tmp_path, monkeypatch) -> None:
    mod = load()
    config = tmp_path / "wg0.conf"
    config.write_text("ORIGINAL_PRIVATE_ONLY_IN_LOCAL_FILE")
    backups = tmp_path / "backups"
    backups.mkdir()
    monkeypatch.setattr(mod, "CONF", config)
    monkeypatch.setattr(mod, "BACKUPS", backups)
    with pytest.raises(mod.PeerSafetyError, match="no intact backup"):
        mod.original_config()


def test_backup_sha_and_contents_must_both_match(tmp_path, monkeypatch) -> None:
    import hashlib

    mod = load()
    data = "[Interface]\nPrivateKey = PRIVATE_NOT_SHOWN\n"
    conf = tmp_path / "wg0.conf"
    conf.write_text(data)
    backups = tmp_path / "backups"
    dir1 = backups / "precutover.verified"
    dir1.mkdir(parents=True)
    backup = dir1 / "wg0.conf"
    backup.write_text(data)
    backup.chmod(0o600)
    (dir1 / "wg0.sha256").write_text(
        hashlib.sha256(data.encode()).hexdigest() + "  " + str(backup) + "\n"
    )
    monkeypatch.setattr(mod, "CONF", conf)
    monkeypatch.setattr(mod, "BACKUPS", backups)
    located, actual = mod.original_config()
    assert located == backup and actual == data
    (dir1 / "wg0.sha256").write_text("0" * 64 + "  " + str(backup))
    with pytest.raises(mod.PeerSafetyError, match="no intact backup"):
        mod.original_config()
    assert "PRIVATE_NOT_SHOWN" not in str(locals().get("located"))


def test_start_schedules_rollback_before_modifying_live_peer(tmp_path, monkeypatch) -> None:
    mod = load()
    monkeypatch.setattr(mod, "locked", lambda: __import__("contextlib").nullcontext())
    monkeypatch.setattr(mod, "preflight", lambda role, pub: (tmp_path / "wg0.conf", OLD, ""))
    root = tmp_path / "cutover"
    root.mkdir(mode=0o700)
    (root / "runner.py").write_text("# trusted immutable script\n")
    (root / "runner.py").chmod(0o600)
    monkeypatch.setattr(mod, "BASE", root)
    monkeypatch.setattr(mod, "STATE", root / "state.json")
    monkeypatch.setattr(mod, "is_timer_running", lambda: True)
    seen = []

    def command(*args, **kw):
        seen.append(args)
        if args[:4] == ("wg", "show", "wg0", "peers"):
            return NEW
        return ""

    monkeypatch.setattr(mod, "call", command)
    mod.start("victim", NEW)
    assert (root / "state.json").is_file()
    assert json.loads((root / "state.json").read_text())["phase"] == "PENDING_ROLLBACK"
    timer_idx = next(i for i, x in enumerate(seen) if x[0] == "systemd-run")
    removal_idx = next(i for i, x in enumerate(seen) if x[:2] == ("wg", "set"))
    assert timer_idx < removal_idx
    assert "--on-active=900s" in seen[timer_idx]
    assert ("wg", "set", "wg0", "peer", OLD, "remove") in seen
    assert ("wg", "set", "wg0", "peer", NEW, "endpoint", mod.NEW_HUB,
            "allowed-ips", "10.77.0.0/24", "persistent-keepalive", "25") in seen


def test_start_cannot_change_interface_without_timer(tmp_path, monkeypatch) -> None:
    mod = load()
    monkeypatch.setattr(mod, "locked", lambda: __import__("contextlib").nullcontext())
    monkeypatch.setattr(mod, "preflight", lambda role, pub: (tmp_path / "wg0.conf", OLD, ""))
    root = tmp_path / "cutover"
    root.mkdir(mode=0o700)
    runner = root / "runner.py"
    runner.write_text("trusted")
    runner.chmod(0o600)
    monkeypatch.setattr(mod, "BASE", root)
    monkeypatch.setattr(mod, "STATE", root / "state.json")
    monkeypatch.setattr(mod, "is_timer_running", lambda: False)
    seen = []
    monkeypatch.setattr(mod, "call", lambda *args, **kw: seen.append(args) or "")
    with pytest.raises(mod.PeerSafetyError, match="rollback timer"):
        mod.start("victim", NEW)
    assert any(x[0] == "systemd-run" for x in seen)
    assert not any(x[:2] == ("wg", "set") for x in seen)


def test_commit_requires_fresh_handshake_and_live_rollback_timer(tmp_path, monkeypatch) -> None:
    mod = load()
    monkeypatch.setattr(mod, "check_root", lambda role: None)
    monkeypatch.setattr(mod, "locked", lambda: __import__("contextlib").nullcontext())
    root = tmp_path / "cutover"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(mod, "BASE", root)
    monkeypatch.setattr(mod, "STATE", root / "state.json")
    mod.save_state({
        "role": "victim", "phase": "PENDING_ROLLBACK",
        "expires_at_utc_epoch": int(time.time()) + 600,
    })
    monkeypatch.setattr(mod, "is_timer_running", lambda: False)
    with pytest.raises(mod.PeerSafetyError, match="timer expired"):
        mod.commit("victim")
    monkeypatch.setattr(mod, "is_timer_running", lambda: True)
    monkeypatch.setattr(
        mod, "check_live_target",
        lambda state: (_ for _ in ()).throw(mod.PeerSafetyError("no handshake"))
    )
    with pytest.raises(mod.PeerSafetyError, match="no handshake"):
        mod.commit("victim")


def test_rollback_never_replaces_persistent_config_if_drifted(tmp_path, monkeypatch) -> None:
    import hashlib

    mod = load()
    root = tmp_path / "cutover"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(mod, "BASE", root)
    monkeypatch.setattr(mod, "STATE", root / "state.json")
    backup = tmp_path / "backups" / "precutover.valid" / "wg0.conf"
    backup.parent.mkdir(parents=True)
    backup.write_text("ORIGINAL_PRIVATE_KEY")
    backup.chmod(0o600)
    backup.with_name("wg0.sha256").write_text(
        hashlib.sha256(backup.read_bytes()).hexdigest() + "  " + str(backup)
    )
    conf = tmp_path / "wg0.conf"
    conf.write_text("EXTERNALLY_MODIFIED")
    monkeypatch.setattr(mod, "CONF", conf)
    mod.save_state({
        "role": "victim", "phase": "PENDING_ROLLBACK",
        "original_backup": str(backup), "old_public_key": OLD,
    })
    monkeypatch.setattr(mod, "call", lambda *a, **k: pytest.fail("unsafe WG modification"))
    with pytest.raises(mod.PeerSafetyError, match="externally"):
        mod.restore("victim")


def test_rollback_never_undoes_committed_peer(tmp_path, monkeypatch) -> None:
    mod = load()
    root = tmp_path / "cutover"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(mod, "BASE", root)
    monkeypatch.setattr(mod, "STATE", root / "state.json")
    mod.save_state({"role": "victim", "phase": "COMMITTED"})
    with pytest.raises(mod.PeerSafetyError, match="committed"):
        mod.restore("victim")


def test_no_unbounded_pressure_or_network_probe_executed_by_cutover():
    src = SCRIPT.read_text()
    for forbidden in ("nmap ", "hping3", "iptables -F", "nft flush ruleset",
                      "wg-quick down", "rm -rf", "sshpass", "StrictHostKeyChecking=no"):
        assert forbidden not in src
    assert "TT L" not in src
    assert "TTL_SECONDS = 900" in src
    assert '["systemctl", "stop", timer_name()]' in src



def test_successful_independent_rollback_restores_original_live_peer(
    tmp_path, monkeypatch
) -> None:
    import hashlib

    mod = load()
    root = tmp_path / "cutover"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(mod, "BASE", root)
    monkeypatch.setattr(mod, "STATE", root / "state.json")
    original = (
        "[Interface]\nPrivateKey = TEST_KEY_NOT_PRINTED\n"
        "[Peer]\nPublicKey = " + OLD + "\n"
        "Endpoint = " + mod.ORIGINAL_HUB + "\nAllowedIPs = 10.77.0.0/24\n"
    )
    backup = tmp_path / "backups" / "precutover.safe" / "wg0.conf"
    backup.parent.mkdir(parents=True)
    backup.write_text(original)
    backup.chmod(0o600)
    backup.with_name("wg0.sha256").write_text(
        hashlib.sha256(original.encode()).hexdigest() + "  " + str(backup)
    )
    conf = tmp_path / "wg0.conf"
    conf.write_text(original)
    monkeypatch.setattr(mod, "CONF", conf)
    monkeypatch.setattr(mod, "RESTORE_TEMP_DIR", tmp_path)
    mod.save_state({
        "role": "victim", "phase": "PENDING_ROLLBACK",
        "original_backup": str(backup), "old_public_key": OLD,
    })
    called = []

    def fake_call(*args, **kwargs):
        called.append(args)
        if args[:2] == ("wg-quick", "strip"):
            assert args[-1] == str(backup)
            return "[Interface]\nPrivateKey = TEST_KEY_NOT_PRINTED\n"
        if args[:3] == ("wg", "show", "wg0"):
            return OLD
        return ""

    monkeypatch.setattr(mod, "call", fake_call)
    mod.restore("victim")
    assert any(c[:3] == ("wg", "syncconf", "wg0") for c in called)
    assert mod.load_state()["phase"] == "ROLLED_BACK"
    assert conf.read_text() == original
    assert backup.read_text() == original


def test_verified_commit_preserves_private_key_allowed_ips_and_backup(
    tmp_path, monkeypatch
) -> None:
    import contextlib

    mod = load()
    root = tmp_path / "cutover"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(mod, "BASE", root)
    monkeypatch.setattr(mod, "STATE", root / "state.json")
    conf = tmp_path / "wg0.conf"
    original = (
        "[Interface]\nPrivateKey = NEVER_PRINT_OR_REPLACE\n"
        "Address = 10.77.0.50/32\n"
        "[Peer]\nPublicKey = " + OLD + "\n"
        "AllowedIPs = 10.77.0.0/24\nEndpoint = " + mod.ORIGINAL_HUB + "\n"
    )
    conf.write_text(original)
    backup = tmp_path / "backups" / "precutover.safe" / "wg0.conf"
    backup.parent.mkdir(parents=True)
    backup.write_text(original)
    monkeypatch.setattr(mod, "CONF", conf)
    mod.save_state({
        "role": "victim", "phase": "PENDING_ROLLBACK",
        "old_public_key": OLD, "hub_public_key": NEW,
        "original_backup": str(backup),
        "expires_at_utc_epoch": int(time.time()) + 300,
    })
    monkeypatch.setattr(mod, "check_root", lambda role: None)
    monkeypatch.setattr(mod, "locked", lambda: contextlib.nullcontext())
    monkeypatch.setattr(mod, "is_timer_running", lambda: True)
    verified = []
    monkeypatch.setattr(
        mod, "check_live_target", lambda state: verified.append(state["hub_public_key"])
    )
    native = []

    def fake_call(*args, **kwargs):
        native.append(args)
        return "[Interface]\n" if args[:2] == ("wg-quick", "strip") else ""

    monkeypatch.setattr(mod, "call", fake_call)
    monkeypatch.setattr(
        mod.subprocess, "run",
        lambda *args, **kwargs: type("Result", (), {"returncode": 0})(),
    )
    mod.commit("victim")
    assert verified == [NEW]
    changed = conf.read_text()
    assert "PrivateKey = NEVER_PRINT_OR_REPLACE" in changed
    assert "Address = 10.77.0.50/32" in changed
    assert "AllowedIPs = 10.77.0.0/24" in changed
    assert f"PublicKey = {NEW}" in changed
    assert "Endpoint = " + mod.NEW_HUB in changed
    assert OLD not in changed
    assert backup.read_text() == original
    assert mod.load_state()["phase"] == "COMMITTED"
    assert any(x[:2] == ("wg-quick", "strip") for x in native)
