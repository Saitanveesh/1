from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "lab_three_host.py"


def load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("mon_lab_three_host", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def inventory(tmp_path: Path, *, users=None, hosts=None) -> Path:
    users = users or {"mon": "pc_2", "victim": "pc-5", "attacker": "pc-6"}
    hosts = hosts or {
        "mon": "100.75.116.62",
        "victim": "100.80.1.2",
        "attacker": "100.80.1.3",
    }
    path = tmp_path / "inventory.json"
    path.write_text(
        json.dumps({name: {"host": hosts[name], "user": users[name]} for name in users}),
        encoding="utf-8",
    )
    return path


def test_inventory_accepts_three_verified_roles(tmp_path: Path) -> None:
    mod = load_module()
    peers = mod.read_inventory(inventory(tmp_path))
    assert set(peers) == {"mon", "victim", "attacker"}
    assert peers["mon"].dest == "pc_2@100.75.116.62"


@pytest.mark.parametrize(
    ("hosts", "users"),
    [
        (
            {"mon": "100.75.116.62", "victim": "100.75.116.62", "attacker": "100.80.1.3"},
            {"mon": "pc-2", "victim": "pc-5", "attacker": "pc-6"},
        ),
        (
            {"mon": "10.5.112.94", "victim": "100.80.1.2", "attacker": "100.80.1.3"},
            {"mon": "pc-2", "victim": "pc-5", "attacker": "pc-6"},
        ),
        (
            {"mon": "100.75.116.62", "victim": "100.80.1.2", "attacker": "100.80.1.3"},
            {"mon": "pc-2;rm -rf /", "victim": "pc-5", "attacker": "pc-6"},
        ),
    ],
)
def test_inventory_rejects_duplicate_non_tailnet_and_shell_metacharacters(
    tmp_path: Path, hosts: dict[str, str], users: dict[str, str]
) -> None:
    mod = load_module()
    with pytest.raises(ValueError):
        mod.read_inventory(inventory(tmp_path, users=users, hosts=hosts))


def test_inventory_rejects_missing_extra_fields(tmp_path: Path) -> None:
    mod = load_module()
    path = inventory(tmp_path)
    data = json.loads(path.read_text())
    data["mon"]["password"] = "never-store-passwords-here"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        mod.read_inventory(path)


def test_preflight_requires_matching_tailscale_identity(tmp_path: Path) -> None:
    mod = load_module()
    peers = mod.read_inventory(inventory(tmp_path))

    class Fake:
        def __init__(self, ips):
            self.peers = peers
            self.ips = ips

        def ssh(self, role, command, *, capture=False, interactive=False):
            peer = self.peers[role]
            return (
                f"host=lab-{role} user={peer.user}\n"
                f"os=ubuntu version=24.04\n"
                f"tail-ip={self.ips.get(role, peer.host)}\n"
                "/usr/bin/sudo\n/usr/bin/apt-get"
            )

    mod.preflight(Fake({}))
    with pytest.raises(RuntimeError, match="does not match inventory"):
        mod.preflight(Fake({"victim": "100.80.2.3"}))


def test_checkout_is_pinned_and_never_resets_dirty_worktree() -> None:
    mod = load_module()
    stage = mod.checkout_script(mod.PINNED_REF)
    assert mod.PINNED_REF in stage
    assert "git status --porcelain" in stage
    assert "git reset --hard" not in stage
    assert "rm -rf" not in stage


def test_overlay_owns_only_scoped_guard_and_preserves_tailscale(tmp_path: Path) -> None:
    mod = load_module()
    peers = mod.read_inventory(inventory(tmp_path))
    issued = []
    key = "A" * 43 + "="

    class Fake:
        def __init__(self):
            self.peers = peers

        def run(self, role, script, *, root=False, label=""):
            issued.append((role, script, root, label))

        def ssh(self, role, command, *, capture=False, interactive=False):
            return key

    mod.overlay(Fake())
    names = [x[3] for x in issued]
    assert names.index("guard-attacker-overlay") < names.index("overlay-forwarding")
    assert names.index("guard-attacker-overlay") < names.index("wireguard-config")
    assert names.count("wireguard-config") == 3
    configs = [script for _, script, _, label in issued if label == "wireguard-config"]
    assert all("PrivateKey = MON_LOCAL_KEY" in script for script in configs)
    assert all("sed -i" in script for script in configs)
    assert all("if [ -e /etc/wireguard/wg0.conf ]" in script for script in configs)
    assert all("nft flush ruleset" not in script for _, script, _, _ in issued)
    assert all("tailscale0" not in script for _, script, _, _ in issued)
    guard = next(script for _, script, _, label in issued if label == "guard-attacker-overlay")
    assert "iifname \"wg0\"" in guard
    assert "10.77.0.60" in guard
    assert "10.77.0.50" in guard


def test_no_automatic_exercise_traffic() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "sshpass" not in source
    assert "nmap -sS" not in source
    assert "hping3" not in source
    assert "StrictHostKeyChecking=no" not in source
    assert "NOPASSWD:ALL" not in source
    assert "sudo nft flush ruleset" not in source



def test_live_sensor_gate_requires_both_fresh_heartbeats() -> None:
    mod = load_module()
    good = [
        {"sensor_id": "suricata-three", "heartbeat_age_seconds": 10},
        {"sensor_id": "linux-victim-three", "heartbeat_age_seconds": 12},
    ]
    mod.validate_live_sensors(good)
    with pytest.raises(RuntimeError, match="missing live sensor"):
        mod.validate_live_sensors(good[:1])
    with pytest.raises(RuntimeError, match="stale heartbeat"):
        mod.validate_live_sensors([
            good[0], {"sensor_id": "linux-victim-three", "heartbeat_age_seconds": 95}
        ])
    with pytest.raises(RuntimeError, match="missing numeric"):
        mod.validate_live_sensors([
            good[0], {"sensor_id": "linux-victim-three", "heartbeat_age_seconds": None}
        ])



def test_demo_preparation_is_explicitly_scoped_and_never_starts_a_scan(
) -> None:
    mod = load_module()
    calls = []

    class Fake:
        def run(self, role, script, *, root=False, label=""):
            calls.append((role, script, root, label))

    mod.demo_prepare(Fake())
    assert len(calls) == 1
    role, script, root, label = calls[0]
    assert role == "victim" and root is True
    assert label == "bounded-recon-port-filter"
    assert 'iifname "wg0"' in script
    assert "ip saddr 10.77.0.60" in script
    assert "tcp dport 20000-20099 drop" in script
    assert "nmap " not in script
    assert "nft flush ruleset" not in script



def mixed_inventory(tmp_path: Path) -> Path:
    path = tmp_path / "mixed.json"
    path.write_text(json.dumps({
        "mon": {
            "host": "100.75.116.62",
            "user": "pc-2",
            "network": "tailscale",
            "lan_ip": "10.5.112.94",
        },
        "victim": {
            "host": "10.5.112.23", "user": "pc-5", "network": "lan",
        },
        "attacker": {
            "host": "10.5.112.4", "user": "pc-6", "network": "lan",
        },
    }), encoding="utf-8")
    return path


def test_mixed_tailnet_and_lan_inventory(tmp_path: Path) -> None:
    mod = load_module()
    peers = mod.read_inventory(mixed_inventory(tmp_path))
    assert peers["mon"].lan_ip == "10.5.112.94"
    assert peers["victim"].network == "lan"
    assert peers["attacker"].dest == "pc-6@10.5.112.4"


def test_mixed_inventory_requires_mon_lan_endpoint(tmp_path: Path) -> None:
    mod = load_module()
    path = mixed_inventory(tmp_path)
    data = json.loads(path.read_text())
    data["mon"].pop("lan_ip")
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="lan_ip is required"):
        mod.read_inventory(path)


def test_mixed_inventory_rejects_unexpected_public_or_special_ips(tmp_path: Path) -> None:
    mod = load_module()
    path = mixed_inventory(tmp_path)
    for invalid in ("8.8.8.8", "100.75.116.62", "127.0.0.1"):
        data = json.loads(path.read_text())
        data["victim"]["host"] = invalid
        path.write_text(json.dumps(data))
        with pytest.raises(ValueError):
            mod.read_inventory(path)


def test_mixed_preflight_verifies_all_local_ipv4_interfaces(tmp_path: Path) -> None:
    mod = load_module()
    peers = mod.read_inventory(mixed_inventory(tmp_path))

    class Fake:
        def __init__(self, override=None):
            self.peers = peers
            self.override = override or {}

        def ssh(self, role, command, *, capture=False, interactive=False):
            peer = peers[role]
            addr = self.override.get(role, peer.host)
            if role == "mon":
                ip_lines = "tail-ip=100.75.116.62\naddr4=10.5.112.94/20"
            else:
                ip_lines = f"addr4={addr}/20"
            return (
                f"host=lab-{role} user={peer.user}\n"
                f"os=ubuntu version=26.04\n{ip_lines}\n"
                "/usr/bin/sudo\n/usr/bin/apt-get"
            )

    mod.preflight(Fake())
    with pytest.raises(RuntimeError, match="LAN IP not assigned"):
        mod.preflight(Fake({"attacker": "10.5.112.99"}))


def test_lan_wireguard_peer_uses_mon_verified_underlay(tmp_path: Path) -> None:
    mod = load_module()
    peers = mod.read_inventory(mixed_inventory(tmp_path))
    calls = []

    class Fake:
        def __init__(self):
            self.peers = peers

        def run(self, role, script, *, root=False, label=""):
            calls.append((role, label, script))

        def ssh(self, role, command, *, capture=False, interactive=False):
            return "A" * 43 + "="

    mod.overlay(Fake())
    for role in ("victim", "attacker"):
        conf = next(script for r, label, script in calls
                    if r == role and label == "wireguard-config")
        assert "Endpoint = 10.5.112.94:51820" in conf
        assert "AllowedIPs = 10.77.0.0/24" in conf
        assert "0.0.0.0/0" not in conf



def test_bootstrap_waits_for_package_manager_lock() -> None:
    mod = load_module()
    for role in ("mon", "victim", "attacker"):
        script = mod.base_script(role)
        assert "DPkg::Lock::Timeout=600" in script


def test_overlay_rejects_existing_wg0_before_mutations(tmp_path: Path) -> None:
    mod = load_module()
    peers = mod.read_inventory(mixed_inventory(tmp_path))
    calls = []

    class Fake:
        def __init__(self):
            self.peers = peers

        def ssh(self, role, command, *, capture=False, interactive=False):
            if "sys/class/net/wg0" in command:
                return "present" if role == "victim" else ""
            return "A" * 43 + "="

        def run(self, role, script, *, root=False, label=""):
            calls.append((role, label))

    with pytest.raises(RuntimeError, match="existing wg0 is active"):
        mod.overlay(Fake())
    assert calls == []



def test_scrubbing_excludes_all_nested_credential_values() -> None:
    mod = load_module()
    result = mod.scrub_secrets({
        "secret": "private",
        "session": {"bearer_token": "jwt-value", "password": "plain"},
        "events": [{"sensor_id": "linux-victim-three", "count": 3}],
    })
    assert result["secret"] == "[REDACTED]"
    assert result["session"]["bearer_token"] == "[REDACTED]"
    assert result["session"]["password"] == "[REDACTED]"
    assert result["events"][0]["count"] == 3


def test_evidence_snapshot_has_explicit_incomplete_state(tmp_path, monkeypatch) -> None:
    mod = load_module()
    monkeypatch.setattr(mod.os, "getlogin", lambda: "operator")
    path = tmp_path / "mon-evidence.json"

    class Fake:
        def ssh(self, role, command, *, capture=False, interactive=False):
            if "incidents" in command:
                raise mod.subprocess.CalledProcessError(22, command)
            if "health" in command:
                return '{"state":"READY"}'
            if "sensors" in command:
                return '[{"sensor_id":"linux-victim-three","credential_ref":"SECRET"}]'
            return "[]"

    with pytest.raises(RuntimeError, match="Some evidence endpoints failed"):
        mod.capture_evidence(Fake(), path)
    result = json.loads(path.read_text())
    assert result["result"] == "INCOMPLETE"
    assert result["sources"]["sensors"][0]["credential_ref"] == "[REDACTED]"
    assert "incidents" in result["errors"]
    assert path.stat().st_mode & 0o077 == 0
    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        mod.capture_evidence(Fake(), path)


def test_doctor_is_inspection_only(tmp_path) -> None:
    mod = load_module()
    peers = mod.read_inventory(mixed_inventory(tmp_path))
    calls = []

    class Fake:
        def __init__(self):
            self.peers = peers

        def ssh(self, role, command, *, capture=False, interactive=False):
            calls.append((role, command))

        def run(self, role, script, *, root=False, label=""):
            calls.append((role, script))
            assert label == "read-only-network-and-package-inspection"
            assert "wg show wg0 endpoints" in script
            assert "fuser -v" in script

    mod.doctor(Fake())
    assert len(calls) == 6
    for _, command in calls:
        assert "kill -9" not in command
        assert "nft add " not in command
        assert "systemctl stop" not in command
