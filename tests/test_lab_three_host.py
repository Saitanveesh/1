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
