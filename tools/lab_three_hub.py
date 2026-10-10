#!/usr/bin/env python3
"""Guarded PC2-only WireGuard hub lifecycle for the authorized three-host MON lab.

No peer migration, traffic generation, forwarding/sysctl changes, or host-LAN
filter changes. Root required, exclusively on the pre-identified MON hub.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import pwd
import re
import subprocess
import sys
import tempfile
from pathlib import Path

WG_CONF = Path("/etc/wireguard/wg0.conf")
GUARD = "mon_three_guard"
MARKER = "# MON_THREE_LAB_HUB_V1"
KEY_REGEX = re.compile(r"[A-Za-z0-9+/]{43}=")
WG_ADDR = "10.77.0.1/24"
EXPECTED_PORT = "51820"


class HubSafetyError(RuntimeError):
    pass


def checked(*args: str, input_data: str | None = None) -> str:
    out = subprocess.run(
        args, input=input_data, text=True, check=True, capture_output=True
    )
    return out.stdout.strip()


def guard_exists() -> bool:
    result = subprocess.run(
        ["nft", "list", "table", "inet", GUARD], capture_output=True, text=True
    )
    return result.returncode == 0


def is_active() -> bool:
    return Path("/sys/class/net/wg0").exists()


def require_root() -> None:
    if os.geteuid() != 0:
        raise HubSafetyError("root required for local WireGuard hub management")


def require_public_keys(args: argparse.Namespace) -> None:
    public_keys = (args.hub_public_key, args.victim_public_key, args.attacker_public_key)
    if any(not KEY_REGEX.fullmatch(value or "") for value in public_keys):
        raise HubSafetyError("invalid peer public key; no changes applied")
    if len(set(public_keys)) != 3:
        raise HubSafetyError("hub and peer public keys must be unique")


def owner_home(user: str) -> Path:
    if user in ("", "root") or not re.fullmatch(r"[a-z_][a-z0-9_-]*", user):
        raise HubSafetyError("the MON owner must be a regular local account")
    record = pwd.getpwnam(user)
    if record.pw_uid == 0:
        raise HubSafetyError("MON owner may not be root")
    return Path(record.pw_dir)


def check_management_routes(ips: tuple[str, ...]) -> None:
    for raw in ips:
        ip = ipaddress.IPv4Address(raw)
        if ip not in ipaddress.IPv4Network("10.5.112.0/20"):
            raise HubSafetyError("unexpected lab management address")
        route = checked("ip", "-4", "route", "get", raw)
        if "dev wg0" in route or "unreachable" in route:
            raise HubSafetyError("LAN management route may not use wg0")


def assert_unused_guard() -> None:
    if guard_exists():
        raise HubSafetyError("MON guard exists; refusing to adopt or overwrite it")


def guard_script() -> str:
    # Atomic nft -f transaction; no flushing/changing external tables.
    return """add table inet mon_three_guard
add chain inet mon_three_guard input { type filter hook input priority -150; policy accept; }
add chain inet mon_three_guard forward { type filter hook forward priority -150; policy accept; }
add rule inet mon_three_guard input iifname "wg0" ip saddr 10.77.0.60 drop
add rule inet mon_three_guard input iifname "wg0" ip saddr != 10.77.0.50 drop
add rule inet mon_three_guard forward iifname "wg0" oifname != "wg0" drop
add rule inet mon_three_guard forward oifname "wg0" iifname != "wg0" drop
add rule inet mon_three_guard forward iifname "wg0" ip saddr 10.77.0.60 ip daddr != 10.77.0.50 drop
add rule inet mon_three_guard forward iifname "wg0" ip saddr 10.77.0.50 ip daddr != 10.77.0.60 drop
"""


def rendered_config(
    hub_private: str,
    victim_public: str,
    attacker_public: str,
) -> str:
    if not KEY_REGEX.fullmatch(hub_private):
        raise HubSafetyError("MON local private key has invalid format")
    return (
        f"{MARKER}\n"
        "[Interface]\n"
        f"Address = {WG_ADDR}\n"
        f"ListenPort = {EXPECTED_PORT}\n"
        f"PrivateKey = {hub_private}\n\n"
        "[Peer]\n"
        f"PublicKey = {victim_public}\n"
        "AllowedIPs = 10.77.0.50/32\n\n"
        "[Peer]\n"
        f"PublicKey = {attacker_public}\n"
        "AllowedIPs = 10.77.0.60/32\n"
    )


def prepare(args: argparse.Namespace) -> None:
    require_root()
    require_public_keys(args)
    if is_active() or WG_CONF.exists():
        raise HubSafetyError("wg0 already exists; refusing to overwrite an interface")
    if Path("/etc/sysctl.d/99-mon-three.conf").exists():
        raise HubSafetyError("existing MON forwarding policy requires manual review")
    assert_unused_guard()
    if checked("ss", "-H", "-lun", "sport = :51820"):
        raise HubSafetyError("UDP/51820 is already in use")
    home = owner_home(args.mon_user)
    key = home / "mon-three/wg.key"
    if not key.is_file() or (key.stat().st_mode & 0o077):
        raise HubSafetyError("MON WireGuard key missing or not owner-only")
    if key.stat().st_uid != pwd.getpwnam(args.mon_user).pw_uid:
        raise HubSafetyError("MON WireGuard key has unexpected owner")
    hub_private = key.read_text(encoding="utf-8").strip()
    hub_public = checked("wg", "pubkey", input_data=hub_private + "\n")
    if hub_public != args.hub_public_key:
        raise HubSafetyError("hub private/public identity differs from migration plan")
    check_management_routes((args.victim_management, args.attacker_management))

    guard_staging: Path | None = None
    conf_staging: Path | None = None
    created_guard = False
    installed_conf = False
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", dir="/tmp", prefix=".mon-wg-nft-", delete=False
        ) as handle:
            guard_staging = Path(handle.name)
            handle.write(guard_script())
        os.chmod(guard_staging, 0o600)
        checked("nft", "-c", "-f", str(guard_staging))
        WG_CONF.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", dir=str(WG_CONF.parent), prefix=".mon-wg0-",
            suffix=".conf", delete=False
        ) as handle:
            conf_staging = Path(handle.name)
            handle.write(
                rendered_config(
                    hub_private, args.victim_public_key, args.attacker_public_key
                )
            )
        os.chmod(conf_staging, 0o600)
        # Validate the exact config with the native WireGuard parser.
        checked("wg-quick", "strip", str(conf_staging))
        # Guard MUST be active before we raise wg0. No global firewall flush.
        checked("nft", "-f", str(guard_staging))
        created_guard = True
        if WG_CONF.exists() or is_active():
            raise HubSafetyError("wg0 appeared during preparation; stop")
        conf_staging.replace(WG_CONF)
        installed_conf = True
        checked("systemctl", "enable", "--now", "wg-quick@wg0")
        assert_prepared()
    except (HubSafetyError, OSError, subprocess.CalledProcessError):
        if installed_conf:
            subprocess.run(
                ["systemctl", "disable", "--now", "wg-quick@wg0"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            )
            if WG_CONF.is_file() and WG_CONF.read_text().startswith(MARKER):
                WG_CONF.unlink()
        if created_guard:
            subprocess.run(
                ["nft", "delete", "table", "inet", GUARD],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            )
        raise
    finally:
        for candidate in (conf_staging, guard_staging):
            if candidate is not None:
                candidate.unlink(missing_ok=True)

    print("HUB_PREPARED_GUARDED")
    print("No existing peer interfaces, old endpoints or campus routing changed.")
    print("No WireGuard handshake with PC5/PC6 is claimed.")


def assert_prepared() -> None:
    require_root()
    if not WG_CONF.is_file() or not WG_CONF.read_text().startswith(MARKER):
        raise HubSafetyError("MON-owned WG0 configuration missing or unexpected")
    if WG_CONF.stat().st_mode & 0o077:
        raise HubSafetyError("hub configuration permissions are too broad")
    if not is_active():
        raise HubSafetyError("hub wg0 is not active")
    if "10.77.0.1/24" not in checked("ip", "-o", "-4", "addr", "show", "dev", "wg0"):
        raise HubSafetyError("hub IPv4 address differs from plan")
    if checked("wg", "show", "wg0", "listen-port") != EXPECTED_PORT:
        raise HubSafetyError("hub UDP port differs from plan")
    if len(checked("wg", "show", "wg0", "peers").splitlines()) != 2:
        raise HubSafetyError("unexpected hub peer count")
    if not guard_exists():
        raise HubSafetyError("MON-owned firewall guard absent")
    table = checked("nft", "list", "table", "inet", GUARD)
    for guard in (
        'iifname "wg0" ip saddr 10.77.0.60 drop',
        'iifname "wg0" oifname != "wg0" drop',
        'oifname "wg0" iifname != "wg0" drop',
    ):
        if guard not in table:
            raise HubSafetyError("MON guard lacks an expected isolation rule")


def verify(args: argparse.Namespace) -> None:
    assert_prepared()
    check_management_routes((args.victim_management, args.attacker_management))
    print("HUB_GUARD_VERIFIED")
    print("Actual peer handshakes (epoch seconds, 0 means not yet connected):")
    print(checked("wg", "show", "wg0", "latest-handshakes"))
    print("No peer cutover or network telemetry has been claimed.")


def rollback() -> None:
    require_root()
    assert_prepared()
    rows = checked("wg", "show", "wg0", "latest-handshakes").splitlines()
    # A recorded handshake means at least one peer has used the new hub; do not
    # terminate it automatically even when currently stale.
    if any(int(row.split()[1]) != 0 for row in rows):
        raise HubSafetyError(
            "A peer has handshaken. Refusing to remove an in-use MON hub."
        )
    checked("systemctl", "disable", "--now", "wg-quick@wg0")
    if is_active():
        raise HubSafetyError("wg0 still active; configuration and guard preserved")
    WG_CONF.unlink()
    checked("nft", "delete", "table", "inet", GUARD)
    print("UNUSED_HUB_ROLLED_BACK")
    print("Peer configurations and management connectivity were not changed.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    prepare_cmd = sub.add_parser("prepare")
    prepare_cmd.add_argument("--mon-user", required=True)
    prepare_cmd.add_argument("--hub-public-key", required=True)
    prepare_cmd.add_argument("--victim-public-key", required=True)
    prepare_cmd.add_argument("--attacker-public-key", required=True)
    for cmd in (prepare_cmd, sub.add_parser("verify")):
        cmd.add_argument("--victim-management", required=True)
        cmd.add_argument("--attacker-management", required=True)
    sub.add_parser("rollback")
    args = parser.parse_args()
    try:
        if args.operation == "prepare":
            prepare(args)
        elif args.operation == "verify":
            verify(args)
        else:
            rollback()
    except (HubSafetyError, subprocess.CalledProcessError, OSError) as exc:
        # Never print a subprocess command: it may carry credentials.
        detail = str(exc) if isinstance(exc, HubSafetyError) else "OS/native command failure"
        print(f"Hub stage failed: {type(exc).__name__}: {detail}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
