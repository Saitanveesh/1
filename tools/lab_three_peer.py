#!/usr/bin/env python3
"""One-peer-at-a-time MON lab WireGuard cutover with an independent rollback timer.

Only the authorized lab's existing wg0 PEER is changed. The underlay network,
SSH route, other firewalls, and existing private key are not changed.
NEVER invoke on an unverified host or without a local original-config backup.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

CONF = Path("/etc/wireguard/wg0.conf")
BACKUPS = Path("/root/mon-three-wg-backups")
BASE = Path("/root/mon-three-peer-cutover")
STATE = BASE / "state.json"
LOCK = Path("/run/lock/mon-three-peer-cutover.lock")
ORIGINAL_HUB = "10.5.115.5:51820"
NEW_HUB = "10.5.112.94:51820"
OVERLAY_HUB = "10.77.0.1"
VALID_ROLES = {"victim": "10.77.0.50/32", "attacker": "10.77.0.60/32"}
PUBLIC_KEY = re.compile(r"[A-Za-z0-9+/]{43}=")
TTL_SECONDS = 900
TIMER = "mon-three-peer-rollback"


class PeerSafetyError(RuntimeError):
    pass


def call(*cmd: str, input_data: str | None = None) -> str:
    """Run native binary; error intentionally omits args/stderr/private material."""
    try:
        proc = subprocess.run(
            cmd, input=input_data, text=True, capture_output=True,
            check=True, timeout=15,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise PeerSafetyError(f"native operation failed: {cmd[0]}") from None
    return proc.stdout.strip()


def check_root(role: str) -> None:
    if os.geteuid() != 0:
        raise PeerSafetyError("root-only cutover helper")
    if role not in VALID_ROLES:
        raise PeerSafetyError("unknown or non-lab peer role")
    if not Path("/sys/class/net/wg0").exists():
        raise PeerSafetyError("existing peer wg0 is absent")
    if not CONF.is_file() or (CONF.stat().st_mode & 0o077):
        raise PeerSafetyError("original peer WireGuard config absent/insecure")
    address = call("ip", "-o", "-4", "addr", "show", "dev", "wg0")
    if VALID_ROLES[role] not in address:
        raise PeerSafetyError("existing WireGuard peer role/address mismatch")
    mgmt = call("ip", "-4", "route", "get", "10.5.112.94")
    if "dev wg0" in mgmt or "unreachable" in mgmt:
        raise PeerSafetyError("PC2 management route unexpectedly traverses WG0")


@contextmanager
def locked():
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open("a+") as fd:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield


def atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix=".mon-atomic-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def save_state(state: dict) -> None:
    atomic_write(STATE, json.dumps(state, indent=2) + "\n")


def load_state() -> dict:
    if not STATE.is_file() or (STATE.stat().st_mode & 0o077):
        raise PeerSafetyError("protected cutover record missing/insecure")
    return json.loads(STATE.read_text(encoding="utf-8"))


def original_config() -> tuple[Path, str]:
    """Require an intact root-only backup matching the current persistent config."""
    current = CONF.read_bytes()
    matches = []
    for backup in sorted(BACKUPS.glob("precutover.*/wg0.conf")):
        if backup.stat().st_mode & 0o077:
            continue
        digest = backup.with_name("wg0.sha256")
        if not digest.is_file():
            continue
        sha = hashlib.sha256(backup.read_bytes()).hexdigest()
        if digest.read_text().split()[0] != sha:
            continue
        if current == backup.read_bytes():
            matches.append(backup)
    if not matches:
        raise PeerSafetyError("no intact backup matches the original persistent wg0.conf")
    return matches[-1], current.decode("utf-8")


def config_peer(config: str) -> tuple[str, str]:
    if config.count("[Peer]") != 1:
        raise PeerSafetyError("original configuration must have exactly one peer")
    match = re.search(
        r"(?m)^\s*PublicKey\s*=\s*([A-Za-z0-9+/]{43}=)\s*$", config
    )
    endpoint = re.search(r"(?m)^\s*Endpoint\s*=\s*(\S+)\s*$", config)
    allowed = re.search(r"(?m)^\s*AllowedIPs\s*=\s*(\S+)\s*$", config)
    if not match or not endpoint or not allowed or allowed.group(1) != "10.77.0.0/24":
        raise PeerSafetyError("original peer configuration is outside lab scope")
    if config.count("PublicKey") != 1 or config.count("Endpoint") != 1:
        raise PeerSafetyError("multiple peer keys/endpoints are unsupported")
    return match.group(1), endpoint.group(1)


def timer_name() -> str:
    return TIMER + ".timer"


def is_timer_running() -> bool:
    proc = subprocess.run(
        ["systemctl", "is-active", "--quiet", timer_name()],
        capture_output=True, check=False,
    )
    return proc.returncode == 0


def recent_handshake(public: str) -> bool:
    now = int(time.time())
    for line in call("wg", "show", "wg0", "latest-handshakes").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == public:
            try:
                return int(fields[1]) > 0 and 0 <= now - int(fields[1]) <= 120
            except ValueError:
                return False
    return False


def check_live_target(state: dict) -> None:
    peers = call("wg", "show", "wg0", "peers").splitlines()
    if peers != [state["hub_public_key"]]:
        raise PeerSafetyError("active peer is not the expected new MON hub")
    endpoints = call("wg", "show", "wg0", "endpoints")
    if endpoints.split() != [state["hub_public_key"], NEW_HUB]:
        raise PeerSafetyError("active endpoint differs from approved MON hub")
    route = call("ip", "-4", "route", "get", OVERLAY_HUB)
    if "dev wg0" not in route:
        raise PeerSafetyError("overlay route no longer uses wg0")
    if not recent_handshake(state["hub_public_key"]):
        raise PeerSafetyError("no recent verified handshake with MON hub")


def preflight(role: str, hub_pub: str) -> tuple[Path, str, str]:
    check_root(role)
    if not PUBLIC_KEY.fullmatch(hub_pub):
        raise PeerSafetyError("invalid new hub public key")
    if STATE.exists():
        raise PeerSafetyError("another cutover record exists; inspect status first")
    old_pub = call("wg", "show", "wg0", "peers")
    if not PUBLIC_KEY.fullmatch(old_pub):
        raise PeerSafetyError("existing WireGuard has unexpected peer roster")
    endpoint = call("wg", "show", "wg0", "endpoints").split()
    if endpoint != [old_pub, ORIGINAL_HUB]:
        raise PeerSafetyError("old hub endpoint changed; no cutover attempted")
    allowed = call("wg", "show", "wg0", "allowed-ips").split()
    if allowed != [old_pub, "10.77.0.0/24"]:
        raise PeerSafetyError("unexpected existing peer route permissions")
    backup, current = original_config()
    config_pub, config_endpoint = config_peer(current)
    if config_pub != old_pub or config_endpoint != ORIGINAL_HUB:
        raise PeerSafetyError("running old peer differs from protected backup")
    if old_pub == hub_pub:
        raise PeerSafetyError("new hub public key equals legacy hub")
    if call("wg", "show", "wg0", "public-key") == hub_pub:
        raise PeerSafetyError("local peer public key equals the hub key")
    return backup, old_pub, current


def start(role: str, hub_pub: str) -> None:
    with locked():
        backup, old_pub, _ = preflight(role, hub_pub)
        BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
        if BASE.stat().st_mode & 0o077:
            raise PeerSafetyError("cutover work directory too permissive")
        runner = BASE / "runner.py"
        if not runner.is_file() or runner.stat().st_mode & 0o077:
            raise PeerSafetyError("immutable root-only rollback runner missing")
        state = {
            "schema_version": "mon.lab.peer-cutover.v1",
            "role": role,
            "phase": "PENDING_ROLLBACK",
            "old_public_key": old_pub,
            "hub_public_key": hub_pub,
            "old_endpoint": ORIGINAL_HUB,
            "new_endpoint": NEW_HUB,
            "original_backup": str(backup),
            "expires_at_utc_epoch": int(time.time()) + TTL_SECONDS,
        }
        save_state(state)
        try:
            call(
                "systemd-run", "--unit", TIMER,
                f"--on-active={TTL_SECONDS}s",
                "--timer-property=AccuracySec=1s",
                "/usr/bin/python3", str(runner), "rollback", "--role", role,
            )
            if not is_timer_running():
                raise PeerSafetyError("independent rollback timer did not start")
            # Only wg0 peer settings change; no interface restart, route or LAN change.
            call("wg", "set", "wg0", "peer", old_pub, "remove")
            call(
                "wg", "set", "wg0", "peer", hub_pub, "endpoint", NEW_HUB,
                "allowed-ips", "10.77.0.0/24",
                "persistent-keepalive", "25",
            )
            if call("wg", "show", "wg0", "peers") != hub_pub:
                raise PeerSafetyError("new peer installation could not be verified")
        except PeerSafetyError:
            if is_timer_running():
                # Retry via the independent timer even if immediate rollback fails.
                try:
                    restore(role, allow_pending=True)
                except PeerSafetyError:
                    pass
            raise
        print("CUTOVER_PENDING_AUTOMATIC_ROLLBACK")
        print(f"Role: {role}; timer: {TTL_SECONDS}s; manual confirmation required.")
        print("Original config is unchanged on disk. No site detector is started.")


def restore(role: str, *, allow_pending: bool = False) -> None:
    state = load_state()
    if state["role"] != role:
        raise PeerSafetyError("cutover record belongs to another host")
    if state["phase"] == "COMMITTED":
        raise PeerSafetyError("committed peer requires a separate approved recovery")
    if state["phase"] == "ROLLED_BACK":
        return
    if state["phase"] != "PENDING_ROLLBACK":
        raise PeerSafetyError("unknown cutover state")
    backup = Path(state["original_backup"])
    if not backup.is_file() or backup.stat().st_mode & 0o077:
        raise PeerSafetyError("protected original config backup unavailable")
    original = backup.read_bytes()
    digest = backup.with_name("wg0.sha256")
    if hashlib.sha256(original).hexdigest() != digest.read_text().split()[0]:
        raise PeerSafetyError("original backup digest mismatch")
    if CONF.read_bytes() != original:
        raise PeerSafetyError(
            "persistent config changed externally; refuse blind rollback overwrite"
        )
    # wg-quick strips system-level Address/MTU but retains private key and peers.
    stripped = call("wg-quick", "strip", str(backup))
    fd, temp = tempfile.mkstemp(prefix="wgmon-", suffix=".conf", dir="/root")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(stripped + "\n")
        call("wg", "syncconf", "wg0", temp)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    if call("wg", "show", "wg0", "peers") != state["old_public_key"]:
        raise PeerSafetyError("old WireGuard peer not restored")
    state["phase"] = "ROLLED_BACK"
    state["rolled_back_at_utc_epoch"] = int(time.time())
    save_state(state)
    print("ORIGINAL_PEER_RESTORED")
    print("The existing LAN management route and private key were preserved.")


def rollback(role: str) -> None:
    check_root(role)
    with locked():
        restore(role)
        # Stop timer when operator invokes rollback; expiration invokes the timer.
        if is_timer_running():
            subprocess.run(
                ["systemctl", "stop", timer_name()], capture_output=True, check=False
            )


def verify(role: str) -> None:
    check_root(role)
    with locked():
        state = load_state()
        if state["role"] != role or state["phase"] not in (
            "PENDING_ROLLBACK", "COMMITTED"
        ):
            raise PeerSafetyError("no active cutover for this role")
        check_live_target(state)
        print("PEER_NEW_HUB_HANDSHAKE_VERIFIED")
        print(
            f"role={role} phase={state['phase']} "
            f"rollback_active={is_timer_running()}"
        )


def commit(role: str) -> None:
    check_root(role)
    with locked():
        state = load_state()
        if state["role"] != role or state["phase"] != "PENDING_ROLLBACK":
            raise PeerSafetyError("no pending, uncommitted migration")
        if not is_timer_running() or int(time.time()) >= state["expires_at_utc_epoch"]:
            raise PeerSafetyError("rollback timer expired or absent; refusing commit")
        check_live_target(state)
        original = CONF.read_text(encoding="utf-8")
        backup = Path(state["original_backup"])
        if hashlib.sha256(CONF.read_bytes()).hexdigest() != hashlib.sha256(
            backup.read_bytes()
        ).hexdigest():
            raise PeerSafetyError("original configuration drifted after cutover")
        old_pub, old_end = config_peer(original)
        if old_pub != state["old_public_key"] or old_end != ORIGINAL_HUB:
            raise PeerSafetyError("original persistent peer no longer matches backup")
        changed = re.sub(
            r"(?m)^(\s*PublicKey\s*=\s*)" + re.escape(old_pub) + r"(?=\s*$)",
            lambda match: match.group(1) + state["hub_public_key"], original,
            count=1,
        )
        changed = re.sub(
            r"(?m)^(\s*Endpoint\s*=\s*)" + re.escape(ORIGINAL_HUB) + r"(?=\s*$)",
            lambda match: match.group(1) + NEW_HUB, changed, count=1,
        )
        if config_peer(changed) != (state["hub_public_key"], NEW_HUB):
            raise PeerSafetyError("persistent config peer migration failed")
        fd, stage = tempfile.mkstemp(
            dir=str(CONF.parent), prefix="wgmon-", suffix=".conf"
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                out.write(changed)
                out.flush()
                os.fsync(out.fileno())
            call("wg-quick", "strip", stage)
            os.replace(stage, CONF)
        finally:
            if os.path.exists(stage):
                os.unlink(stage)
        state["phase"] = "COMMITTED"
        state["committed_at_utc_epoch"] = int(time.time())
        save_state(state)
        # If stopping the timer fails, the timer's COMMITTED state check
        # still prevents it from undoing the validated new peer.
        subprocess.run(
            ["systemctl", "stop", timer_name()], capture_output=True, check=False
        )
        print("PEER_CUTOVER_COMMITTED")
        print("Original backup retained for separately approved recovery.")


def status(role: str) -> None:
    check_root(role)
    if not STATE.exists():
        print("CUTOVER_NOT_STARTED")
        return
    with locked():
        state = load_state()
        if state.get("role") != role:
            raise PeerSafetyError("cutover status has incorrect peer role")
        print(f"role={role} phase={state['phase']} timer_active={is_timer_running()}")
        print(f"expected_new_hub={NEW_HUB}; rollback_deadline={state['expires_at_utc_epoch']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("start", "verify", "commit", "rollback", "status"))
    parser.add_argument("--role", required=True, choices=sorted(VALID_ROLES))
    parser.add_argument("--hub-public-key")
    args = parser.parse_args()
    try:
        if args.command == "start":
            if not args.hub_public_key:
                raise PeerSafetyError("start requires verified hub public key")
            start(args.role, args.hub_public_key)
        elif args.command == "verify":
            verify(args.role)
        elif args.command == "commit":
            commit(args.role)
        elif args.command == "rollback":
            rollback(args.role)
        else:
            status(args.role)
    except PeerSafetyError as exc:
        print(f"Peer migration stopped: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
