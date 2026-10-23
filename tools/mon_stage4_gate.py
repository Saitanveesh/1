#!/usr/bin/env python3
"""PC-2 local, tightly scoped nftables gate for the fictional MON web range.

Receives requests ONLY on a Unix socket. The portal separately authenticates
the operator and verifies a recent real IDS signature. This privileged helper
does not accept custom ports, destinations, actions or firewall commands.

A kernel nftables timeout set makes blocks expire even if this daemon crashes.
The dedicated table is never used for other MON enforcement policies.
"""
from __future__ import annotations

import grp
import ipaddress
import json
import os
import socket
import socketserver
import subprocess
import threading
from pathlib import Path
from typing import Any, Callable

TABLE = "mon_stage4_range"
CHAIN = "training_forward"
SET = "blocked_sources"
VICTIM = "10.77.0.50"
PORT = 8085
IFACE = "wg0"
ATTACKERS = frozenset({"10.77.0.60", "10.77.0.70"})
SOCKET_PATH = Path(os.environ.get("MON_STAGE4_SOCKET", "/run/mon-stage4/control.sock"))
GROUP = "pc-2"
MAX_REQUEST = 1024


def validate_source(value: object) -> str:
    if not isinstance(value, str) or value not in ATTACKERS:
        raise ValueError("Only enrolled lab attackers 10.77.0.60 and 10.77.0.70 can be controlled")
    if str(ipaddress.ip_address(value)) != value:
        raise ValueError("Invalid source address")
    return value


def validate_ttl(value: object) -> int:
    if type(value) is not int or not 30 <= value <= 180:
        raise ValueError("Block duration must be 30–180 seconds")
    return value


class NftGate:
    def __init__(self, runner: Callable[..., Any] = subprocess.run) -> None:
        self.runner = runner

    def _run(self, args: list[str], *, source: str | None = None) -> subprocess.CompletedProcess:
        result = self.runner(["/usr/sbin/nft", *args], input=source, text=True,
                             capture_output=True, timeout=6, check=False)
        if result.returncode:
            raise RuntimeError("nftables command failed: " + (result.stderr or "")[:180])
        return result

    def _existing(self) -> bool:
        result = self.runner(["/usr/sbin/nft", "list", "table", "inet", TABLE],
                             capture_output=True, text=True, timeout=6, check=False)
        if result.returncode:
            if "No such file" in (result.stderr or ""):
                return False
            raise RuntimeError("Cannot verify dedicated firewall table: " + (result.stderr or "")[:180])
        body = result.stdout or ""
        # Never adopt or delete a table that looks different.
        if (body.count("set ") != 1 or body.count("chain ") != 1 or
            body.count("counter") != 1 or
            f"set {SET}" not in body or f"chain {CHAIN}" not in body or
            f"ip saddr @{SET}" not in body or f"ip daddr {VICTIM}" not in body or
            f"tcp dport {PORT}" not in body or "hook forward" not in body or
            'iifname "wg0"' not in body or 'oifname "wg0"' not in body):
            raise RuntimeError("Dedicated firewall namespace conflicts with existing rules")
        return True

    def initialize(self) -> None:
        if self._existing():
            return
        rules = (
            f"add table inet {TABLE}\n"
            f"add set inet {TABLE} {SET} {{ type ipv4_addr; flags timeout; }}\n"
            f"add chain inet {TABLE} {CHAIN} "
            "{ type filter hook forward priority -55; policy accept; }\n"
            f"add rule inet {TABLE} {CHAIN} iifname \"{IFACE}\" oifname \"{IFACE}\" "
            f"ip saddr @{SET} ip daddr {VICTIM} tcp dport {PORT} counter drop\n"
        )
        self._run(["-c", "-f", "-"], source=rules)
        self._run(["-f", "-"], source=rules)
        if not self._existing():
            raise RuntimeError("Firewall gate did not match the expected narrow policy")

    @staticmethod
    def _members(data: dict) -> dict[str, int | None]:
        active: dict[str, int | None] = {}
        for item in data.get("nftables", []):
            setting = item.get("set")
            if not isinstance(setting, dict):
                continue
            for element in setting.get("elem", []):
                if isinstance(element, str):
                    value, expires = element, None
                elif isinstance(element, dict):
                    part = element.get("elem", element)
                    if isinstance(part, dict):
                        value = part.get("val", part.get("value"))
                        duration = part.get("expires")
                        expires = max(0, int(duration) // 1000) if isinstance(duration, int) else None
                    else:
                        value, expires = part, None
                else:
                    continue
                if value in ATTACKERS:
                    active[value] = expires
        return active

    def _counters(self) -> tuple[int | None, int | None]:
        try:
            chain = self._run(["-j", "list", "chain", "inet", TABLE, CHAIN])
            for obj in json.loads(chain.stdout).get("nftables", []):
                for expr in obj.get("rule", {}).get("expr", []):
                    counter = expr.get("counter") if isinstance(expr, dict) else None
                    if isinstance(counter, dict):
                        packets, size = counter.get("packets"), counter.get("bytes")
                        if type(packets) is int and type(size) is int and packets >= 0 and size >= 0:
                            return packets, size
        except (ValueError, OSError, RuntimeError, KeyError, TypeError):
            pass
        return None, None

    def status(self, source: str) -> dict:
        validate_source(source)
        if not self._existing():
            return {"source": source, "active": False, "expires_in_seconds": None,
                    "enforcement": "UNAVAILABLE"}
        record = self._run(["-j", "list", "set", "inet", TABLE, SET])
        members = self._members(json.loads(record.stdout))
        packets, size = self._counters()
        return {"source": source, "active": source in members,
                "expires_in_seconds": members.get(source),
                "dropped_packets_total": packets,
                "dropped_bytes_total": size,
                "enforcement": "KERNEL_RULE_PRESENT" if source in members else "NO_RULE"}

    def block(self, source: str, ttl: int) -> dict:
        source = validate_source(source)
        ttl = validate_ttl(ttl)
        self.initialize()
        if self.status(source)["active"]:
            raise ValueError("An active block already exists; release it before replacing it")
        command = f"add element inet {TABLE} {SET} {{ {source} timeout {ttl}s }}\n"
        self._run(["-f", "-"], source=command)
        result = self.status(source)
        if not result["active"]:
            raise RuntimeError("Kernel did not report the installed timed block")
        return result

    def release(self, source: str) -> dict:
        source = validate_source(source)
        if not self._existing():
            return self.status(source)
        if self.status(source)["active"]:
            self._run(["-f", "-"], source=f"delete element inet {TABLE} {SET} {{ {source} }}\n")
        result = self.status(source)
        if result["active"]:
            raise RuntimeError("Kernel still reports a block after release")
        return result


GATE = NftGate()
GATE_MUTEX = threading.Lock()


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(4)
        try:
            line = self.rfile.readline(MAX_REQUEST + 1)
            if not line or len(line) > MAX_REQUEST:
                raise ValueError("Invalid request size")
            req = json.loads(line)
            if not isinstance(req, dict):
                raise ValueError("Invalid request")
            action = req.get("action")
            if action == "health":
                result = {"ready": True, "scope": "PC5 training web port only"}
            elif action == "status":
                with GATE_MUTEX:
                    result = GATE.status(validate_source(req.get("source")))
            elif action == "block":
                with GATE_MUTEX:
                    result = GATE.block(validate_source(req.get("source")), validate_ttl(req.get("ttl")))
            elif action == "release":
                with GATE_MUTEX:
                    result = GATE.release(validate_source(req.get("source")))
            else:
                raise ValueError("Unsupported action")
            answer = {"ok": True, **result}
        except (ValueError, KeyError, TypeError) as exc:
            answer = {"ok": False, "error": str(exc)[:160]}
        except (OSError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            answer = {"ok": False, "error": "Kernel enforcement unavailable"}
            print("[STAGE4] enforcement failure:", type(exc).__name__, str(exc)[:180], flush=True)
        self.wfile.write((json.dumps(answer, separators=(",", ":")) + "\n").encode())


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("PC2 mitigation helper must run via restricted root systemd unit")
    GATE.initialize()
    SOCKET_PATH.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(SOCKET_PATH.parent, 0, grp.getgrnam(GROUP).gr_gid)
    os.chmod(SOCKET_PATH.parent, 0o750)
    if SOCKET_PATH.exists():
        SOCKET_PATH.unlink()
    with Server(str(SOCKET_PATH), Handler) as server:
        os.chown(SOCKET_PATH, 0, grp.getgrnam(GROUP).gr_gid)
        os.chmod(SOCKET_PATH, 0o660)
        print("[STAGE4] scoped, time-expiring forward-only web gate ready", flush=True)
        try:
            server.serve_forever(poll_interval=0.25)
        finally:
            SOCKET_PATH.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
