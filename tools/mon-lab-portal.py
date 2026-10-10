#!/usr/bin/env python3
"""Local MON lab operator gateway + metadata-only WireGuard packet capture.

Only run on the controlled PC2 lab host. Credentials are supplied through a
scrypt password verifier; never place plaintext passwords in source or HTML.
Packet data are captured from a real Linux AF_PACKET socket, header-only,
without persisting traffic or payloads. Nothing here fabricates observations.
"""
from __future__ import annotations

import collections
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import socket
import struct
import threading
import time
from datetime import UTC, datetime
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

LISTEN = ("127.0.0.1", 8088)
INTERFACE = os.environ.get("MON_PORTAL_INTERFACE", "wg0")
ORIGIN = os.environ.get("MON_PORTAL_ORIGIN", "http://100.75.116.62:5173")
USERNAME = os.environ.get("MON_PORTAL_USERNAME", "sai")
VERIFIER = os.environ.get("MON_PORTAL_PASSWORD_HASH", "")
TOKEN_FILE = Path(
    os.environ.get(
        "MON_PORTAL_OPERATOR_TOKEN_FILE",
        str(Path.home() / "mon-three/identity/operator.jwt"),
    )
)
AUTH_WINDOW = 120
AUTH_ATTEMPTS = 5
WINDOW = 90


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    hashed = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32
    )
    return f"scrypt:{salt.hex()}:{hashed.hex()}"


def verify_password(password: str, verifier: str) -> bool:
    try:
        scheme, salt_hex, digest_hex = verifier.split(":")
        if scheme != "scrypt":
            return False
        candidate = hash_password(password, salt=bytes.fromhex(salt_hex))
        return hmac.compare_digest(candidate, verifier)
    except (ValueError, TypeError):
        return False


def parse_packet(data: bytes, packet_kind: int) -> tuple[str, str, str, int | None, int] | None:
    """Return IP endpoints and on-wire IP length, excluding outgoing duplicates."""
    if packet_kind == socket.PACKET_OUTGOING or not data:
        return None
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20:
            return None
        ihl = (data[0] & 15) * 4
        if ihl < 20 or len(data) < ihl:
            return None
        total = struct.unpack_from("!H", data, 2)[0]
        fragment = struct.unpack_from("!H", data, 6)[0]
        proto = data[9]
        src = str(ipaddress.IPv4Address(data[12:16]))
        dst = str(ipaddress.IPv4Address(data[16:20]))
        offset = ihl
        fragmented = bool(fragment & 0x1FFF)
        length = min(len(data), total) if total >= ihl else len(data)
    elif version == 6:
        if len(data) < 40:
            return None
        proto = data[6]
        src = str(ipaddress.IPv6Address(data[8:24]))
        dst = str(ipaddress.IPv6Address(data[24:40]))
        offset = 40
        # IPv6 extension headers require further decoding before extracting ports.
        fragmented = proto in (0, 43, 44, 50, 51, 60)
        length = min(len(data), 40 + struct.unpack_from("!H", data, 4)[0])
    else:
        return None
    name = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(proto, str(proto))
    port = None
    if not fragmented and proto in (6, 17) and len(data) >= offset + 4:
        port = struct.unpack_from("!H", data, offset + 2)[0]
    return src, dst, name, port, length


class FlowCapture:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.history: collections.deque[dict] = collections.deque(maxlen=WINDOW)
        self.current: collections.Counter[tuple[str, str, str, int | None]] = (
            collections.Counter()
        )
        self.bytes: collections.Counter[tuple[str, str, str, int | None]] = (
            collections.Counter()
        )
        self.current_start = int(time.time())
        self.error: str | None = None
        self.state = "STARTING"

    def _flush(self, epoch: int) -> None:
        if epoch <= self.current_start:
            return
        with self.lock:
            while self.current_start < epoch:
                rows = [
                    {
                        "src_ip": src, "dst_ip": dst, "protocol": proto,
                        "dst_port": port, "packets": packets,
                        "bytes": self.bytes[(src, dst, proto, port)],
                    }
                    for (src, dst, proto, port), packets in self.current.most_common(100)
                ]
                rows.sort(key=lambda row: row["bytes"], reverse=True)
                self.history.append({
                    "second": self.current_start,
                    "packets": sum(self.current.values()),
                    "bytes": sum(self.bytes.values()),
                    "flows": rows[:30],
                })
                self.current.clear()
                self.bytes.clear()
                self.current_start += 1

    def run(self) -> None:
        try:
            if not hasattr(socket, "AF_PACKET"):
                raise OSError("AF_PACKET is available on Linux only")
            # SOCK_DGRAM supplies layer-3 headers even on WireGuard's link type.
            with socket.socket(
                socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003)
            ) as reader:
                reader.bind((INTERFACE, 0))
                reader.settimeout(0.3)
                self.state = "CAPTURING"
                while True:
                    try:
                        packet, address = reader.recvfrom(65535)
                    except TimeoutError:
                        self._flush(int(time.time()))
                        continue
                    observation = parse_packet(packet, address[2])
                    self._flush(int(time.time()))
                    if observation is not None:
                        src, dst, proto, port, length = observation
                        key = src, dst, proto, port
                        with self.lock:
                            self.current[key] += 1
                            self.bytes[key] += length
        except Exception as exc:
            self.state = "UNAVAILABLE"
            self.error = str(exc)[:200]

    def snapshot(self) -> dict:
        self._flush(int(time.time()))
        with self.lock:
            samples = list(self.history)
            totals: collections.Counter[tuple[str, str, str, int | None]] = (
                collections.Counter()
            )
            bytes_: collections.Counter[tuple[str, str, str, int | None]] = (
                collections.Counter()
            )
            for sample in samples[-10:]:
                for row in sample["flows"]:
                    key = (
                        row["src_ip"], row["dst_ip"],
                        row["protocol"], row["dst_port"],
                    )
                    totals[key] += row["packets"]
                    bytes_[key] += row["bytes"]
            top = [
                {
                    "src_ip": k[0], "dst_ip": k[1], "protocol": k[2],
                    "dst_port": k[3], "packets": v, "bytes": bytes_[k],
                }
                for k, v in totals.most_common(30)
            ]
        return {
            "source": "linux-af_packet",
            "interface": INTERFACE,
            "status": self.state,
            "error": self.error,
            "observed_at": datetime.now(UTC).isoformat(),
            "sample_interval_seconds": 1,
            "capture_window_seconds": WINDOW,
            "direction": "incoming only; excludes forwarded outgoing duplicates",
            "packet_layer": "IP layer; no application payload captured",
            "samples": [{k: v for k, v in row.items() if k != "flows"} for row in samples],
            "flows": top,
        }


FLOW = FlowCapture()
FAILURES: collections.deque[float] = collections.deque()
FAILURE_LOCK = threading.Lock()


def operator_token() -> str:
    return TOKEN_FILE.read_text(encoding="utf-8").strip()


class Handler(BaseHTTPRequestHandler):
    server_version = "MONLabPortal/1"
    sys_version = ""

    def log_message(self, fmt: str, *args: object) -> None:
        # Do not log secrets, login bodies, or cookie headers.
        print(f"[PORTAL] {self.command} {urlsplit(self.path).path}", flush=True)

    def reply(
        self, status: int, payload: dict, *, cookie: str | None = None
    ) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _session(self) -> bool:
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
            value = jar.get("mon_session")
            if not value:
                return False
            return hmac.compare_digest(value.value, operator_token())
        except (ValueError, OSError):
            return False

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/portal/health":
            self.reply(HTTPStatus.OK, {"state": "READY", "capture": FLOW.state})
        elif path == "/portal/flows":
            if not self._session():
                self.reply(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"})
                return
            self.reply(HTTPStatus.OK, FLOW.snapshot())
        elif path == "/portal/session":
            self.reply(HTTPStatus.OK, {"authenticated": self._session()})
        else:
            self.reply(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path not in ("/portal/login", "/portal/logout"):
            self.reply(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if self.headers.get("Origin") != ORIGIN:
            self.reply(HTTPStatus.FORBIDDEN, {"error": "origin denied"})
            return
        if path == "/portal/logout":
            self.reply(
                HTTPStatus.OK, {"success": True},
                cookie="mon_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax",
            )
            return
        try:
            count = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            count = 0
        if count <= 0 or count > 2048 or not self.headers.get(
            "Content-Type", ""
        ).startswith("application/json"):
            self.reply(HTTPStatus.BAD_REQUEST, {"error": "invalid request"})
            return
        with FAILURE_LOCK:
            now = time.monotonic()
            while FAILURES and FAILURES[0] < now - AUTH_WINDOW:
                FAILURES.popleft()
            if len(FAILURES) >= AUTH_ATTEMPTS:
                self.reply(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {"error": "too many attempts; retry later"},
                )
                return
        try:
            data = json.loads(self.rfile.read(count))
            username = str(data.get("username", ""))
            password = str(data.get("password", ""))
        except (ValueError, AttributeError):
            username, password = "", ""
        valid_user = hmac.compare_digest(username, USERNAME)
        valid_password = verify_password(password, VERIFIER)
        if not valid_user or not valid_password:
            with FAILURE_LOCK:
                FAILURES.append(time.monotonic())
            self.reply(HTTPStatus.UNAUTHORIZED, {"error": "invalid credentials"})
            return
        try:
            token = operator_token()
        except OSError:
            self.reply(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "operator identity unavailable"})
            return
        # This local lab cookie uses the existing signed MON JWT; the control
        # plane remains responsible for signature, scope and expiry validation.
        self.reply(
            HTTPStatus.OK, {"success": True, "username": USERNAME},
            cookie=(
                f"mon_session={token}; HttpOnly; Path=/; SameSite=Lax; "
                "Max-Age=3600"
            ),
        )


def main() -> None:
    if not VERIFIER.startswith("scrypt:"):
        raise RuntimeError("MON_PORTAL_PASSWORD_HASH must be provisioned")
    if not TOKEN_FILE.is_file():
        raise RuntimeError("operator JWT file unavailable")
    threading.Thread(target=FLOW.run, daemon=True, name="wg0-flow-capture").start()
    with ThreadingHTTPServer(LISTEN, Handler) as app:
        app.daemon_threads = True
        print(
            f"MON lab portal listening on {LISTEN}; capture={INTERFACE}; origin={ORIGIN}",
            flush=True,
        )
        app.serve_forever()


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2 and sys.argv[1] == "--hash-password":
        from getpass import getpass

        password = getpass("MON lab password: ")
        if not password:
            raise SystemExit("empty passwords are not allowed")
        print(hash_password(password))
    else:
        main()
