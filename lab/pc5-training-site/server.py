#!/usr/bin/env python3
"""Fictional, deliberately vulnerable MON training website on PC-5 only.

Educational vulnerabilities exist ONLY inside memory/fake files:
  - SQL injection in an in-memory, read-only-to-requests SQLite notice search
  - IDOR returning one of four deliberately fabricated student records
  - scoped path traversal reading a fictional canary under this directory
  - toy sign-in attempts (not real credentials or authentication)
No real user records, college service, host file or database is accessed.
"""
from __future__ import annotations

import collections
import ipaddress
import json
import os
import secrets
import sqlite3
import threading
import time
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

BASE = Path(__file__).resolve().parent
PUBLIC = BASE / "public"
HOST = os.environ.get("MON_TRAINING_BIND", "127.0.0.1")
PORT = int(os.environ.get("MON_TRAINING_PORT", "8085"))
MAX_BODY = 4096
LAB_NET = ipaddress.ip_network("10.77.0.0/24")
RATE_LOCK = threading.Lock()
REQUESTS: dict[str, collections.deque[float]] = collections.defaultdict(collections.deque)

# All identities, notices and details below are invented lab fixtures.
STUDENTS = {
    "STU-1001": {"student_id": "STU-1001", "name": "Aarya Example",
                 "department": "Aerospace", "semester": 5, "lab_token": "FAKE-AERO-1001"},
    "STU-1002": {"student_id": "STU-1002", "name": "Rohan Sample",
                 "department": "Computing", "semester": 3, "lab_token": "FAKE-COMP-1002"},
    "STU-1003": {"student_id": "STU-1003", "name": "Kavya Fiction",
                 "department": "Electronics", "semester": 7, "lab_token": "FAKE-ELX-1003"},
    "STU-1004": {"student_id": "STU-1004", "name": "Neel Demo",
                 "department": "Mechanical", "semester": 1, "lab_token": "FAKE-MECH-1004"},
}
NOTICES = [
    (1, "Semester timetable", "Academics", "Public"),
    (2, "Robotics lab orientation", "Research", "Public"),
    (3, "Library opening hours", "Campus", "Public"),
    (4, "Synthetic staff draft", "Staff simulation", "FAKE INTERNAL"),
    (5, "Prototype badge test", "Lab simulation", "FAKE INTERNAL"),
]
TOY_IDENTITIES = {"demo.student": "labpass-1001", "demo.operator": "labpass-2002"}


def source_allowed(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
        return address.is_loopback or address in LAB_NET
    except ValueError:
        return False


def allow_request(ip: str, now: float | None = None) -> bool:
    stamp = time.monotonic() if now is None else now
    with RATE_LOCK:
        bucket = REQUESTS[ip]
        while bucket and stamp - bucket[0] > 60:
            bucket.popleft()
        if len(bucket) >= 90:  # bounded controlled lab tests
            return False
        bucket.append(stamp)
    return True


def unsafe_notice_search(query: str) -> list[dict]:
    """INTENTIONAL SQLi. SQLite exists only in RAM and contains fake fixtures."""
    with sqlite3.connect(":memory:") as conn:
        conn.execute(
            "CREATE TABLE notices (id INTEGER, headline TEXT, category TEXT, visibility TEXT)"
        )
        conn.executemany("INSERT INTO notices VALUES (?, ?, ?, ?)", NOTICES)
        # No write access through this handler and sqlite3.execute rejects
        # multiple statements. The concatenation is the deliberate exercise.
        sql = "SELECT id, headline, category, visibility FROM notices WHERE headline LIKE '%" + query + "%' LIMIT 20"
        rows = conn.execute(sql).fetchall()
    return [
        {"id": row[0], "headline": row[1], "category": row[2], "visibility": row[3]}
        for row in rows
    ]


class Handler(BaseHTTPRequestHandler):
    server_version = "MONTrainingSite/2"
    sys_version = ""

    def respond(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; object-src 'none'")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def json_reply(self, status: int, payload: dict) -> None:
        self.respond(status, json.dumps(payload, separators=(",", ":")).encode(), "application/json")

    def log_message(self, fmt: str, *args: object) -> None:
        # Full request URLs, SQLi payloads and login attempts are intentionally
        # not sent to ordinary service logs; JSON metadata follows below.
        return

    def allowed(self) -> bool:
        remote = self.client_address[0]
        if not source_allowed(remote):
            self.json_reply(HTTPStatus.FORBIDDEN, {"error": "lab overlay only"})
            return False
        if not allow_request(remote):
            self.json_reply(HTTPStatus.TOO_MANY_REQUESTS, {"error": "lab rate limit"})
            return False
        return True

    def log_evidence(self, route: str, status: int, request_id: str) -> None:
        # Server-side corroboration: real socket remote address and status,
        # never a synthetic source IP, credentials or raw SQL query.
        print(json.dumps({
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "request_id": request_id,
            "src_ip": self.client_address[0],
            "route": route,
            "http_status": int(status),
            "lab_only": True,
        }), flush=True)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        request_id = secrets.token_hex(6)
        status = HTTPStatus.OK
        if not self.allowed():
            return
        query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        try:
            if path in ("/", "/index.html"):
                self.respond(status, (PUBLIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            elif path == "/app.js":
                self.respond(status, (PUBLIC / "app.js").read_bytes(), "application/javascript; charset=utf-8")
            elif path == "/health":
                self.json_reply(status, {"status": "READY", "training": True, "version": 2})
            elif path == "/api/notices":
                search = query.get("q", [""])[0][:160]
                try:
                    rows = unsafe_notice_search(search)
                    self.json_reply(status, {"results": rows, "count": len(rows), "fixture_only": True})
                except sqlite3.Error:
                    status = HTTPStatus.BAD_REQUEST
                    self.json_reply(status, {"error": "invalid training SQL query", "fixture_only": True})
            elif path == "/api/student":
                requested = query.get("id", [""])[0][:40]
                viewer = query.get("viewer", [""])[0][:40]
                # INTENTIONAL IDOR: accepts a claimed viewer but never checks
                # that requested belongs to viewer. Only synthetic records exist.
                if requested not in STUDENTS:
                    status = HTTPStatus.NOT_FOUND
                    self.json_reply(status, {"error": "no such fictional record"})
                else:
                    self.json_reply(status, {
                        "viewer_claim": viewer or "UNVERIFIED",
                        "record": STUDENTS[requested],
                        "fixture_only": True,
                    })
            elif path == "/download":
                filename = query.get("file", [""])[0]
                # INTENTIONAL lab traversal: checks BASE rather than PUBLIC.
                # Never permits a path outside this isolated fake-data tree.
                target = (PUBLIC / filename).resolve()
                if not target.is_relative_to(BASE) or not target.is_file():
                    status = HTTPStatus.NOT_FOUND
                    self.respond(status, b"Document not found", "text/plain; charset=utf-8")
                elif target.suffix not in {".txt", ".md"}:
                    status = HTTPStatus.FORBIDDEN
                    self.respond(status, b"Training documents only", "text/plain; charset=utf-8")
                else:
                    self.respond(status, target.read_bytes()[:16384], "text/plain; charset=utf-8")
            else:
                status = HTTPStatus.NOT_FOUND
                self.json_reply(status, {"error": "route not found"})
        except (OSError, ValueError):
            status = HTTPStatus.INTERNAL_SERVER_ERROR
            self.json_reply(status, {"error": "fictional lab site unavailable"})
        finally:
            self.log_evidence(path, status, request_id)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        request_id = secrets.token_hex(6)
        status = HTTPStatus.UNAUTHORIZED
        if not self.allowed():
            return
        try:
            if path != "/api/login":
                status = HTTPStatus.NOT_FOUND
                self.json_reply(status, {"error": "route not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if not 1 <= length <= MAX_BODY or not self.headers.get("Content-Type", "").startswith("application/json"):
                status = HTTPStatus.BAD_REQUEST
                self.json_reply(status, {"error": "invalid lab login request"})
                return
            try:
                data = json.loads(self.rfile.read(length))
                username, password = data["username"], data["password"]
                if not isinstance(username, str) or not isinstance(password, str):
                    raise ValueError
            except (ValueError, TypeError, KeyError, AttributeError):
                status = HTTPStatus.BAD_REQUEST
                self.json_reply(status, {"error": "invalid lab credentials format"})
                return
            # Toy identity check. No sessions, cookies or production logins.
            if username in TOY_IDENTITIES and secrets.compare_digest(TOY_IDENTITIES[username], password):
                status = HTTPStatus.OK
                self.json_reply(status, {"message": "fictional training login accepted", "fixture_only": True})
            else:
                status = HTTPStatus.UNAUTHORIZED
                self.json_reply(status, {"error": "fictional training login denied"})
        finally:
            self.log_evidence(path, status, request_id)


def main() -> None:
    address = ipaddress.ip_address(HOST)
    if not address.is_loopback and address != ipaddress.ip_address("10.77.0.50"):
        raise SystemExit("Training website must bind only loopback or PC-5 wg0 10.77.0.50")
    if not 1 <= PORT <= 65535:
        raise SystemExit("Invalid training port")
    print(f"MON fictional campus training website on http://{HOST}:{PORT} (fake data only)", flush=True)
    with ThreadingHTTPServer((HOST, PORT), Handler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
