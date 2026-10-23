#!/usr/bin/env python3
"""PC-5 local-only training web server. Never expose to the public Internet.

The /download endpoint deliberately fails to confine requested paths to
public/. It is STILL constrained to this training directory, so it cannot
return arbitrary PC-5 files. All identities and canary files are fictitious.
"""
from __future__ import annotations

import json
import os
import secrets
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

BASE = Path(__file__).resolve().parent
PUBLIC = BASE / "public"
HOST = os.environ.get("MON_TRAINING_BIND", "127.0.0.1")
PORT = int(os.environ.get("MON_TRAINING_PORT", "8085"))


class Handler(BaseHTTPRequestHandler):
    server_version = "MONTrainingSite/1"
    sys_version = ""

    def respond(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        request_id = secrets.token_hex(6)
        response_status = HTTPStatus.OK
        try:
            if url.path in ("/", "/index.html"):
                self.respond(HTTPStatus.OK, (PUBLIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            elif url.path == "/health":
                self.respond(HTTPStatus.OK, b'{"status":"READY","training":true}', "application/json")
            elif url.path == "/download":
                filename = parse_qs(url.query).get("file", [""])[0]
                # Intentional lab flaw: validates against BASE instead of PUBLIC,
                # permitting ../training-private/* within this isolated directory.
                # No paths outside BASE and no symlink traversal are permitted.
                target = (PUBLIC / filename).resolve()
                if not target.is_relative_to(BASE) or not target.is_file():
                    response_status = HTTPStatus.NOT_FOUND
                    self.respond(response_status, b"Document not found", "text/plain; charset=utf-8")
                elif target.suffix not in {".txt", ".md"}:
                    response_status = HTTPStatus.FORBIDDEN
                    self.respond(response_status, b"Training documents only", "text/plain; charset=utf-8")
                else:
                    self.respond(HTTPStatus.OK, target.read_bytes()[:16384], "text/plain; charset=utf-8")
            else:
                response_status = HTTPStatus.NOT_FOUND
                self.respond(response_status, b"Page not found", "text/plain; charset=utf-8")
        except (OSError, ValueError):
            response_status = HTTPStatus.INTERNAL_SERVER_ERROR
            self.respond(response_status, b"Training site unavailable", "text/plain; charset=utf-8")
        finally:
            # Local console evidence: source is the actual socket peer.
            # Only the route is logged, not credential-like query contents.
            print(json.dumps({
                "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "request_id": request_id,
                "src_ip": self.client_address[0],
                "route": url.path,
                "http_status": int(response_status),
                "lab_only": True,
            }), flush=True)


def main() -> None:
    if HOST == "0.0.0.0" and os.environ.get("MON_TRAINING_ALLOW_ALL_INTERFACES") != "1":
        raise SystemExit("Refusing all-interface bind without explicit lab authorization")
    print(f"MON training website on http://{HOST}:{PORT} (isolated fake data only)", flush=True)
    with ThreadingHTTPServer((HOST, PORT), Handler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
