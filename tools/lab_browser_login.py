#!/usr/bin/env python3
"""Disposable lab only: one-use localhost pairing into MON's signed HttpOnly session.

Vite proxies /lab-session/ to localhost:8766. Requires existing signed operator JWT
validated by the running control plane. Not OIDC or a production login service.
"""
from __future__ import annotations

import argparse
import http.server
import ipaddress
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MAX_BODY_BYTES = 256
MAX_ATTEMPTS = 5
PAIR_TTL_SECONDS = 600
AUTH_URL = "http://127.0.0.1:8080/api/v1/me"


def validate_operator(token: str) -> dict:
    """Require real signed-JWT validation and a tenant_admin/operator role."""
    if not token or len(token) > 16384:
        raise RuntimeError("missing or oversized operator credential")
    request = urllib.request.Request(
        AUTH_URL,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=4) as response:
            principal = json.loads(response.read(16384))
    except (urllib.error.URLError, ValueError, OSError) as exc:
        raise RuntimeError("MON refused the operator credential") from exc
    if not isinstance(principal, dict):
        raise RuntimeError("MON operator identity response invalid")
    roles = principal.get("roles")
    if (principal.get("tenant_id") != "mon-lab"
            or not isinstance(roles, list)
            or "tenant_admin" not in roles):
        raise RuntimeError("MON operator credential lacks lab tenant_admin scope")
    return principal


class PairingState:
    def __init__(
        self,
        *,
        token: str,
        expected_origin: str,
        challenge: str,
        started: float | None = None,
    ) -> None:
        self.token = token
        self.expected_origin = expected_origin
        self.challenge = challenge
        # Form nonce prevents blind third-party POSTs; kept only in server memory.
        self.form_nonce = secrets.token_urlsafe(32)
        self.expires_at = (time.monotonic() if started is None else started) + PAIR_TTL_SECONDS
        self.attempts = 0
        self.used = False
        self.failure_reason = "Pairing is unavailable or expired"
        self.cookie_max_age = 3600

    def active(self) -> bool:
        return not self.used and self.attempts < MAX_ATTEMPTS and time.monotonic() < self.expires_at

    def claim(self, *, challenge: str, form_nonce: str) -> bool:
        """Redeem a code only with the nonce from the currently served login form.

        The login service binds to PC2 loopback, reached only via the Vite
        proxy. Browser Origin/Fetch-Metadata headers are intentionally NOT
        authentication factors: Vite may rewrite or strip them. Security here
        comes from two independent unpredictable values, single redemption,
        expiration, bounded retries and MON's real signed JWT verification.
        """
        if not self.active():
            self.failure_reason = "This sign-in code has expired. Request a new code."
            return False
        self.attempts += 1
        if not secrets.compare_digest(form_nonce, self.form_nonce):
            self.failure_reason = "Sign-in form expired. Refresh the page and try again."
            return False
        if not secrets.compare_digest(challenge, self.challenge):
            self.failure_reason = "Incorrect code. Check the terminal and try again."
            return False
        validate_operator(self.token)
        self.used = True
        return True


def make_handler(state: PairingState):
    class LoginHandler(http.server.BaseHTTPRequestHandler):
        server_version = "MONLabSession/1"
        sys_version = ""

        def log_message(self, format: str, *args: object) -> None:
            # Suppress URLs, form contents, credentials and client details.
            pass

        def headers_safe(self) -> None:
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; "
                "form-action 'self'; base-uri 'none'",
            )

        def response(self, status: int, message: str, *, cookie: bool = False) -> None:
            encoded = message.encode("utf-8")
            self.send_response(status)
            self.headers_safe()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            if cookie:
                self.send_header(
                    "Set-Cookie",
                    f"mon_session={state.token}; Path=/; HttpOnly; SameSite=Strict; "
                    f"Max-Age={state.cookie_max_age}",
                )
            if status == 303:
                self.send_header("Location", "/?tenant=mon-lab&site=site-a")
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:
            if self.path not in ("/lab-session/", "/lab-session"):
                self.response(404, "Not found")
                return
            if not state.active():
                self.response(410, "Pairing expired or already redeemed. Restart pairing from PC2.")
                return
            page = (
                "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
                "<meta name='viewport' content='width=device-width, initial-scale=1'>"
                "<title>MON | Sign in</title></head>"
                "<body style='background:#f8f8f8;color:#111;font:16px system-ui;margin:0'>"
                "<main style='max-width:390px;margin:10vh auto;padding:30px;"
                "background:white;border:1px solid #ddd'>"
                "<div style='font-weight:800;letter-spacing:.12em'>MON</div>"
                "<div style='font-size:12px;letter-spacing:.15em;margin:8px 0 30px'>"
                "SECURITY FABRIC</div>"
                "<div style='font-size:12px;line-height:1.6;color:#555;margin-bottom:22px'>"
                "Monitoring · Orchestration · Neutralization</div>"
                "<h1 style='font-size:25px'>Operator sign-in</h1>"
                "<p>Enter the one-time access code from your operator terminal.</p>"
                "<form method='POST' action='/lab-session/claim'>"
                f"<input type='hidden' name='form_nonce' value='{state.form_nonce}'>"
                "<label for='code'>Access code</label>"
                "<input id='code' name='code' type='password' autocomplete='off' "
                "required minlength='20' maxlength='128' "
                "style='box-sizing:border-box;width:100%;padding:12px;"
                "border:1px solid #888;margin:8px 0 20px'>"
                "<button type='submit' style='width:100%;background:#111;color:#fff;"
                "padding:13px;border:0;cursor:pointer'>Sign in</button></form>"
                "</main></body></html>"
            )
            self.response(200, page)

        def do_POST(self) -> None:
            if self.path != "/lab-session/claim":
                self.response(404, "Not found")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.response(400, "Invalid request")
                return
            if (
                length <= 0
                or length > MAX_BODY_BYTES
                or self.headers.get("Content-Type", "").split(";", 1)[0].strip()
                != "application/x-www-form-urlencoded"
            ):
                self.response(400, "Invalid request")
                return
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            parsed = urllib.parse.parse_qs(body, strict_parsing=True)
            values = parsed.get("code", [])
            nonces = parsed.get("form_nonce", [])
            if len(values) != 1 or len(nonces) != 1:
                self.response(400, "Missing required login form fields")
                return
            try:
                accepted = state.claim(
                    challenge=values[0],
                    form_nonce=nonces[0],
                )
            except RuntimeError:
                self.response(503, "Operator credential expired or MON auth unavailable")
                return
            if not accepted:
                self.response(403 if state.active() else 410, state.failure_reason)
                return
            self.response(303, "Signed operator session established.", cookie=True)

    return LoginHandler


def serve(state: PairingState, host: str = "127.0.0.1", port: int = 8766) -> None:
    if host != "127.0.0.1":
        raise RuntimeError("the browser pairing server must bind only to loopback")
    with http.server.HTTPServer((host, port), make_handler(state)) as server:
        server.timeout = 1.0
        print(
            f"Pairing URL: {state.expected_origin}/lab-session/\n"
            f"One-time pairing code: {state.challenge}\n"
            "Expires in 10 minutes. Do not post this code or any JWT in chat.",
            flush=True,
        )
        while state.active():
            server.handle_request()
    state.token = ""
    state.challenge = ""
    state.form_nonce = ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator-jwt", required=True, type=Path)
    parser.add_argument("--tail-ip", required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("run pairing as the unprivileged PC2 operator, never root")
    try:
        parsed_ip = ipaddress.IPv4Address(args.tail_ip)
        if parsed_ip not in ipaddress.IPv4Network("100.64.0.0/10"):
            raise ValueError("expected an address in the Tailscale CGNAT range")
    except ValueError as exc:
        parser.error(f"invalid tailnet address: {exc}")
    path = args.operator_jwt.expanduser()
    stat = path.stat()
    if stat.st_uid != os.geteuid() or stat.st_mode & 0o077:
        parser.error("operator credential must be owner-only and not accessible to other users")
    token = path.read_text(encoding="utf-8").strip()
    try:
        validate_operator(token)
        serve(PairingState(
            token=token,
            challenge=secrets.token_urlsafe(32),
            expected_origin=f"http://{args.tail_ip}:5173",
        ))
    except (RuntimeError, OSError) as exc:
        print(f"Lab browser session unavailable: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
