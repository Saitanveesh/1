"""One-shot loopback login for a disposable MON lab session.

Never a production identity provider. A locally generated, signed operator JWT
is verified against the configured public key, then set as an HttpOnly cookie
by a short-lived, loopback-only HTTP endpoint. No network listener persists.
"""
from __future__ import annotations

import argparse
import re
import secrets
import stat
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlencode

import jwt


def _read_token(path: Path) -> str:
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or (stat.S_IMODE(details.st_mode) & 0o077):
        raise ValueError("operator token must be in a private mode-0600 regular file")
    token = path.read_text(encoding="utf-8").strip()
    if not 1 <= len(token) <= 3500 or any(x.isspace() for x in token):
        raise ValueError("operator token length/content invalid")
    return token


def verify_local_operator(
    token_path: Path, public_key_path: Path, *,
    issuer: str, audience: str, tenant: str, site: str,
) -> tuple[str, int]:
    for value in (tenant, site):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
            raise ValueError("invalid tenant/site scope")
    token = _read_token(token_path)
    decoded = jwt.decode(
        token, public_key_path.read_text(encoding="utf-8"),
        algorithms=["RS256"], issuer=issuer, audience=audience,
        options={"require": ["sub", "iat", "exp"]},
    )
    if (
        decoded.get("tenant_id") != tenant
        or "tenant_admin" not in decoded.get("roles", [])
        or (
            decoded.get("site_ids")
            and site not in decoded["site_ids"]
        )
    ):
        raise ValueError("signed token does not represent the requested lab operator")
    seconds_left = int(decoded["exp"] - time.time())
    if seconds_left <= 0:
        raise ValueError("operator token has expired")
    return token, min(seconds_left, 3600)


def make_login_handler(
    *, token: str, ttl: int, nonce: str, tenant: str, site: str,
    state: dict[str, bool],
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if (
                self.headers.get("Host") not in {
                    "127.0.0.1:9876", "localhost:9876",
                }
                or self.path != f"/lab-login/{nonce}"
                or state["used"]
            ):
                self.send_error(404)
                return
            state["used"] = True
            self.send_response(302)
            self.send_header(
                "Set-Cookie",
                f"mon_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ttl}",
            )
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Location",
                "http://127.0.0.1:8088/?" + urlencode({
                    "tenant": tenant, "site": site,
                }),
            )
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            # Never log credential-bearing response headers or the nonce URL.
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="One-time local-only signed lab operator session"
    )
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--public-key-file", type=Path, required=True)
    parser.add_argument("--issuer", default="mon-lab-local-only")
    parser.add_argument("--audience", default="mon-lab-control-plane")
    parser.add_argument("--tenant", default="mon-lab")
    parser.add_argument("--site", default="isolated-range")
    args = parser.parse_args(argv)
    try:
        token, ttl = verify_local_operator(
            args.token_file, args.public_key_file,
            issuer=args.issuer, audience=args.audience,
            tenant=args.tenant, site=args.site,
        )
    except (OSError, ValueError, jwt.PyJWTError) as exc:
        parser.exit(2, f"lab operator validation failed: {type(exc).__name__}\n")

    nonce = secrets.token_urlsafe(24)
    state = {"used": False}
    handler = make_login_handler(
        token=token, ttl=ttl, nonce=nonce,
        tenant=args.tenant, site=args.site, state=state,
    )
    with HTTPServer(("127.0.0.1", 9876), handler) as server:
        server.timeout = 1.0
        print("One-time MON lab login URL (loopback / SSH forwarded only):", flush=True)
        print(f"http://127.0.0.1:9876/lab-login/{nonce}", flush=True)
        print("Open this URL in your operator browser, then this listener exits.", flush=True)
        until = time.monotonic() + 180
        while not state["used"] and time.monotonic() < until:
            server.handle_request()
        if not state["used"]:
            raise SystemExit("login URL expired without being used")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
