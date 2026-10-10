#!/usr/bin/env python3
"""CI smoke: genuine Node/Vite reverse-proxy round trip to a local MON pairing server.

Uses only fake test credentials. The real MON API is not touched, and the
test's localhost-only servers are always terminated on exit.
"""
from __future__ import annotations

import http.client
import http.server
import importlib.util
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONSOLE = HERE.parent / "console"


def load_login():
    spec = importlib.util.spec_from_file_location(
        "mon_vite_proxy_test_login", HERE / "lab_browser_login.py"
    )
    if not spec or not spec.loader:
        raise RuntimeError("login module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def issue(method: str, path: str, body: str | None = None, *, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", 5173, timeout=3)
    conn.request(method, path, body, headers=headers or {})
    resp = conn.getresponse()
    content = resp.read().decode("utf-8")
    headers_out = {name.lower(): value for name, value in resp.getheaders()}
    status = resp.status
    conn.close()
    return status, content, headers_out


def main() -> int:
    if os.name != "posix":
        raise RuntimeError("this smoke test uses Linux process-group cleanup")
    mod = load_login()
    # This test must never use or expose a real operator JWT.
    mod.validate_operator = lambda token: (
        {"roles": ["tenant_admin"], "tenant_id": "mon-lab"}
        if token == "ci-fake-signed-token" else RuntimeError("invalid")
    )
    session = mod.PairingState(
        token="ci-fake-signed-token",
        expected_origin="http://127.0.0.1:5173",
        challenge="ci-test-code-not-a-real-credential-1234",
    )
    server = http.server.HTTPServer(("127.0.0.1", 8766), mod.make_handler(session))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    vite = None
    try:
        vite = subprocess.Popen(
            ["npm", "run", "dev", "--", "--host", "127.0.0.1",
             "--port", "5173", "--strictPort"],
            cwd=CONSOLE, stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        for _ in range(75):
            if vite.poll() is not None:
                raise RuntimeError("Vite exited before proxy health could be checked")
            try:
                status, page, headers = issue("GET", "/lab-session/")
                if status == 200 and "Operator sign-in" in page:
                    break
            except (ConnectionError, OSError, TimeoutError):
                pass
            time.sleep(0.2)
        else:
            raise RuntimeError("Vite pairing proxy did not return the real form")

        assert "ci-fake-signed-token" not in page
        assert "no-store" in headers.get("cache-control", "")
        nonce_match = re.search(r"name='form_nonce' value='([^']+)'", page)
        if not nonce_match:
            raise RuntimeError("proxied login form has no one-time nonce")
        body = urllib.parse.urlencode({
            "code": session.challenge,
            "form_nonce": nonce_match.group(1),
        })
        status, response, headers = issue(
            "POST", "/lab-session/claim", body,
            headers={
                "Origin": "http://127.0.0.1:5173",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert status == 303, f"Vite proxy login returned HTTP {status}: {response!r}"
        assert headers.get("location") == "/?tenant=mon-lab&site=site-a", headers
        cookie = headers.get("set-cookie", "")
        assert "mon_session=ci-fake-signed-token" in cookie
        assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
        assert session.used
        print("Vite proxy + pairing form + signed session cookie: PASS")
        return 0
    finally:
        if vite and vite.poll() is None:
            os.killpg(vite.pid, signal.SIGTERM)
            try:
                vite.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(vite.pid, signal.SIGKILL)
                vite.wait(timeout=5)
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    raise SystemExit(main())
