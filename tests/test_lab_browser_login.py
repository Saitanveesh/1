from __future__ import annotations

import http.client
import http.server
import importlib.util
import json
import sys
import threading
import time
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "lab_browser_login.py"


def module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("mon_lab_browser_login", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def pairing_state(mod):
    return mod.PairingState(
        token="signed-jwt-not-a-real-secret",
        expected_origin="http://100.75.116.62:5173",
        challenge="example-one-use-256-bit-random-code",
    )


def test_pairing_is_nonce_bound_one_use_and_still_validates_real_mon_operator(
    monkeypatch,
) -> None:
    mod = module()
    seen = []
    monkeypatch.setattr(mod, "validate_operator", lambda token: seen.append(token))
    state = pairing_state(mod)
    assert not state.claim(challenge=state.challenge, form_nonce="wrong")
    assert not state.claim(challenge="wrong", form_nonce=state.form_nonce)
    assert seen == []
    assert state.claim(challenge=state.challenge, form_nonce=state.form_nonce)
    assert seen == ["signed-jwt-not-a-real-secret"]
    assert not state.claim(challenge=state.challenge, form_nonce=state.form_nonce)
    assert state.used


def test_pairing_expiry_and_failed_attempt_cap() -> None:
    mod = module()
    expired = pairing_state(mod)
    expired.expires_at = time.monotonic() - 1
    assert not expired.claim(challenge=expired.challenge, form_nonce=expired.form_nonce)

    exhausted = pairing_state(mod)
    for _ in range(mod.MAX_ATTEMPTS):
        assert not exhausted.claim(challenge="bad", form_nonce=exhausted.form_nonce)
    assert not exhausted.active()
    assert not exhausted.claim(
        challenge=exhausted.challenge, form_nonce=exhausted.form_nonce
    )


def test_mon_api_must_validate_signed_jwt_and_tenant_admin(monkeypatch) -> None:
    mod = module()

    class FakeReply:
        def __init__(self, payload):
            self.payload = payload

        def read(self, limit):
            assert limit <= 16384
            return json.dumps(self.payload).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    payload = {"subject": "operator", "tenant_id": "mon-lab", "roles": ["tenant_admin"]}

    def fake_urlopen(request, timeout):
        assert request.full_url == "http://127.0.0.1:8080/api/v1/me"
        assert request.headers["Authorization"] == "Bearer jwt-not-a-real-secret"
        return FakeReply(payload)

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake_urlopen)
    assert mod.validate_operator("jwt-not-a-real-secret")["subject"] == "operator"

    for item in [
        {"tenant_id": "different", "roles": ["tenant_admin"]},
        {"tenant_id": "mon-lab", "roles": ["viewer"]},
    ]:
        payload = item
        with pytest.raises(RuntimeError, match="lacks lab tenant_admin"):
            mod.validate_operator("jwt-not-a-real-secret")


@pytest.mark.parametrize(
    "headers",
    [
        {},  # HTTP reverse proxies and browsers may omit Origin and Fetch Metadata.
        {"Origin": "http://127.0.0.1:8766"},
        {"Origin": "http://100.75.116.62:5173", "Sec-Fetch-Site": "same-origin"},
        {"Origin": "http://unexpected.invalid", "Sec-Fetch-Site": "cross-site"},
    ],
)
def test_login_via_proxy_ignores_unreliable_headers_but_requires_both_secrets(
    monkeypatch, headers
) -> None:
    """Full local HTTP path: the form and one-time nonce prevent blind POSTs."""
    mod = module()
    state = pairing_state(mod)
    verified = []
    monkeypatch.setattr(mod, "validate_operator", lambda t: verified.append(t))
    server = http.server.HTTPServer(("127.0.0.1", 0), mod.make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        client.request("GET", "/lab-session/")
        response = client.getresponse()
        page = response.read().decode()
        assert response.status == 200
        assert "Operator sign-in" in page
        assert "Private signing key" not in page
        assert f"name='form_nonce' value='{state.form_nonce}'" in page
        assert "signed-jwt-not-a-real-secret" not in page
        assert response.getheader("Cache-Control") == "no-store"

        client.request(
            "POST",
            "/lab-session/claim",
            "code=" + state.challenge + "&form_nonce=" + state.form_nonce,
            headers={"Content-Type": "application/x-www-form-urlencoded", **headers},
        )
        claimed = client.getresponse()
        body = claimed.read().decode()
        assert claimed.status == 303
        assert claimed.getheader("Location") == "/?tenant=mon-lab&site=site-a"
        cookie = claimed.getheader("Set-Cookie", "")
        assert cookie.startswith("mon_session=signed-jwt-not-a-real-secret;")
        assert "HttpOnly" in cookie
        assert "SameSite=Strict" in cookie
        assert "Max-Age=3600" in cookie
        assert "signed-jwt-not-a-real-secret" not in body
        assert verified == ["signed-jwt-not-a-real-secret"]

        client.request(
            "POST",
            "/lab-session/claim",
            "code=" + state.challenge + "&form_nonce=" + state.form_nonce,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        replay = client.getresponse()
        replay.read()
        assert replay.status == 410
        assert replay.getheader("Set-Cookie") is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_cookie_is_never_issued_without_valid_code_and_nonce(monkeypatch) -> None:
    mod = module()
    state = pairing_state(mod)
    verified = []
    monkeypatch.setattr(mod, "validate_operator", lambda t: verified.append(t))
    server = http.server.HTTPServer(("127.0.0.1", 0), mod.make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        for form in [
            "code=" + state.challenge + "&form_nonce=wrong",
            "code=wrong&form_nonce=" + state.form_nonce,
            "code=" + state.challenge,
        ]:
            client.request(
                "POST",
                "/lab-session/claim",
                form,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            denied = client.getresponse()
            denied.read()
            assert denied.status in (400, 403)
            assert denied.getheader("Set-Cookie") is None
        assert verified == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_pairing_server_never_binds_public_interface() -> None:
    mod = module()
    with pytest.raises(RuntimeError, match="loopback"):
        mod.serve(pairing_state(mod), host="0.0.0.0", port=0)


def test_oversized_form_rejected_without_cookie(monkeypatch) -> None:
    mod = module()
    state = pairing_state(mod)
    monkeypatch.setattr(mod, "validate_operator", lambda _: {"roles": ["tenant_admin"]})
    server = http.server.HTTPServer(("127.0.0.1", 0), mod.make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        client.request(
            "POST", "/lab-session/claim", "a" * 300,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        rejected = client.getresponse()
        rejected.read()
        assert rejected.status == 400
        assert rejected.getheader("Set-Cookie") is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
