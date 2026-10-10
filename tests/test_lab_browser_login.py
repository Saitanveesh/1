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


def state(mod) -> object:
    return mod.PairingState(
        token="signed-jwt-do-not-expose",
        expected_origin="http://100.75.116.62:5173",
        challenge="temporary-one-use-256-bit-random-code",
    )


def test_pairing_requires_matching_code_and_origin_and_real_operator(monkeypatch) -> None:
    mod = module()
    validated = []
    monkeypatch.setattr(mod, "validate_operator", lambda token: validated.append(token))
    pairing = state(mod)
    assert not pairing.claim(
        challenge="wrong", form_nonce=pairing.form_nonce,
        origin=pairing.expected_origin, fetch_site="same-origin",
    )
    assert not pairing.claim(
        challenge=pairing.challenge, form_nonce=pairing.form_nonce,
        origin="http://attacker.invalid", fetch_site="cross-site",
    )
    assert pairing.active()
    assert pairing.claim(
        challenge=pairing.challenge, form_nonce=pairing.form_nonce,
        origin=pairing.expected_origin, fetch_site="same-origin",
    )
    assert validated == ["signed-jwt-do-not-expose"]
    assert not pairing.claim(
        challenge=pairing.challenge, form_nonce=pairing.form_nonce,
        origin=pairing.expected_origin, fetch_site="same-origin",
    )
    assert not pairing.active()


def test_pairing_expires_and_locks_out_five_failures(monkeypatch) -> None:
    mod = module()
    expired = state(mod)
    expired.expires_at = time.monotonic() - 1
    assert not expired.claim(
        challenge=expired.challenge, form_nonce=expired.form_nonce,
        origin=expired.expected_origin, fetch_site="same-origin",
    )
    assert not expired.active()

    locked = state(mod)
    for _ in range(mod.MAX_ATTEMPTS):
        assert not locked.claim(
            challenge="wrong", form_nonce=locked.form_nonce,
            origin=locked.expected_origin, fetch_site="same-origin",
        )
    assert not locked.active()
    assert not locked.claim(
        challenge=locked.challenge, form_nonce=locked.form_nonce,
        origin=locked.expected_origin, fetch_site="same-origin",
    )


def test_operator_validation_checks_issuer_verified_identity(monkeypatch) -> None:
    mod = module()

    class FakeReply:
        def __init__(self, body):
            self.body = body

        def read(self, limit):
            assert limit <= 16384
            return json.dumps(self.body).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    def fake_urlopen(request, timeout):
        assert request.full_url == "http://127.0.0.1:8080/api/v1/me"
        assert request.headers["Authorization"] == "Bearer jwt-not-a-real-credential"
        return FakeReply({"tenant_id": "mon-lab", "roles": ["tenant_admin"], "subject": "operator"})

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake_urlopen)
    principal = mod.validate_operator("jwt-not-a-real-credential")
    assert principal["subject"] == "operator"


def test_operator_validation_rejects_wrong_tenant_or_role(monkeypatch) -> None:
    mod = module()

    class FakeReply:
        def __init__(self, payload):
            self.payload = payload

        def read(self, _):
            return json.dumps(self.payload).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    for payload in [
        {"tenant_id": "tenant-b", "roles": ["tenant_admin"]},
        {"tenant_id": "mon-lab", "roles": ["viewer"]},
    ]:
        monkeypatch.setattr(
            mod.urllib.request,
            "urlopen",
            lambda *_args, payload=payload, **_kw: FakeReply(payload),
        )
        with pytest.raises(RuntimeError, match="lacks lab tenant_admin"):
            mod.validate_operator("signed-jwt")


def test_http_claim_sets_http_only_cookie_once_and_does_not_echo_jwt(monkeypatch) -> None:
    mod = module()
    pairing = state(mod)
    monkeypatch.setattr(mod, "validate_operator", lambda _: {"roles": ["tenant_admin"]})
    server = http.server.HTTPServer(("127.0.0.1", 0), mod.make_handler(pairing))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        client.request("GET", "/lab-session/")
        login_form = client.getresponse()
        body = login_form.read().decode()
        assert login_form.status == 200
        assert "<form" in body
        assert "signed-jwt-do-not-expose" not in body
        assert f"name='form_nonce' value='{pairing.form_nonce}'" in body
        assert login_form.getheader("Cache-Control") == "no-store"

        client.request(
            "POST", "/lab-session/claim",
            "code=" + pairing.challenge + "&form_nonce=" + pairing.form_nonce,
            headers={
                "Origin": pairing.expected_origin,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        response = client.getresponse()
        text = response.read().decode()
        assert response.status == 303
        assert response.getheader("Location") == "/?tenant=mon-lab&site=site-a"
        cookie = response.getheader("Set-Cookie")
        assert cookie is not None and "mon_session=signed-jwt-do-not-expose" in cookie
        assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
        assert "Max-Age=3600" in cookie
        assert "signed-jwt-do-not-expose" not in text
        assert pairing.used

        client.request(
            "POST", "/lab-session/claim",
            "code=" + pairing.challenge + "&form_nonce=" + pairing.form_nonce,
            headers={"Origin": pairing.expected_origin,
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
        reused = client.getresponse()
        reused.read()
        assert reused.status == 410
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def test_http_claim_rejects_cross_origin_and_oversized_payload(monkeypatch) -> None:
    mod = module()
    pairing = state(mod)
    monkeypatch.setattr(mod, "validate_operator", lambda _: {"roles": ["tenant_admin"]})
    server = http.server.HTTPServer(("127.0.0.1", 0), mod.make_handler(pairing))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        conn.request(
            "POST", "/lab-session/claim",
            "code=" + pairing.challenge + "&form_nonce=" + pairing.form_nonce,
            headers={"Origin": "http://other.test",
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
        denied = conn.getresponse()
        denied.read()
        assert denied.status == 403
        assert denied.getheader("Set-Cookie") is None

        conn.request(
            "POST", "/lab-session/claim", "x" * 300,
            headers={"Origin": pairing.expected_origin,
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
        oversize = conn.getresponse()
        oversize.read()
        assert oversize.status == 400
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def test_pairing_server_never_binds_non_loopback() -> None:
    mod = module()
    with pytest.raises(RuntimeError, match="loopback"):
        mod.serve(state(mod), host="0.0.0.0", port=0)



def test_missing_origin_allowed_only_with_verified_same_origin_metadata_and_nonce(
    monkeypatch,
) -> None:
    mod = module()
    monkeypatch.setattr(mod, "validate_operator", lambda _: {"roles": ["tenant_admin"]})
    allowed = state(mod)
    assert allowed.claim(
        challenge=allowed.challenge,
        form_nonce=allowed.form_nonce,
        origin="",
        fetch_site="same-origin",
    )
    assert allowed.used

    for origin, fetch_site in [
        ("", ""),
        ("", "cross-site"),
        ("null", "cross-site"),
        ("http://evil.invalid", "same-origin"),
    ]:
        attempt = state(mod)
        assert not attempt.claim(
            challenge=attempt.challenge,
            form_nonce=attempt.form_nonce,
            origin=origin,
            fetch_site=fetch_site,
        )
        assert not attempt.used

    bypass_attempt = state(mod)
    assert not bypass_attempt.claim(
        challenge=bypass_attempt.challenge,
        form_nonce="invalid",
        origin="",
        fetch_site="same-origin",
    )


def test_http_same_origin_chrome_form_without_origin_header_succeeds(monkeypatch) -> None:
    mod = module()
    monkeypatch.setattr(mod, "validate_operator", lambda _: {"roles": ["tenant_admin"]})
    pairing = state(mod)
    server = http.server.HTTPServer(("127.0.0.1", 0), mod.make_handler(pairing))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        client.request("GET", "/lab-session/")
        get_response = client.getresponse()
        assert get_response.status == 200
        get_response.read()
        client.request(
            "POST", "/lab-session/claim",
            "code=" + pairing.challenge + "&form_nonce=" + pairing.form_nonce,
            headers={
                "Sec-Fetch-Site": "same-origin",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        result = client.getresponse()
        result.read()
        assert result.status == 303
        assert result.getheader("Set-Cookie", "").startswith("mon_session=")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
