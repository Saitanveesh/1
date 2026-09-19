import datetime as dt
import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mon.auth import (
    AuthConfigurationError,
    InvalidCredentials,
    JWKSAuthenticator,
    JWTAuthenticator,
    Permission,
    Principal,
    Role,
    is_scope_authorized,
)


def keypair() -> tuple[object, str, str]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private, private_pem, public_pem


def public_jwk(private: object, kid: str) -> dict[str, object]:
    value = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    value.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return value


def token(
    private_key: str,
    *,
    tenant_id: str = "tenant-a",
    roles: list[str] | None = None,
    site_ids: list[str] | None = None,
    audience: str = "mon-control-plane",
    kid: str | None = None,
) -> str:
    now = dt.datetime.now(dt.UTC)
    headers = {"kid": kid} if kid is not None else None
    return jwt.encode(
        {
            "sub": "user-1",
            "tenant_id": tenant_id,
            "roles": roles or ["viewer"],
            "site_ids": site_ids or [],
            "iss": "https://id.example.test/",
            "aud": audience,
            "iat": now,
            "exp": now + dt.timedelta(minutes=5),
        },
        private_key,
        algorithm="RS256",
        headers=headers,
    )


def test_jwt_authenticator_validates_signature_issuer_and_audience() -> None:
    _, private_key, public_key = keypair()
    authenticator = JWTAuthenticator(
        public_key,
        issuer="https://id.example.test/",
        audience="mon-control-plane",
    )

    principal = authenticator.verify(token(private_key))
    assert principal.subject == "user-1"
    assert principal.tenant_id == "tenant-a"
    assert principal.roles == {Role.VIEWER}

    with pytest.raises(InvalidCredentials):
        authenticator.verify(token(private_key, audience="wrong-audience"))


def test_jwks_authenticator_accepts_multiple_rotation_keys() -> None:
    first, first_private, _ = keypair()
    second, second_private, _ = keypair()
    authenticator = JWKSAuthenticator(
        issuer="https://id.example.test/",
        audience="mon-control-plane",
        jwks_json=json.dumps(
            {"keys": [public_jwk(first, "key-1"), public_jwk(second, "key-2")]}
        ),
    )

    assert authenticator.verify(token(first_private, kid="key-1")).subject == "user-1"
    assert authenticator.verify(token(second_private, kid="key-2")).subject == "user-1"


def test_jwks_authenticator_rejects_missing_or_unknown_kid() -> None:
    private, private_pem, _ = keypair()
    authenticator = JWKSAuthenticator(
        issuer="https://id.example.test/",
        audience="mon-control-plane",
        jwks_json=json.dumps({"keys": [public_jwk(private, "trusted")]}),
    )

    with pytest.raises(InvalidCredentials):
        authenticator.verify(token(private_pem))
    with pytest.raises(InvalidCredentials):
        authenticator.verify(token(private_pem, kid="unknown"))


def test_jwks_file_hot_reload_replaces_the_trust_set(tmp_path) -> None:
    first, first_private, _ = keypair()
    second, second_private, _ = keypair()
    path = tmp_path / "auth.jwks.json"
    path.write_text(
        json.dumps({"keys": [public_jwk(first, "first")]}),
        encoding="utf-8",
    )
    authenticator = JWKSAuthenticator(
        issuer="https://id.example.test/",
        audience="mon-control-plane",
        jwks_file=path,
    )

    assert authenticator.verify(token(first_private, kid="first")).subject == "user-1"

    replacement = tmp_path / "auth.next.json"
    replacement.write_text(
        json.dumps({"keys": [public_jwk(second, "second")]}),
        encoding="utf-8",
    )
    replacement.replace(path)

    assert authenticator.verify(token(second_private, kid="second")).subject == "user-1"
    with pytest.raises(InvalidCredentials):
        authenticator.verify(token(first_private, kid="first"))


def test_invalid_jwks_reload_fails_closed(tmp_path) -> None:
    private, private_pem, _ = keypair()
    path = tmp_path / "auth.jwks.json"
    path.write_text(
        json.dumps({"keys": [public_jwk(private, "trusted")]}),
        encoding="utf-8",
    )
    authenticator = JWKSAuthenticator(
        issuer="https://id.example.test/",
        audience="mon-control-plane",
        jwks_file=path,
    )
    assert authenticator.verify(token(private_pem, kid="trusted")).subject == "user-1"

    replacement = tmp_path / "broken.json"
    replacement.write_text("{", encoding="utf-8")
    replacement.replace(path)
    with pytest.raises(AuthConfigurationError):
        authenticator.verify(token(private_pem, kid="trusted"))


def test_jwks_rejects_private_or_non_rsa_key_material() -> None:
    private, _, _ = keypair()
    private_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private))
    private_jwk.update({"kid": "private", "alg": "RS256", "use": "sig"})
    with pytest.raises(AuthConfigurationError):
        JWKSAuthenticator(
            issuer="https://id.example.test/",
            audience="mon-control-plane",
            jwks_json=json.dumps({"keys": [private_jwk]}),
        )

    with pytest.raises(AuthConfigurationError):
        JWKSAuthenticator(
            issuer="https://id.example.test/",
            audience="mon-control-plane",
            jwks_json=json.dumps(
                {
                    "keys": [
                        {
                            "kty": "oct",
                            "kid": "symmetric",
                            "alg": "HS256",
                            "k": "c2VjcmV0",
                        }
                    ]
                }
            ),
        )


def test_tenant_and_site_permissions_are_explicit() -> None:
    viewer = Principal(
        subject="viewer",
        tenant_id="tenant-a",
        roles={Role.VIEWER},
        site_ids={"site-1"},
    )
    assert is_scope_authorized(viewer, "tenant-a", "site-1", Permission.VIEW)
    assert not is_scope_authorized(viewer, "tenant-a", "site-2", Permission.VIEW)
    assert not is_scope_authorized(viewer, "tenant-b", "site-1", Permission.VIEW)
    assert not is_scope_authorized(viewer, "tenant-a", "site-1", Permission.RESPOND)

    controller = Principal(
        subject="site-controller",
        tenant_id="tenant-a",
        roles={Role.SITE_CONTROLLER},
        site_ids={"site-1"},
    )
    assert is_scope_authorized(
        controller,
        "tenant-a",
        "site-1",
        Permission.INGEST,
    )
    assert not is_scope_authorized(
        controller,
        "tenant-a",
        "site-2",
        Permission.INGEST,
    )
    assert not is_scope_authorized(
        controller,
        "tenant-a",
        "site-1",
        Permission.VIEW,
    )
