import datetime as dt

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mon.auth import (
    InvalidCredentials,
    JWTAuthenticator,
    Permission,
    Principal,
    Role,
    is_scope_authorized,
)


def keypair() -> tuple[str, str]:
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
    return private_pem, public_pem


def token(
    private_key: str,
    *,
    tenant_id: str = "tenant-a",
    roles: list[str] | None = None,
    site_ids: list[str] | None = None,
    audience: str = "mon-control-plane",
) -> str:
    now = dt.datetime.now(dt.UTC)
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
    )


def test_jwt_authenticator_validates_signature_issuer_and_audience() -> None:
    private_key, public_key = keypair()
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
