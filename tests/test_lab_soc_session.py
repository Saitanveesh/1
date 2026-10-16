"""Local lab browser login requires a valid, scoped RS256 credential."""
import datetime as dt

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tools.lab_soc_session import _read_token, verify_local_operator


def material(tmp_path, *, tenant="mon-lab", roles=None, exp_delta=30):
    now = dt.datetime.now(dt.UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    claims = {
        "iss": "mon-lab-local-only",
        "aud": "mon-lab-control-plane",
        "iat": now,
        "exp": now + dt.timedelta(minutes=exp_delta),
        "sub": "local-test-operator",
        "tenant_id": tenant,
        "site_ids": [],
        "roles": roles or ["tenant_admin"],
    }
    tok = jwt.encode(claims, private, algorithm="RS256")
    token_file, key_file = tmp_path / "operator.jwt", tmp_path / "public.pem"
    token_file.write_text(tok + "\n", encoding="utf-8")
    token_file.chmod(0o600)
    key_file.write_bytes(public)
    return token_file, key_file


def test_valid_short_lived_scope_grants_one_hour_at_most(tmp_path):
    token_file, public_file = material(tmp_path)
    token, age = verify_local_operator(
        token_file, public_file,
        issuer="mon-lab-local-only", audience="mon-lab-control-plane",
        tenant="mon-lab", site="isolated-range",
    )
    assert token == _read_token(token_file)
    assert 1 <= age <= 1800


def test_rejects_untrusted_tenant_or_wrong_role(tmp_path):
    token_file, public_file = material(tmp_path)
    with pytest.raises(ValueError, match="signed token"):
        verify_local_operator(
            token_file, public_file,
            issuer="mon-lab-local-only", audience="mon-lab-control-plane",
            tenant="other-tenant", site="isolated-range",
        )
    second_dir = tmp_path / "other"
    second_dir.mkdir()
    token_file, public_file = material(second_dir, roles=["site_controller"])
    with pytest.raises(ValueError, match="signed token"):
        verify_local_operator(
            token_file, public_file,
            issuer="mon-lab-local-only", audience="mon-lab-control-plane",
            tenant="mon-lab", site="isolated-range",
        )


def test_file_permission_and_expiry_enforced(tmp_path):
    token_file, public_file = material(tmp_path)
    token_file.chmod(0o644)
    with pytest.raises(ValueError, match="private"):
        _read_token(token_file)
    token_file.chmod(0o600)
    token_file, public_file = material(tmp_path, exp_delta=-1)
    with pytest.raises(jwt.ExpiredSignatureError):
        verify_local_operator(
            token_file, public_file,
            issuer="mon-lab-local-only", audience="mon-lab-control-plane",
            tenant="mon-lab", site="isolated-range",
        )
