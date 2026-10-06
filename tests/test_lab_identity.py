from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

import jwt
import pytest
from cryptography import x509

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "lab_identity.py"
SPEC = importlib.util.spec_from_file_location("mon_lab_identity", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
lab_identity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab_identity)


def test_init_creates_scoped_short_lived_lab_material(tmp_path: Path) -> None:
    out = tmp_path / "identity"
    args = argparse.Namespace(
        out_dir=out,
        tenant_id="lab-tenant",
        site_id="lab-site",
        site_ingress_host="192.0.2.10",
        sensor_ingress_host="192.0.2.20",
        issuer="mon-lab-test",
        audience="mon-control-plane",
        kid="lab-key",
        token_hours=2,
    )

    lab_identity.init_material(args)

    jwks = json.loads((out / "jwks.json").read_text(encoding="utf-8"))
    key = jwt.PyJWK.from_dict(jwks["keys"][0]).key
    operator = jwt.decode(
        (out / "operator.jwt").read_text(encoding="utf-8").strip(),
        key=key,
        algorithms=["RS256"],
        issuer="mon-lab-test",
        audience="mon-control-plane",
    )
    site = jwt.decode(
        (out / "site-controller.jwt").read_text(encoding="utf-8").strip(),
        key=key,
        algorithms=["RS256"],
        issuer="mon-lab-test",
        audience="mon-control-plane",
    )

    assert operator["tenant_id"] == "lab-tenant"
    assert operator["roles"] == ["tenant_admin"]
    assert site["roles"] == ["site_controller"]
    assert site["site_ids"] == ["lab-site"]

    site_server = x509.load_pem_x509_certificate(
        (out / "site-ingress-server.pem").read_bytes()
    )
    site_sans = site_server.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    assert "192.0.2.10" in {
        str(value)
        for value in site_sans.get_values_for_type(x509.IPAddress)
    }

    sensor_server = x509.load_pem_x509_certificate(
        (out / "sensor-ingress-server.pem").read_bytes()
    )
    sensor_sans = sensor_server.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    assert "192.0.2.20" in {
        str(value)
        for value in sensor_sans.get_values_for_type(x509.IPAddress)
    }


def test_init_refuses_to_overwrite_existing_identity_directory(
    tmp_path: Path,
) -> None:
    out = tmp_path / "identity"
    out.mkdir()
    (out / "keep.txt").write_text("preserve", encoding="utf-8")
    args = argparse.Namespace(
        out_dir=out,
        tenant_id="lab-tenant",
        site_id="lab-site",
        site_ingress_host="pc1.lab",
        sensor_ingress_host="pc3.lab",
        issuer="mon-lab",
        audience="mon-control-plane",
        kid="lab-key",
        token_hours=2,
    )

    with pytest.raises(lab_identity.LabIdentityError, match="not empty"):
        lab_identity.init_material(args)

    assert (out / "keep.txt").read_text(encoding="utf-8") == "preserve"


def test_site_and_sensor_requests_keep_private_keys_local(tmp_path: Path) -> None:
    site_dir = tmp_path / "site"
    lab_identity.make_site_request(
        argparse.Namespace(
            out_dir=site_dir,
            tenant_id="lab-tenant",
            site_id="lab-site",
        )
    )
    site_csr = x509.load_pem_x509_csr(
        (site_dir / "site-client.csr.pem").read_bytes()
    )
    assert site_csr.is_signature_valid
    assert (site_dir / "site-client-key.pem").exists()

    sensor_dir = tmp_path / "sensor"
    lab_identity.make_sensor_request(
        argparse.Namespace(
            out_dir=sensor_dir,
            tenant_id="lab-tenant",
            site_id="lab-site",
            sensor_id="victim-linux",
        )
    )
    sensor_csr = x509.load_pem_x509_csr(
        (sensor_dir / "sensor-client.csr.pem").read_bytes()
    )
    assert sensor_csr.is_signature_valid
    assert (sensor_dir / "sensor-client-key.pem").exists()


def test_plain_http_enrollment_is_loopback_only() -> None:
    with pytest.raises(
        lab_identity.LabIdentityError,
        match="loopback",
    ):
        lab_identity._client("http://192.0.2.10:8080")

    client = lab_identity._client("http://127.0.0.1:8080")
    client.close()
