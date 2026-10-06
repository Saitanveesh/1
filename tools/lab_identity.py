from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mon.sensor_identity import generate_sensor_key_and_csr
from mon.site_identity import CertificateAuthority, generate_site_key_and_csr

DEFAULT_ISSUER = "mon-lab"
DEFAULT_AUDIENCE = "mon-control-plane"
DEFAULT_KID = "mon-lab-key-1"


class LabIdentityError(RuntimeError):
    pass


def _write(path: Path, data: str, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise LabIdentityError(f"refusing to overwrite existing file: {path}")
    path.write_text(data, encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o600 if private else 0o644)


def _private_key_pem(key: object) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _make_ca(common_name: str, *, valid_days: int = 30) -> tuple[CertificateAuthority, str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MON Security Fabric Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=2))
        .not_valid_after(now + dt.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = _private_key_pem(key)
    return CertificateAuthority.from_pem(cert_pem, key_pem), cert_pem, key_pem


def _server_certificate(
    ca: CertificateAuthority,
    *,
    common_name: str,
    host: str,
    valid_days: int = 7,
) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    try:
        san_value: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        san_value = x509.DNSName(host)

    expires_at = min(
        now + dt.timedelta(days=valid_days),
        ca.certificate.not_valid_after_utc,
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_NAME,
                        "MON Security Fabric Lab",
                    ),
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name[:64]),
                ]
            )
        )
        .issuer_name(ca.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=2))
        .not_valid_after(expires_at)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName([san_value]), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca.certificate.public_key()
            ),
            critical=False,
        )
        .sign(ca.private_key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM).decode(),
        _private_key_pem(key),
    )


def _jwt(
    private_key_pem: str,
    *,
    subject: str,
    tenant_id: str,
    roles: list[str],
    site_ids: list[str],
    issuer: str,
    audience: str,
    kid: str,
    valid_hours: int,
) -> str:
    now = dt.datetime.now(dt.UTC)
    return jwt.encode(
        {
            "sub": subject,
            "tenant_id": tenant_id,
            "roles": roles,
            "site_ids": site_ids,
            "iss": issuer,
            "aud": audience,
            "iat": now,
            "exp": now + dt.timedelta(hours=valid_hours),
        },
        private_key_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )


def init_material(args: argparse.Namespace) -> None:
    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise LabIdentityError(
            f"{out} is not empty; use a fresh directory to avoid overwriting credentials"
        )

    auth_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    auth_private = _private_key_pem(auth_key)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(auth_key.public_key()))
    jwk.update({"kid": args.kid, "use": "sig", "alg": "RS256"})

    site_ca, site_ca_pem, site_ca_key = _make_ca("MON Lab Site CA")
    sensor_ca, sensor_ca_pem, sensor_ca_key = _make_ca("MON Lab Sensor CA")
    site_server_cert, site_server_key = _server_certificate(
        site_ca,
        common_name="mon-lab-site-ingress",
        host=args.site_ingress_host,
    )
    sensor_server_cert, sensor_server_key = _server_certificate(
        sensor_ca,
        common_name="mon-lab-sensor-ingress",
        host=args.sensor_ingress_host,
    )

    operator_token = _jwt(
        auth_private,
        subject="mon-lab-operator",
        tenant_id=args.tenant_id,
        roles=["tenant_admin"],
        site_ids=[],
        issuer=args.issuer,
        audience=args.audience,
        kid=args.kid,
        valid_hours=args.token_hours,
    )
    site_token = _jwt(
        auth_private,
        subject="mon-lab-site-controller",
        tenant_id=args.tenant_id,
        roles=["site_controller"],
        site_ids=[args.site_id],
        issuer=args.issuer,
        audience=args.audience,
        kid=args.kid,
        valid_hours=args.token_hours,
    )

    _write(out / "auth-private.pem", auth_private, private=True)
    _write(out / "jwks.json", json.dumps({"keys": [jwk]}, indent=2) + "\n")
    _write(out / "operator.jwt", operator_token + "\n", private=True)
    _write(out / "site-controller.jwt", site_token + "\n", private=True)
    _write(out / "site-ca.pem", site_ca_pem)
    _write(out / "site-ca-key.pem", site_ca_key, private=True)
    _write(out / "sensor-ca.pem", sensor_ca_pem)
    _write(out / "sensor-ca-key.pem", sensor_ca_key, private=True)
    _write(out / "site-ingress-server.pem", site_server_cert)
    _write(out / "site-ingress-server-key.pem", site_server_key, private=True)
    _write(out / "sensor-ingress-server.pem", sensor_server_cert)
    _write(out / "sensor-ingress-server-key.pem", sensor_server_key, private=True)
    _write(
        out / "lab.json",
        json.dumps(
            {
                "tenant_id": args.tenant_id,
                "site_id": args.site_id,
                "issuer": args.issuer,
                "audience": args.audience,
                "kid": args.kid,
                "site_ingress_host": args.site_ingress_host,
                "sensor_ingress_host": args.sensor_ingress_host,
                "token_hours": args.token_hours,
            },
            indent=2,
        )
        + "\n",
    )
    print(f"lab identity material created under {out}")


def make_site_request(args: argparse.Namespace) -> None:
    material = generate_site_key_and_csr(args.tenant_id, args.site_id)
    _write(args.out_dir / "site-client-key.pem", material.private_key_pem, private=True)
    _write(args.out_dir / "site-client.csr.pem", material.csr_pem)
    print(f"site CSR created under {args.out_dir}; private key remains local")


def make_sensor_request(args: argparse.Namespace) -> None:
    private_key, csr, _spiffe = generate_sensor_key_and_csr(
        args.tenant_id,
        args.site_id,
        args.sensor_id,
    )
    _write(args.out_dir / "sensor-client-key.pem", private_key, private=True)
    _write(args.out_dir / "sensor-client.csr.pem", csr)
    print(f"sensor CSR created under {args.out_dir}; private key remains local")


def _client(control_url: str) -> httpx.Client:
    parsed = urlparse(control_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise LabIdentityError("control URL must be an http(s) URL with a host")
    if parsed.scheme == "http":
        try:
            address = ipaddress.ip_address(parsed.hostname)
            loopback = address.is_loopback
        except ValueError:
            loopback = parsed.hostname == "localhost"
        if not loopback:
            raise LabIdentityError(
                "plain HTTP enrollment is allowed only to a loopback control-plane URL"
            )
    return httpx.Client(base_url=control_url.rstrip("/"), timeout=10, trust_env=False)


def _must_json(response: httpx.Response) -> dict[str, object]:
    if response.status_code not in {200, 201}:
        raise LabIdentityError(
            f"{response.request.method} {response.request.url} -> "
            f"{response.status_code}: {response.text[:500]}"
        )
    payload = response.json()
    if not isinstance(payload, dict):
        raise LabIdentityError("control plane returned a non-object JSON response")
    return payload


def enroll_site_csr(args: argparse.Namespace) -> None:
    admin_token = args.admin_token_file.read_text(encoding="utf-8").strip()
    csr = args.csr_file.read_text(encoding="utf-8")
    headers = {"Authorization": f"Bearer {admin_token}"}
    with _client(args.control_url) as client:
        issued = _must_json(
            client.post(
                "/api/v1/enrollment-tokens",
                headers=headers,
                json={
                    "tenant_id": args.tenant_id,
                    "site_id": args.site_id,
                    "ttl_seconds": args.ttl_seconds,
                },
            )
        )
        enrolled = _must_json(
            client.post(
                "/api/v1/site-enrollment",
                json={
                    "enrollment_token": issued["enrollment_token"],
                    "csr_pem": csr,
                },
            )
        )
    _write(args.out_dir / "site-client-cert.pem", str(enrolled["certificate_pem"]))
    _write(args.out_dir / "site-ca.pem", str(enrolled["ca_certificate_pem"]))
    print(f"site certificate created under {args.out_dir}")


def enroll_sensor_csr(args: argparse.Namespace) -> None:
    admin_token = args.admin_token_file.read_text(encoding="utf-8").strip()
    csr = args.csr_file.read_text(encoding="utf-8")
    headers = {"Authorization": f"Bearer {admin_token}"}
    with _client(args.control_url) as client:
        issued = _must_json(
            client.post(
                "/api/v1/sensor-enrollment-tokens",
                headers=headers,
                json={
                    "tenant_id": args.tenant_id,
                    "site_id": args.site_id,
                    "sensor_id": args.sensor_id,
                    "ttl_seconds": args.ttl_seconds,
                },
            )
        )
        enrolled = _must_json(
            client.post(
                "/api/v1/sensor-enrollment",
                json={
                    "enrollment_token": issued["enrollment_token"],
                    "csr_pem": csr,
                },
            )
        )
    _write(args.out_dir / "sensor-client-cert.pem", str(enrolled["certificate_pem"]))
    _write(args.out_dir / "sensor-ca.pem", str(enrolled["ca_certificate_pem"]))
    print(f"sensor certificate created under {args.out_dir}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate disposable MON lab identity material without weakening runtime trust"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init")
    init.add_argument("--out-dir", type=Path, required=True)
    init.add_argument("--tenant-id", required=True)
    init.add_argument("--site-id", required=True)
    init.add_argument("--site-ingress-host", required=True)
    init.add_argument("--sensor-ingress-host", required=True)
    init.add_argument("--issuer", default=DEFAULT_ISSUER)
    init.add_argument("--audience", default=DEFAULT_AUDIENCE)
    init.add_argument("--kid", default=DEFAULT_KID)
    init.add_argument("--token-hours", type=int, default=12, choices=range(1, 49))
    init.set_defaults(func=init_material)

    site_request = sub.add_parser("site-request")
    site_request.add_argument("--out-dir", type=Path, required=True)
    site_request.add_argument("--tenant-id", required=True)
    site_request.add_argument("--site-id", required=True)
    site_request.set_defaults(func=make_site_request)

    sensor_request = sub.add_parser("sensor-request")
    sensor_request.add_argument("--out-dir", type=Path, required=True)
    sensor_request.add_argument("--tenant-id", required=True)
    sensor_request.add_argument("--site-id", required=True)
    sensor_request.add_argument("--sensor-id", required=True)
    sensor_request.set_defaults(func=make_sensor_request)

    site_enroll = sub.add_parser("enroll-site-csr")
    site_enroll.add_argument("--control-url", default="http://127.0.0.1:8080")
    site_enroll.add_argument("--admin-token-file", type=Path, required=True)
    site_enroll.add_argument("--csr-file", type=Path, required=True)
    site_enroll.add_argument("--out-dir", type=Path, required=True)
    site_enroll.add_argument("--tenant-id", required=True)
    site_enroll.add_argument("--site-id", required=True)
    site_enroll.add_argument("--ttl-seconds", type=int, default=900)
    site_enroll.set_defaults(func=enroll_site_csr)

    sensor_enroll = sub.add_parser("enroll-sensor-csr")
    sensor_enroll.add_argument("--control-url", default="http://127.0.0.1:8080")
    sensor_enroll.add_argument("--admin-token-file", type=Path, required=True)
    sensor_enroll.add_argument("--csr-file", type=Path, required=True)
    sensor_enroll.add_argument("--out-dir", type=Path, required=True)
    sensor_enroll.add_argument("--tenant-id", required=True)
    sensor_enroll.add_argument("--site-id", required=True)
    sensor_enroll.add_argument("--sensor-id", required=True)
    sensor_enroll.add_argument("--ttl-seconds", type=int, default=900)
    sensor_enroll.set_defaults(func=enroll_sensor_csr)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        args.func(args)
    except (LabIdentityError, OSError, ValueError, httpx.HTTPError) as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
