import datetime as dt
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mon.sensor_credentials import (
    SensorCredentialError,
    SensorCredentialStore,
    SensorCredentialTransportError,
    rotate_sensor_credentials_if_due,
)
from mon.sensor_fleet_models import (
    SensorEnrollmentResult,
    SensorRenewalResult,
    SensorTrustSnapshot,
)
from mon.sensor_identity import (
    generate_sensor_key_and_csr,
    issue_sensor_client_certificate,
    sensor_spiffe_uri,
)
from mon.site_identity import CertificateAuthority


def make_ca() -> CertificateAuthority:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "MON Sensor Credential Test CA")]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return CertificateAuthority.from_pem(
        certificate.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


def write_bootstrap(
    tmp_path,
    ca: CertificateAuthority,
    *,
    password: str | None = None,
):
    private_key_pem, csr_pem, _ = generate_sensor_key_and_csr(
        "tenant-a",
        "site-a",
        "sensor-1",
        password=password,
    )
    certificate = issue_sensor_client_certificate(
        ca,
        csr_pem,
        "tenant-a",
        "site-a",
        "sensor-1",
        validity_days=30,
    )
    server_ca = tmp_path / "server-ca.pem"
    certificate_file = tmp_path / "sensor.pem"
    private_key_file = tmp_path / "sensor-key.pem"
    server_ca.write_text(ca.certificate_pem, encoding="utf-8")
    certificate_file.write_text(
        certificate.public_bytes(serialization.Encoding.PEM).decode(),
        encoding="utf-8",
    )
    private_key_file.write_text(private_key_pem, encoding="utf-8")
    return server_ca, certificate_file, private_key_file


def make_store(
    tmp_path,
    ca: CertificateAuthority,
    *,
    password: str | None = None,
) -> SensorCredentialStore:
    server_ca, certificate_file, private_key_file = write_bootstrap(
        tmp_path,
        ca,
        password=password,
    )
    return SensorCredentialStore(
        tmp_path / "credentials",
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="sensor-1",
        server_ca_certificate_file=server_ca,
        bootstrap_certificate_file=certificate_file,
        bootstrap_private_key_file=private_key_file,
        private_key_password=password,
    )


def renewal_result(
    ca: CertificateAuthority,
    csr_pem: str,
) -> SensorRenewalResult:
    certificate = issue_sensor_client_certificate(
        ca,
        csr_pem,
        "tenant-a",
        "site-a",
        "sensor-1",
        validity_days=30,
    )
    certificate_pem = certificate.public_bytes(
        serialization.Encoding.PEM
    ).decode()
    return SensorRenewalResult(
        certificate=SensorEnrollmentResult(
            identity_id="renewed-identity",
            tenant_id="tenant-a",
            site_id="site-a",
            sensor_id="sensor-1",
            certificate_pem=certificate_pem,
            ca_certificate_pem=ca.certificate_pem,
            fingerprint_sha256=certificate.fingerprint(
                hashes.SHA256()
            ).hex(),
            spiffe_uri=sensor_spiffe_uri(
                "tenant-a",
                "site-a",
                "sensor-1",
            ),
            expires_at=certificate.not_valid_after_utc,
        ),
        trust_snapshot=SensorTrustSnapshot(
            tenant_id="tenant-a",
            site_id="site-a",
            generated_at=dt.datetime.now(dt.UTC),
            identities=[],
        ),
    )


class FakeCredentialClient:
    def __init__(
        self,
        ca: CertificateAuthority,
        *,
        fail_renewal: bool = False,
        probe_failures: int = 0,
        current_fingerprint_sha256: str | None = None,
    ) -> None:
        self.ca = ca
        self.fail_renewal = fail_renewal
        self.probe_failures = probe_failures
        self.renew_calls: list[str] = []
        self.probe_calls = 0
        self.replace_calls = 0
        self._credential_fingerprint_sha256 = current_fingerprint_sha256

    @property
    def credential_fingerprint_sha256(self) -> str | None:
        return self._credential_fingerprint_sha256

    async def renew_certificate(self, csr_pem: str) -> SensorRenewalResult:
        self.renew_calls.append(csr_pem)
        if self.fail_renewal:
            raise SensorCredentialTransportError("simulated renewal outage")
        return renewal_result(self.ca, csr_pem)

    async def probe_ssl_context(
        self,
        ssl_context,
        *,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
    ) -> None:
        assert tenant_id == "tenant-a"
        assert site_id == "site-a"
        assert sensor_id == "sensor-1"
        self.probe_calls += 1
        if self.probe_failures:
            self.probe_failures -= 1
            raise SensorCredentialTransportError("simulated probe failure")

    async def replace_ssl_context(
        self,
        ssl_context,
        *,
        fingerprint_sha256: str,
    ) -> None:
        self.replace_calls += 1
        self._credential_fingerprint_sha256 = fingerprint_sha256


def test_bootstrap_import_is_scope_bound_and_key_is_private(tmp_path) -> None:
    ca = make_ca()
    store = make_store(tmp_path, ca)

    active = store.active_generation()
    assert active.spiffe_uri == (
        "spiffe://mon.local/tenant/tenant-a/site/site-a/sensor/sensor-1"
    )
    assert store.diagnostics()["durability"] == "FSYNC_ATOMIC_POINTER"
    assert stat.S_IMODE(active.private_key_file.stat().st_mode) == 0o600

    with pytest.raises(SensorCredentialError, match="site_id mismatch"):
        SensorCredentialStore(
            store.root,
            tenant_id="tenant-a",
            site_id="site-b",
            sensor_id="sensor-1",
            server_ca_certificate_file=store.server_ca_certificate_file,
            bootstrap_certificate_file=None,
            bootstrap_private_key_file=None,
        )


def test_managed_store_reopens_without_bootstrap_files(tmp_path) -> None:
    ca = make_ca()
    server_ca, certificate_file, private_key_file = write_bootstrap(tmp_path, ca)
    root = tmp_path / "credentials"
    first = SensorCredentialStore(
        root,
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="sensor-1",
        server_ca_certificate_file=server_ca,
        bootstrap_certificate_file=certificate_file,
        bootstrap_private_key_file=private_key_file,
    )
    fingerprint = first.active_generation().fingerprint_sha256

    certificate_file.unlink()
    private_key_file.unlink()

    second = SensorCredentialStore(
        root,
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="sensor-1",
        server_ca_certificate_file=server_ca,
        bootstrap_certificate_file=None,
        bootstrap_private_key_file=None,
    )
    assert second.active_generation().fingerprint_sha256 == fingerprint


def test_pending_renewal_survives_restart_with_same_key_and_csr(tmp_path) -> None:
    ca = make_ca()
    store = make_store(tmp_path, ca)
    pending = store.begin_renewal()

    reopened = SensorCredentialStore(
        store.root,
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="sensor-1",
        server_ca_certificate_file=store.server_ca_certificate_file,
        bootstrap_certificate_file=None,
        bootstrap_private_key_file=None,
    )
    restored = reopened.pending_renewal()
    assert restored is not None
    assert restored.generation_id == pending.generation_id
    assert restored.csr_pem == pending.csr_pem
    assert (
        reopened.active_generation().fingerprint_sha256
        == pending.current_fingerprint_sha256
    )


@pytest.mark.asyncio
async def test_failed_renewal_keeps_old_active_and_persists_retry_state(
    tmp_path,
) -> None:
    ca = make_ca()
    store = make_store(tmp_path, ca)
    original = store.active_generation()
    client = FakeCredentialClient(ca, fail_renewal=True)

    with pytest.raises(SensorCredentialTransportError, match="renewal outage"):
        await rotate_sensor_credentials_if_due(
            store,
            client,
            renew_before=dt.timedelta(days=7),
            now=original.expires_at - dt.timedelta(days=1),
        )

    pending = store.pending_renewal()
    assert pending is not None
    assert store.pending_generation() is None
    assert (
        store.active_generation().fingerprint_sha256
        == original.fingerprint_sha256
    )

    reopened = SensorCredentialStore(
        store.root,
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="sensor-1",
        server_ca_certificate_file=store.server_ca_certificate_file,
        bootstrap_certificate_file=None,
        bootstrap_private_key_file=None,
    )
    restored = reopened.pending_renewal()
    assert restored is not None
    assert restored.csr_pem == pending.csr_pem


@pytest.mark.asyncio
async def test_persisted_candidate_recovers_without_old_credential_reissue(
    tmp_path,
) -> None:
    ca = make_ca()
    store = make_store(tmp_path, ca)
    original = store.active_generation()
    first_client = FakeCredentialClient(ca, probe_failures=1)

    with pytest.raises(SensorCredentialTransportError, match="probe failure"):
        await rotate_sensor_credentials_if_due(
            store,
            first_client,
            renew_before=dt.timedelta(days=7),
            now=original.expires_at - dt.timedelta(days=1),
        )

    candidate = store.pending_generation()
    assert candidate is not None
    assert candidate.fingerprint_sha256 != original.fingerprint_sha256
    assert (
        store.active_generation().fingerprint_sha256
        == original.fingerprint_sha256
    )

    reopened = SensorCredentialStore(
        store.root,
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="sensor-1",
        server_ca_certificate_file=store.server_ca_certificate_file,
        bootstrap_certificate_file=None,
        bootstrap_private_key_file=None,
    )
    second_client = FakeCredentialClient(ca)
    recovered = await rotate_sensor_credentials_if_due(
        reopened,
        second_client,
        renew_before=dt.timedelta(days=7),
        now=original.expires_at + dt.timedelta(days=1),
    )

    assert recovered["state"] == "ROTATED"
    assert recovered["recovered_pending"] is True
    assert second_client.renew_calls == []
    assert second_client.probe_calls == 1
    assert second_client.replace_calls == 1
    assert reopened.pending_renewal() is None
    assert (
        reopened.active_generation().fingerprint_sha256
        == candidate.fingerprint_sha256
    )


@pytest.mark.asyncio
async def test_successful_rotation_switches_only_after_probe(tmp_path) -> None:
    ca = make_ca()
    store = make_store(tmp_path, ca)
    old = store.active_generation()
    client = FakeCredentialClient(ca)

    result = await rotate_sensor_credentials_if_due(
        store,
        client,
        renew_before=dt.timedelta(days=7),
        now=old.expires_at - dt.timedelta(days=1),
    )

    active = store.active_generation()
    assert result["state"] == "ROTATED"
    assert result["recovered_pending"] is False
    assert active.fingerprint_sha256 != old.fingerprint_sha256
    assert client.renew_calls
    assert client.probe_calls == 1
    assert client.replace_calls == 1
    assert store.pending_renewal() is None


def test_renewal_result_for_different_key_is_rejected(tmp_path) -> None:
    ca = make_ca()
    store = make_store(tmp_path, ca)
    pending = store.begin_renewal()

    _, wrong_csr, _ = generate_sensor_key_and_csr(
        "tenant-a",
        "site-a",
        "sensor-1",
    )
    mismatched = renewal_result(ca, wrong_csr)

    with pytest.raises(SensorCredentialError, match="pending private key"):
        store.install_renewal_result(mismatched)

    assert store.pending_renewal() == pending


def test_rotation_not_due_does_not_create_pending_generation(tmp_path) -> None:
    ca = make_ca()
    store = make_store(tmp_path, ca)
    active = store.active_generation()
    now = active.expires_at - dt.timedelta(days=20)

    assert (
        store.renewal_due(
            now=now,
            renew_before=dt.timedelta(days=7),
        )
        is False
    )
    assert store.pending_renewal() is None


@pytest.mark.asyncio
async def test_peer_rotation_is_loaded_before_old_overlap_expires(tmp_path) -> None:
    ca = make_ca()
    first_store = make_store(tmp_path, ca)
    original = first_store.active_generation()
    first_client = FakeCredentialClient(
        ca,
        current_fingerprint_sha256=original.fingerprint_sha256,
    )
    rotated = await rotate_sensor_credentials_if_due(
        first_store,
        first_client,
        renew_before=dt.timedelta(days=7),
        now=original.expires_at - dt.timedelta(days=1),
    )
    assert rotated["state"] == "ROTATED"
    new_active = first_store.active_generation()

    second_store = SensorCredentialStore(
        first_store.root,
        tenant_id="tenant-a",
        site_id="site-a",
        sensor_id="sensor-1",
        server_ca_certificate_file=first_store.server_ca_certificate_file,
        bootstrap_certificate_file=None,
        bootstrap_private_key_file=None,
    )
    second_client = FakeCredentialClient(
        ca,
        current_fingerprint_sha256=original.fingerprint_sha256,
    )
    result = await rotate_sensor_credentials_if_due(
        second_store,
        second_client,
        renew_before=dt.timedelta(days=7),
    )

    assert result["state"] == "CURRENT"
    assert second_client.renew_calls == []
    assert second_client.probe_calls == 1
    assert second_client.replace_calls == 1
    assert (
        second_client.credential_fingerprint_sha256
        == new_active.fingerprint_sha256
    )


@pytest.mark.asyncio
async def test_busy_rotation_lease_does_not_start_second_renewal(tmp_path) -> None:
    ca = make_ca()
    store = make_store(tmp_path, ca)
    active = store.active_generation()
    client = FakeCredentialClient(
        ca,
        current_fingerprint_sha256=active.fingerprint_sha256,
    )

    with store.rotation_lease():
        result = await rotate_sensor_credentials_if_due(
            store,
            client,
            renew_before=dt.timedelta(days=7),
            now=active.expires_at - dt.timedelta(days=1),
        )

    assert result == {"state": "BUSY"}
    assert client.renew_calls == []
    assert store.pending_renewal() is None


def test_renewal_lead_time_must_be_shorter_than_certificate_lifetime(
    tmp_path,
) -> None:
    ca = make_ca()
    store = make_store(tmp_path, ca)
    active = store.active_generation()

    with pytest.raises(SensorCredentialError, match="lead time"):
        store.renewal_due(
            now=active.not_before,
            renew_before=active.expires_at - active.not_before,
        )
