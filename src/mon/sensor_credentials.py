from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import ssl
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from mon.sensor_fleet_models import SensorRenewalResult
from mon.sensor_identity import generate_sensor_key_and_csr, sensor_spiffe_uri
from mon.site_identity import create_mtls_client_ssl_context

_GENERATION_ID = re.compile(r"^[A-Za-z0-9-]{1,80}$")


class SensorCredentialError(RuntimeError):
    pass


class SensorCredentialTransportError(RuntimeError):
    pass


class SensorCredentialBusyError(SensorCredentialError):
    pass


@dataclass(frozen=True, slots=True)
class SensorCredentialGeneration:
    generation_id: str
    certificate_file: Path
    private_key_file: Path
    fingerprint_sha256: str
    not_before: dt.datetime
    expires_at: dt.datetime
    spiffe_uri: str


@dataclass(frozen=True, slots=True)
class PendingSensorRenewal:
    generation_id: str
    current_fingerprint_sha256: str
    csr_pem: str
    created_at: dt.datetime


class SensorCredentialClient(Protocol):
    @property
    def credential_fingerprint_sha256(self) -> str | None: ...

    async def renew_certificate(self, csr_pem: str) -> SensorRenewalResult: ...

    async def probe_ssl_context(
        self,
        ssl_context: ssl.SSLContext,
        *,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
    ) -> None: ...

    async def replace_ssl_context(
        self,
        ssl_context: ssl.SSLContext,
        *,
        fingerprint_sha256: str,
    ) -> None: ...


class SensorCredentialStore:
    """Crash-safe, site-sensor-bound credential generations with atomic activation."""

    _SCHEMA_VERSION = "1"

    def __init__(
        self,
        root: str | Path,
        *,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
        server_ca_certificate_file: str | Path,
        bootstrap_certificate_file: str | Path | None,
        bootstrap_private_key_file: str | Path | None,
        private_key_password: str | None = None,
    ) -> None:
        if not tenant_id or not site_id or not sensor_id:
            raise ValueError("sensor credential tenant/site/sensor scope is required")

        self.root = Path(root)
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.sensor_id = sensor_id
        self.server_ca_certificate_file = Path(server_ca_certificate_file)
        self.bootstrap_certificate_file = (
            Path(bootstrap_certificate_file)
            if bootstrap_certificate_file is not None
            else None
        )
        self.bootstrap_private_key_file = (
            Path(bootstrap_private_key_file)
            if bootstrap_private_key_file is not None
            else None
        )
        self.private_key_password = private_key_password
        self.generations_dir = self.root / "generations"
        self.metadata_file = self.root / "metadata.json"
        self.active_file = self.root / "active.json"
        self.pending_file = self.root / "pending.json"

        if not self.server_ca_certificate_file.is_file():
            raise SensorCredentialError(
                "sensor ingress server CA certificate file does not exist: "
                f"{self.server_ca_certificate_file}"
            )

        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.generations_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        os.chmod(self.generations_dir, 0o700)
        self._cleanup_temporary_artifacts()
        self._bind_metadata()
        if not self.active_file.exists():
            self._import_bootstrap_generation()
        self._recover_completed_activation()
        self.active_generation()

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @classmethod
    def _write_bytes_atomic(
        cls,
        path: Path,
        data: bytes,
        *,
        mode: int,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            mode,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
            cls._fsync_directory(path.parent)
        except Exception:
            try:
                temporary.unlink(missing_ok=True)
            finally:
                raise

    @classmethod
    def _write_json_atomic(
        cls,
        path: Path,
        payload: dict[str, object],
    ) -> None:
        cls._write_bytes_atomic(
            path,
            (
                json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode(),
            mode=0o600,
        )

    @staticmethod
    def _read_json(path: Path) -> dict[str, object]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SensorCredentialError(
                f"invalid sensor credential metadata: {path}"
            ) from exc
        if not isinstance(payload, dict):
            raise SensorCredentialError(
                f"sensor credential metadata must be an object: {path}"
            )
        return payload

    def _cleanup_temporary_artifacts(self) -> None:
        for parent in (self.root, self.generations_dir):
            for path in parent.iterdir():
                if path.name.startswith(".") and (
                    path.name.endswith(".tmp")
                    or path.name.startswith(".tmp-")
                ):
                    if path.is_dir():
                        shutil.rmtree(path, ignore_errors=True)
                    else:
                        path.unlink(missing_ok=True)
            self._fsync_directory(parent)

    def _bind_metadata(self) -> None:
        expected = {
            "schema_version": self._SCHEMA_VERSION,
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "sensor_id": self.sensor_id,
        }
        if not self.metadata_file.exists():
            self._write_json_atomic(self.metadata_file, expected)
            return
        actual = self._read_json(self.metadata_file)
        for key, value in expected.items():
            if actual.get(key) != value:
                raise SensorCredentialError(
                    f"sensor credential store {key} mismatch: "
                    f"expected {value!r}, found {actual.get(key)!r}"
                )

    @contextmanager
    def rotation_lease(self) -> Iterator[None]:
        lock_file = self.root / "rotation.lock"
        descriptor = os.open(
            lock_file,
            os.O_RDWR | os.O_CREAT,
            0o600,
        )
        try:
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(
                        descriptor,
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
            except (BlockingIOError, OSError) as exc:
                raise SensorCredentialBusyError(
                    "another collector owns sensor credential rotation"
                ) from exc
            try:
                yield
            finally:
                os.lseek(descriptor, 0, os.SEEK_SET)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    @staticmethod
    def _public_key_bytes(public_key: object) -> bytes:
        return public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _load_private_key(self, path: Path) -> object:
        password = (
            self.private_key_password.encode()
            if self.private_key_password
            else None
        )
        try:
            return serialization.load_pem_private_key(
                path.read_bytes(),
                password=password,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise SensorCredentialError(
                f"invalid sensor private key: {path}"
            ) from exc

    def _validate_material(
        self,
        certificate_file: Path,
        private_key_file: Path,
    ) -> SensorCredentialGeneration:
        try:
            certificate = x509.load_pem_x509_certificate(
                certificate_file.read_bytes()
            )
        except (OSError, ValueError) as exc:
            raise SensorCredentialError(
                f"invalid sensor certificate: {certificate_file}"
            ) from exc
        private_key = self._load_private_key(private_key_file)
        if self._public_key_bytes(certificate.public_key()) != self._public_key_bytes(
            private_key.public_key()
        ):
            raise SensorCredentialError(
                "sensor certificate public key does not match private key"
            )

        expected_spiffe = sensor_spiffe_uri(
            self.tenant_id,
            self.site_id,
            self.sensor_id,
        )
        try:
            eku = certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
            san = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
        except x509.ExtensionNotFound as exc:
            raise SensorCredentialError(
                "sensor certificate is missing required identity extensions"
            ) from exc
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
            raise SensorCredentialError(
                "sensor certificate is not valid for client authentication"
            )
        sensor_uris = [
            uri
            for uri in san.get_values_for_type(
                x509.UniformResourceIdentifier
            )
            if uri.startswith("spiffe://mon.local/")
        ]
        if sensor_uris != [expected_spiffe]:
            raise SensorCredentialError(
                "sensor credential identity does not match configured scope"
            )
        generation_id = certificate_file.parent.name
        if not _GENERATION_ID.fullmatch(generation_id):
            raise SensorCredentialError("invalid sensor credential generation id")
        return SensorCredentialGeneration(
            generation_id=generation_id,
            certificate_file=certificate_file,
            private_key_file=private_key_file,
            fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
            not_before=certificate.not_valid_before_utc,
            expires_at=certificate.not_valid_after_utc,
            spiffe_uri=expected_spiffe,
        )

    def _generation_dir(self, generation_id: str) -> Path:
        if not _GENERATION_ID.fullmatch(generation_id):
            raise SensorCredentialError("invalid sensor credential generation id")
        return self.generations_dir / generation_id

    def _generation_from_id(
        self,
        generation_id: str,
    ) -> SensorCredentialGeneration:
        directory = self._generation_dir(generation_id)
        certificate_file = directory / "certificate.pem"
        private_key_file = directory / "private-key.pem"
        if not certificate_file.is_file() or not private_key_file.is_file():
            raise SensorCredentialError(
                f"sensor credential generation is incomplete: {generation_id}"
            )
        return self._validate_material(certificate_file, private_key_file)

    def _install_generation_directory(
        self,
        generation_id: str,
        *,
        private_key_pem: str,
        certificate_pem: str | None,
        csr_pem: str | None,
        created_at: dt.datetime,
    ) -> Path:
        final_directory = self._generation_dir(generation_id)
        if final_directory.exists():
            return final_directory

        temporary = self.generations_dir / f".tmp-{generation_id}-{uuid.uuid4().hex}"
        temporary.mkdir(mode=0o700)
        try:
            self._write_bytes_atomic(
                temporary / "private-key.pem",
                private_key_pem.encode(),
                mode=0o600,
            )
            if certificate_pem is not None:
                self._write_bytes_atomic(
                    temporary / "certificate.pem",
                    certificate_pem.encode(),
                    mode=0o644,
                )
            if csr_pem is not None:
                self._write_bytes_atomic(
                    temporary / "request.csr.pem",
                    csr_pem.encode(),
                    mode=0o600,
                )
            self._write_json_atomic(
                temporary / "generation.json",
                {
                    "generation_id": generation_id,
                    "created_at": created_at.astimezone(dt.UTC).isoformat(),
                },
            )
            self._fsync_directory(temporary)
            os.replace(temporary, final_directory)
            self._fsync_directory(self.generations_dir)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return final_directory

    def _import_bootstrap_generation(self) -> None:
        if (
            self.bootstrap_certificate_file is None
            or self.bootstrap_private_key_file is None
            or not self.bootstrap_certificate_file.is_file()
            or not self.bootstrap_private_key_file.is_file()
        ):
            raise SensorCredentialError(
                "bootstrap sensor certificate and private key are required "
                "when the managed credential store is uninitialized"
            )
        try:
            certificate = x509.load_pem_x509_certificate(
                self.bootstrap_certificate_file.read_bytes()
            )
        except (OSError, ValueError) as exc:
            raise SensorCredentialError(
                "bootstrap sensor certificate is invalid"
            ) from exc
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        generation_id = f"bootstrap-{fingerprint[:24]}"
        directory = self._install_generation_directory(
            generation_id,
            private_key_pem=self.bootstrap_private_key_file.read_text(
                encoding="utf-8"
            ),
            certificate_pem=self.bootstrap_certificate_file.read_text(
                encoding="utf-8"
            ),
            csr_pem=None,
            created_at=dt.datetime.now(dt.UTC),
        )
        generation = self._validate_material(
            directory / "certificate.pem",
            directory / "private-key.pem",
        )
        if generation.fingerprint_sha256 != fingerprint:
            raise SensorCredentialError(
                "bootstrap sensor fingerprint changed during import"
            )
        self._write_json_atomic(
            self.active_file,
            {"generation_id": generation_id},
        )

    def _recover_completed_activation(self) -> None:
        if not self.pending_file.exists() or not self.active_file.exists():
            return
        pending = self.pending_renewal()
        active_payload = self._read_json(self.active_file)
        if active_payload.get("generation_id") == pending.generation_id:
            self.pending_file.unlink(missing_ok=True)
            self._fsync_directory(self.root)

    def active_generation(self) -> SensorCredentialGeneration:
        payload = self._read_json(self.active_file)
        generation_id = payload.get("generation_id")
        if not isinstance(generation_id, str):
            raise SensorCredentialError(
                "active sensor credential generation id is missing"
            )
        return self._generation_from_id(generation_id)

    def pending_renewal(self) -> PendingSensorRenewal | None:
        if not self.pending_file.exists():
            return None
        payload = self._read_json(self.pending_file)
        try:
            generation_id = str(payload["generation_id"])
            fingerprint = str(payload["current_fingerprint_sha256"])
            csr_pem = str(payload["csr_pem"])
            created_at = dt.datetime.fromisoformat(str(payload["created_at"]))
        except (KeyError, ValueError) as exc:
            raise SensorCredentialError(
                "pending sensor renewal metadata is invalid"
            ) from exc
        if not _GENERATION_ID.fullmatch(generation_id):
            raise SensorCredentialError("pending sensor generation id is invalid")
        if len(fingerprint) != 64:
            raise SensorCredentialError(
                "pending sensor renewal fingerprint is invalid"
            )
        if created_at.tzinfo is None or created_at.utcoffset() is None:
            raise SensorCredentialError(
                "pending sensor renewal created_at must be timezone-aware"
            )
        if not (self._generation_dir(generation_id) / "private-key.pem").is_file():
            raise SensorCredentialError(
                "pending sensor renewal private key is missing"
            )
        return PendingSensorRenewal(
            generation_id=generation_id,
            current_fingerprint_sha256=fingerprint,
            csr_pem=csr_pem,
            created_at=created_at.astimezone(dt.UTC),
        )

    def pending_generation(self) -> SensorCredentialGeneration | None:
        pending = self.pending_renewal()
        if pending is None:
            return None
        certificate = self._generation_dir(pending.generation_id) / "certificate.pem"
        if not certificate.is_file():
            return None
        return self._generation_from_id(pending.generation_id)

    def discard_stale_pending(self) -> bool:
        pending = self.pending_renewal()
        if pending is None:
            return False
        active = self.active_generation()
        if pending.current_fingerprint_sha256 == active.fingerprint_sha256:
            return False
        directory = self._generation_dir(pending.generation_id)
        self.pending_file.unlink(missing_ok=True)
        self._fsync_directory(self.root)
        if directory.exists() and directory.name != active.generation_id:
            shutil.rmtree(directory)
            self._fsync_directory(self.generations_dir)
        return True

    def renewal_due(
        self,
        *,
        now: dt.datetime | None = None,
        renew_before: dt.timedelta,
    ) -> bool:
        if renew_before <= dt.timedelta(0):
            raise ValueError("renew_before must be positive")
        if self.pending_file.exists():
            return True
        check_at = (now or dt.datetime.now(dt.UTC)).astimezone(dt.UTC)
        active = self.active_generation()
        certificate_lifetime = active.expires_at - active.not_before
        if renew_before >= certificate_lifetime:
            raise SensorCredentialError(
                "sensor renewal lead time must be shorter than "
                "the active certificate lifetime"
            )
        return active.expires_at - check_at <= renew_before

    def begin_renewal(
        self,
        *,
        now: dt.datetime | None = None,
    ) -> PendingSensorRenewal:
        existing = self.pending_renewal()
        if existing is not None:
            return existing

        created_at = (now or dt.datetime.now(dt.UTC)).astimezone(dt.UTC)
        active = self.active_generation()
        if active.expires_at <= created_at:
            raise SensorCredentialError(
                "active sensor certificate expired before renewal completed"
            )

        private_key_pem, csr_pem, spiffe_uri = generate_sensor_key_and_csr(
            self.tenant_id,
            self.site_id,
            self.sensor_id,
            password=self.private_key_password,
        )
        expected_spiffe = sensor_spiffe_uri(
            self.tenant_id,
            self.site_id,
            self.sensor_id,
        )
        if spiffe_uri != expected_spiffe:
            raise SensorCredentialError(
                "generated sensor CSR identity does not match configured scope"
            )

        generation_id = f"gen-{uuid.uuid4().hex}"
        self._install_generation_directory(
            generation_id,
            private_key_pem=private_key_pem,
            certificate_pem=None,
            csr_pem=csr_pem,
            created_at=created_at,
        )
        pending = PendingSensorRenewal(
            generation_id=generation_id,
            current_fingerprint_sha256=active.fingerprint_sha256,
            csr_pem=csr_pem,
            created_at=created_at,
        )
        self._write_json_atomic(
            self.pending_file,
            {
                "generation_id": pending.generation_id,
                "current_fingerprint_sha256": (
                    pending.current_fingerprint_sha256
                ),
                "csr_pem": pending.csr_pem,
                "created_at": pending.created_at.isoformat(),
            },
        )
        return pending

    @staticmethod
    def _verify_issuer_signature(
        certificate: x509.Certificate,
        ca_certificate: x509.Certificate,
    ) -> None:
        try:
            constraints = ca_certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound as exc:
            raise SensorCredentialError(
                "returned sensor CA lacks BasicConstraints"
            ) from exc
        if not constraints.ca:
            raise SensorCredentialError(
                "returned sensor issuing certificate is not a CA"
            )
        if ca_certificate.not_valid_after_utc <= dt.datetime.now(dt.UTC):
            raise SensorCredentialError("returned sensor CA is expired")
        if certificate.issuer != ca_certificate.subject:
            raise SensorCredentialError(
                "renewed sensor certificate issuer does not match returned CA"
            )
        public_key = ca_certificate.public_key()
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    certificate.signature_hash_algorithm,
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    ec.ECDSA(certificate.signature_hash_algorithm),
                )
            else:
                raise SensorCredentialError(
                    "unsupported sensor CA public-key type"
                )
        except InvalidSignature as exc:
            raise SensorCredentialError(
                "renewed sensor certificate signature is invalid"
            ) from exc

    def install_renewal_result(
        self,
        result: SensorRenewalResult,
    ) -> SensorCredentialGeneration:
        pending = self.pending_renewal()
        if pending is None:
            raise SensorCredentialError(
                "cannot install sensor renewal without pending state"
            )
        active = self.active_generation()
        if active.fingerprint_sha256 != pending.current_fingerprint_sha256:
            raise SensorCredentialError(
                "pending renewal no longer matches active sensor credential"
            )

        issued = result.certificate
        if (
            issued.tenant_id != self.tenant_id
            or issued.site_id != self.site_id
            or issued.sensor_id != self.sensor_id
        ):
            raise SensorCredentialError(
                "renewal response scope does not match sensor credential store"
            )
        expected_spiffe = sensor_spiffe_uri(
            self.tenant_id,
            self.site_id,
            self.sensor_id,
        )
        if issued.spiffe_uri != expected_spiffe:
            raise SensorCredentialError(
                "renewal response SPIFFE identity does not match sensor"
            )

        directory = self._generation_dir(pending.generation_id)
        private_key = self._load_private_key(directory / "private-key.pem")
        try:
            certificate = x509.load_pem_x509_certificate(
                issued.certificate_pem.encode()
            )
            ca_certificate = x509.load_pem_x509_certificate(
                issued.ca_certificate_pem.encode()
            )
        except ValueError as exc:
            raise SensorCredentialError(
                "renewal response contains invalid certificate material"
            ) from exc
        if self._public_key_bytes(certificate.public_key()) != self._public_key_bytes(
            private_key.public_key()
        ):
            raise SensorCredentialError(
                "renewed certificate does not match pending private key"
            )
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        if fingerprint != issued.fingerprint_sha256:
            raise SensorCredentialError(
                "renewal response fingerprint does not match certificate"
            )
        if (
            issued.expires_at.tzinfo is None
            or issued.expires_at.utcoffset() is None
        ):
            raise SensorCredentialError(
                "renewal response expiry must be timezone-aware"
            )
        if certificate.not_valid_after_utc != issued.expires_at.astimezone(dt.UTC):
            raise SensorCredentialError(
                "renewal response expiry does not match certificate"
            )
        self._verify_issuer_signature(certificate, ca_certificate)

        now = dt.datetime.now(dt.UTC)
        if certificate.not_valid_before_utc > now:
            raise SensorCredentialError(
                "renewed sensor certificate is not valid yet"
            )
        if certificate.not_valid_after_utc <= now:
            raise SensorCredentialError(
                "renewed sensor certificate is already expired"
            )
        try:
            eku = certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
            san = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
        except x509.ExtensionNotFound as exc:
            raise SensorCredentialError(
                "renewed sensor certificate is missing identity extensions"
            ) from exc
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
            raise SensorCredentialError(
                "renewed sensor certificate lacks client-auth usage"
            )
        sensor_uris = san.get_values_for_type(
            x509.UniformResourceIdentifier
        )
        if sensor_uris != [expected_spiffe]:
            raise SensorCredentialError(
                "renewed certificate identity does not match configured sensor"
            )

        self._write_bytes_atomic(
            directory / "certificate.pem",
            issued.certificate_pem.encode(),
            mode=0o644,
        )
        self._write_bytes_atomic(
            directory / "issuing-ca.pem",
            issued.ca_certificate_pem.encode(),
            mode=0o644,
        )
        self._write_json_atomic(
            directory / "generation.json",
            {
                "generation_id": pending.generation_id,
                "created_at": pending.created_at.isoformat(),
                "fingerprint_sha256": fingerprint,
                "expires_at": certificate.not_valid_after_utc.isoformat(),
            },
        )
        return self._generation_from_id(pending.generation_id)

    def ssl_context_for(
        self,
        generation: SensorCredentialGeneration,
    ) -> ssl.SSLContext:
        return create_mtls_client_ssl_context(
            str(self.server_ca_certificate_file),
            str(generation.certificate_file),
            str(generation.private_key_file),
            private_key_password=self.private_key_password,
        )

    def activate_pending(self) -> SensorCredentialGeneration:
        pending = self.pending_renewal()
        if pending is None:
            raise SensorCredentialError(
                "cannot activate sensor credential without pending renewal"
            )
        generation = self._generation_from_id(pending.generation_id)
        self._write_json_atomic(
            self.active_file,
            {"generation_id": pending.generation_id},
        )
        self.pending_file.unlink(missing_ok=True)
        self._fsync_directory(self.root)
        return generation

    def prune_generations(self, retain_total: int = 2) -> int:
        if retain_total < 1 or retain_total > 10:
            raise ValueError("retain_total must be between 1 and 10")
        active_id = self.active_generation().generation_id
        pending = self.pending_renewal()
        protected = {active_id}
        if pending is not None:
            protected.add(pending.generation_id)

        candidates = [
            path
            for path in self.generations_dir.iterdir()
            if path.is_dir()
            and not path.name.startswith(".")
            and path.name not in protected
        ]
        candidates.sort(key=lambda path: path.stat().st_mtime_ns, reverse=True)
        keep_extra = max(0, retain_total - len(protected))
        removed = 0
        for path in candidates[keep_extra:]:
            shutil.rmtree(path)
            removed += 1
        if removed:
            self._fsync_directory(self.generations_dir)
        return removed

    def diagnostics(
        self,
        *,
        now: dt.datetime | None = None,
    ) -> dict[str, object]:
        check_at = (now or dt.datetime.now(dt.UTC)).astimezone(dt.UTC)
        active = self.active_generation()
        pending = self.pending_renewal()
        return {
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "sensor_id": self.sensor_id,
            "active_generation_id": active.generation_id,
            "active_fingerprint_sha256": active.fingerprint_sha256,
            "active_expires_at": active.expires_at.isoformat(),
            "active_seconds_remaining": max(
                0,
                int((active.expires_at - check_at).total_seconds()),
            ),
            "renewal_pending": pending is not None,
            "pending_generation_id": (
                pending.generation_id if pending is not None else None
            ),
            "durability": "FSYNC_ATOMIC_POINTER",
        }


async def _rotate_sensor_credentials_locked(
    store: SensorCredentialStore,
    client: SensorCredentialClient,
    *,
    renew_before: dt.timedelta,
    check_at: dt.datetime,
) -> dict[str, object]:
    active = store.active_generation()
    if (
        client.credential_fingerprint_sha256 is not None
        and client.credential_fingerprint_sha256
        != active.fingerprint_sha256
    ):
        store.discard_stale_pending()
        active = store.active_generation()
        active_context = store.ssl_context_for(active)
        await client.probe_ssl_context(
            active_context,
            tenant_id=store.tenant_id,
            site_id=store.site_id,
            sensor_id=store.sensor_id,
        )
        await client.replace_ssl_context(
            active_context,
            fingerprint_sha256=active.fingerprint_sha256,
        )

    if not store.renewal_due(now=check_at, renew_before=renew_before):
        active = store.active_generation()
        return {
            "state": "CURRENT",
            "fingerprint_sha256": active.fingerprint_sha256,
            "expires_at": active.expires_at.isoformat(),
        }

    pending = store.begin_renewal(now=check_at)
    candidate = store.pending_generation()
    if candidate is not None:
        candidate_context = store.ssl_context_for(candidate)
        try:
            await client.probe_ssl_context(
                candidate_context,
                tenant_id=store.tenant_id,
                site_id=store.site_id,
                sensor_id=store.sensor_id,
            )
        except SensorCredentialTransportError:
            pass
        else:
            activated = store.activate_pending()
            await client.replace_ssl_context(
                candidate_context,
                fingerprint_sha256=activated.fingerprint_sha256,
            )
            store.prune_generations()
            return {
                "state": "ROTATED",
                "generation_id": activated.generation_id,
                "fingerprint_sha256": activated.fingerprint_sha256,
                "expires_at": activated.expires_at.isoformat(),
                "recovered_pending": True,
            }

    result = await client.renew_certificate(pending.csr_pem)
    candidate = store.install_renewal_result(result)
    candidate_context = store.ssl_context_for(candidate)
    await client.probe_ssl_context(
        candidate_context,
        tenant_id=store.tenant_id,
        site_id=store.site_id,
        sensor_id=store.sensor_id,
    )
    activated = store.activate_pending()
    await client.replace_ssl_context(
        candidate_context,
        fingerprint_sha256=activated.fingerprint_sha256,
    )
    store.prune_generations()
    return {
        "state": "ROTATED",
        "generation_id": activated.generation_id,
        "fingerprint_sha256": activated.fingerprint_sha256,
        "expires_at": activated.expires_at.isoformat(),
        "recovered_pending": False,
    }


async def rotate_sensor_credentials_if_due(
    store: SensorCredentialStore,
    client: SensorCredentialClient,
    *,
    renew_before: dt.timedelta,
    now: dt.datetime | None = None,
) -> dict[str, object]:
    check_at = (now or dt.datetime.now(dt.UTC)).astimezone(dt.UTC)
    try:
        with store.rotation_lease():
            return await _rotate_sensor_credentials_locked(
                store,
                client,
                renew_before=renew_before,
                check_at=check_at,
            )
    except SensorCredentialBusyError:
        return {"state": "BUSY"}
