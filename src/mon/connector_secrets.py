from __future__ import annotations

import argparse
import base64
import datetime as dt
import getpass
import json
import os
import re
import stat
import sys
from collections.abc import Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, Field

from mon.domain import AuditRecord

_MAX_SECRET_BYTES = 64 * 1024
_MAX_KEYRING_BYTES = 1024 * 1024
_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ConnectorSecretError(RuntimeError):
    pass


class ConnectorSecretNotFound(ConnectorSecretError):
    pass


class ConnectorSecretKeyUnavailable(ConnectorSecretError):
    pass


class ConnectorSecretIntegrityError(ConnectorSecretError):
    pass


@dataclass(frozen=True, slots=True)
class EncryptedConnectorSecret:
    secret_id: str
    tenant_id: str
    site_id: str
    key_id: str
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)
    created_at: dt.datetime
    updated_at: dt.datetime


class ConnectorSecretMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    secret_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    key_id: str = Field(min_length=1, max_length=128)
    created_at: dt.datetime
    updated_at: dt.datetime


class ConnectorSecretStore(Protocol):
    def transaction(self) -> AbstractContextManager[None]: ...

    def get_connector_secret_record(
        self,
        tenant_id: str,
        site_id: str,
        secret_id: str,
    ) -> EncryptedConnectorSecret | None: ...

    def put_connector_secret_record(
        self,
        record: EncryptedConnectorSecret,
    ) -> EncryptedConnectorSecret: ...

    def delete_connector_secret_record(
        self,
        tenant_id: str,
        site_id: str,
        secret_id: str,
    ) -> bool: ...

    def add_audit_record(self, record: AuditRecord) -> AuditRecord: ...


@dataclass(frozen=True, slots=True)
class ConnectorSecretKeyring:
    active_key_id: str
    keys: Mapping[str, bytes] = field(repr=False)

    def __post_init__(self) -> None:
        if not _KEY_ID_PATTERN.fullmatch(self.active_key_id):
            raise ConnectorSecretError("active connector-secret key id is invalid")
        normalized = dict(self.keys)
        if self.active_key_id not in normalized:
            raise ConnectorSecretError(
                "active connector-secret key is absent from the keyring"
            )
        if len(normalized) < 1 or len(normalized) > 32:
            raise ConnectorSecretError(
                "connector-secret keyring must contain between 1 and 32 keys"
            )
        for key_id, key in normalized.items():
            if not _KEY_ID_PATTERN.fullmatch(key_id):
                raise ConnectorSecretError(
                    "connector-secret keyring contains an invalid key id"
                )
            if not isinstance(key, bytes) or len(key) != 32:
                raise ConnectorSecretError(
                    "connector-secret encryption keys must be 32 bytes"
                )
        object.__setattr__(self, "keys", normalized)

    @classmethod
    def from_json(cls, raw: str) -> ConnectorSecretKeyring:
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ConnectorSecretError(
                "connector-secret keyring is not valid JSON"
            ) from exc
        if not isinstance(document, dict) or set(document) != {
            "active_key_id",
            "keys",
        }:
            raise ConnectorSecretError(
                "connector-secret keyring must contain only active_key_id and keys"
            )
        active_key_id = document.get("active_key_id")
        encoded_keys = document.get("keys")
        if not isinstance(active_key_id, str) or not isinstance(encoded_keys, dict):
            raise ConnectorSecretError("connector-secret keyring fields are invalid")

        keys: dict[str, bytes] = {}
        for key_id, encoded in encoded_keys.items():
            if not isinstance(key_id, str) or not isinstance(encoded, str):
                raise ConnectorSecretError("connector-secret key entries are invalid")
            try:
                key = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError) as exc:
                raise ConnectorSecretError(
                    "connector-secret key is not valid base64"
                ) from exc
            keys[key_id] = key
        return cls(active_key_id=active_key_id, keys=keys)

    @classmethod
    def from_file(cls, path: str | Path) -> ConnectorSecretKeyring:
        keyring_path = Path(path)
        try:
            file_stat = keyring_path.stat()
        except OSError as exc:
            raise ConnectorSecretError(
                "connector-secret keyring file is unavailable"
            ) from exc
        if not stat.S_ISREG(file_stat.st_mode):
            raise ConnectorSecretError(
                "connector-secret keyring path must be a regular file"
            )
        if os.name == "posix" and file_stat.st_mode & 0o077:
            raise ConnectorSecretError(
                "connector-secret keyring file must not be accessible by group or others"
            )
        if file_stat.st_size > _MAX_KEYRING_BYTES:
            raise ConnectorSecretError("connector-secret keyring file is too large")
        try:
            raw = keyring_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConnectorSecretError(
                "connector-secret keyring file is unreadable"
            ) from exc
        return cls.from_json(raw)

    def key(self, key_id: str) -> bytes:
        value = self.keys.get(key_id)
        if value is None:
            raise ConnectorSecretKeyUnavailable(
                f"connector-secret key {key_id!r} is unavailable"
            )
        return value


def _validate_scope_value(value: str, *, field_name: str, maximum: int) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise ConnectorSecretError(f"{field_name} is invalid")
    return normalized


def _aad(
    tenant_id: str,
    site_id: str,
    secret_id: str,
) -> bytes:
    return json.dumps(
        ["mon-connector-secret", 1, tenant_id, site_id, secret_id],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


class ConnectorSecretCipher:
    def __init__(self, keyring: ConnectorSecretKeyring) -> None:
        self.keyring = keyring

    def encrypt(
        self,
        *,
        tenant_id: str,
        site_id: str,
        secret_id: str,
        plaintext: bytes,
        created_at: dt.datetime | None = None,
        now: dt.datetime | None = None,
    ) -> EncryptedConnectorSecret:
        tenant_id = _validate_scope_value(
            tenant_id,
            field_name="tenant_id",
            maximum=128,
        )
        site_id = _validate_scope_value(site_id, field_name="site_id", maximum=128)
        secret_id = _validate_scope_value(
            secret_id,
            field_name="secret_id",
            maximum=256,
        )
        if not isinstance(plaintext, bytes) or not plaintext:
            raise ConnectorSecretError("connector secret must not be empty")
        if len(plaintext) > _MAX_SECRET_BYTES:
            raise ConnectorSecretError(
                f"connector secret exceeds {_MAX_SECRET_BYTES} bytes"
            )

        timestamp = now or dt.datetime.now(dt.UTC)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ConnectorSecretError("connector-secret timestamp must be timezone-aware")
        timestamp = timestamp.astimezone(dt.UTC)
        created = created_at or timestamp
        if created.tzinfo is None or created.utcoffset() is None:
            raise ConnectorSecretError("connector-secret created_at must be timezone-aware")
        created = created.astimezone(dt.UTC)

        nonce = os.urandom(12)
        key_id = self.keyring.active_key_id
        ciphertext = AESGCM(self.keyring.key(key_id)).encrypt(
            nonce,
            plaintext,
            _aad(tenant_id, site_id, secret_id),
        )
        return EncryptedConnectorSecret(
            secret_id=secret_id,
            tenant_id=tenant_id,
            site_id=site_id,
            key_id=key_id,
            nonce=nonce,
            ciphertext=ciphertext,
            created_at=created,
            updated_at=timestamp,
        )

    def decrypt(self, record: EncryptedConnectorSecret) -> bytes:
        if len(record.nonce) != 12 or not record.ciphertext:
            raise ConnectorSecretIntegrityError(
                "connector-secret encrypted record is malformed"
            )
        key = self.keyring.key(record.key_id)
        try:
            plaintext = AESGCM(key).decrypt(
                record.nonce,
                record.ciphertext,
                _aad(record.tenant_id, record.site_id, record.secret_id),
            )
        except InvalidTag as exc:
            raise ConnectorSecretIntegrityError(
                "connector-secret authentication failed"
            ) from exc
        if not plaintext or len(plaintext) > _MAX_SECRET_BYTES:
            raise ConnectorSecretIntegrityError(
                "connector-secret plaintext failed bounds validation"
            )
        return plaintext


def _metadata(record: EncryptedConnectorSecret) -> ConnectorSecretMetadata:
    return ConnectorSecretMetadata(
        secret_id=record.secret_id,
        tenant_id=record.tenant_id,
        site_id=record.site_id,
        key_id=record.key_id,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


class ConnectorSecretVault:
    """Encrypt connector credentials at rest and expose plaintext only to connector code."""

    def __init__(
        self,
        store: ConnectorSecretStore,
        keyring: ConnectorSecretKeyring,
    ) -> None:
        self.store = store
        self.cipher = ConnectorSecretCipher(keyring)

    def put(
        self,
        *,
        tenant_id: str,
        site_id: str,
        secret_id: str,
        plaintext: bytes,
        actor_id: str,
        now: dt.datetime | None = None,
    ) -> ConnectorSecretMetadata:
        actor_id = _validate_scope_value(
            actor_id,
            field_name="actor_id",
            maximum=256,
        )
        with self.store.transaction():
            existing = self.store.get_connector_secret_record(
                tenant_id,
                site_id,
                secret_id,
            )
            encrypted = self.cipher.encrypt(
                tenant_id=tenant_id,
                site_id=site_id,
                secret_id=secret_id,
                plaintext=plaintext,
                created_at=existing.created_at if existing is not None else None,
                now=now,
            )
            self.store.put_connector_secret_record(encrypted)
            self.store.add_audit_record(
                AuditRecord(
                    tenant_id=encrypted.tenant_id,
                    site_id=encrypted.site_id,
                    actor_id=actor_id,
                    category="CONNECTOR_SECRET",
                    object_type="connector_secret",
                    object_id=encrypted.secret_id,
                    action="PUT",
                    outcome="STORED",
                    occurred_at=encrypted.updated_at,
                    details={"key_id": encrypted.key_id},
                )
            )
        return _metadata(encrypted)

    def metadata(
        self,
        tenant_id: str,
        site_id: str,
        secret_id: str,
    ) -> ConnectorSecretMetadata:
        record = self.store.get_connector_secret_record(
            tenant_id,
            site_id,
            secret_id,
        )
        if record is None:
            raise ConnectorSecretNotFound("connector secret was not found")
        return _metadata(record)

    def resolve(
        self,
        tenant_id: str,
        site_id: str,
        secret_id: str,
    ) -> bytes:
        record = self.store.get_connector_secret_record(
            tenant_id,
            site_id,
            secret_id,
        )
        if record is None:
            raise ConnectorSecretNotFound("connector secret was not found")
        return self.cipher.decrypt(record)

    def rotate(
        self,
        *,
        tenant_id: str,
        site_id: str,
        secret_id: str,
        actor_id: str,
        now: dt.datetime | None = None,
    ) -> ConnectorSecretMetadata:
        actor_id = _validate_scope_value(
            actor_id,
            field_name="actor_id",
            maximum=256,
        )
        with self.store.transaction():
            existing = self.store.get_connector_secret_record(
                tenant_id,
                site_id,
                secret_id,
            )
            if existing is None:
                raise ConnectorSecretNotFound("connector secret was not found")
            plaintext = self.cipher.decrypt(existing)
            encrypted = self.cipher.encrypt(
                tenant_id=existing.tenant_id,
                site_id=existing.site_id,
                secret_id=existing.secret_id,
                plaintext=plaintext,
                created_at=existing.created_at,
                now=now,
            )
            self.store.put_connector_secret_record(encrypted)
            self.store.add_audit_record(
                AuditRecord(
                    tenant_id=encrypted.tenant_id,
                    site_id=encrypted.site_id,
                    actor_id=actor_id,
                    category="CONNECTOR_SECRET",
                    object_type="connector_secret",
                    object_id=encrypted.secret_id,
                    action="REKEY",
                    outcome="STORED",
                    occurred_at=encrypted.updated_at,
                    details={
                        "previous_key_id": existing.key_id,
                        "key_id": encrypted.key_id,
                    },
                )
            )
        return _metadata(encrypted)

    def delete(
        self,
        *,
        tenant_id: str,
        site_id: str,
        secret_id: str,
        actor_id: str,
        now: dt.datetime | None = None,
    ) -> bool:
        actor_id = _validate_scope_value(
            actor_id,
            field_name="actor_id",
            maximum=256,
        )
        occurred_at = now or dt.datetime.now(dt.UTC)
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise ConnectorSecretError("connector-secret timestamp must be timezone-aware")
        occurred_at = occurred_at.astimezone(dt.UTC)
        with self.store.transaction():
            existing = self.store.get_connector_secret_record(
                tenant_id,
                site_id,
                secret_id,
            )
            if existing is None:
                return False
            deleted = self.store.delete_connector_secret_record(
                tenant_id,
                site_id,
                secret_id,
            )
            if not deleted:
                raise ConnectorSecretError(
                    "connector secret disappeared during deletion"
                )
            self.store.add_audit_record(
                AuditRecord(
                    tenant_id=existing.tenant_id,
                    site_id=existing.site_id,
                    actor_id=actor_id,
                    category="CONNECTOR_SECRET",
                    object_type="connector_secret",
                    object_id=existing.secret_id,
                    action="DELETE",
                    outcome="DELETED",
                    occurred_at=occurred_at,
                    details={"key_id": existing.key_id},
                )
            )
        return True


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mon-connector-secret",
        description=(
            "Provision encrypted MON connector credentials. "
            "Secret plaintext is accepted only on stdin."
        ),
    )
    parser.add_argument(
        "--keyring-file",
        default=os.environ.get("MON_CONNECTOR_SECRET_KEYRING_FILE", ""),
        help="protected JSON keyring file (or MON_CONNECTOR_SECRET_KEYRING_FILE)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def scope_arguments(command: argparse.ArgumentParser) -> None:
        command.add_argument("--tenant", required=True)
        command.add_argument("--site", required=True)
        command.add_argument("--secret-id", required=True)

    put = subparsers.add_parser("put", help="encrypt and store a secret from stdin")
    scope_arguments(put)
    put.add_argument("--actor", required=True)

    rotate = subparsers.add_parser(
        "rotate",
        help="re-encrypt an existing secret with the active key",
    )
    scope_arguments(rotate)
    rotate.add_argument("--actor", required=True)

    delete = subparsers.add_parser("delete", help="delete an encrypted secret")
    scope_arguments(delete)
    delete.add_argument("--actor", required=True)

    metadata = subparsers.add_parser(
        "metadata",
        help="show non-secret metadata only",
    )
    scope_arguments(metadata)
    return parser


def _read_secret_stdin() -> bytes:
    if sys.stdin.isatty():
        raise ConnectorSecretError(
            "refusing interactive secret input; pipe or redirect secret bytes to stdin"
        )
    value = sys.stdin.buffer.read(_MAX_SECRET_BYTES + 1)
    if len(value) > _MAX_SECRET_BYTES:
        raise ConnectorSecretError(
            f"connector secret exceeds {_MAX_SECRET_BYTES} bytes"
        )
    if not value:
        raise ConnectorSecretError("connector secret must not be empty")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = _build_cli_parser()
    args = parser.parse_args(argv)
    database_url = os.environ.get("MON_DATABASE_URL", "").strip()
    if not database_url:
        parser.error("MON_DATABASE_URL is required")
    if not args.keyring_file:
        parser.error(
            "--keyring-file or MON_CONNECTOR_SECRET_KEYRING_FILE is required"
        )

    from mon.database import DatabaseStore

    store = DatabaseStore(database_url)
    try:
        keyring = ConnectorSecretKeyring.from_file(args.keyring_file)
        vault = ConnectorSecretVault(store, keyring)
        if args.command == "put":
            result = vault.put(
                tenant_id=args.tenant,
                site_id=args.site,
                secret_id=args.secret_id,
                plaintext=_read_secret_stdin(),
                actor_id=args.actor,
            )
        elif args.command == "rotate":
            result = vault.rotate(
                tenant_id=args.tenant,
                site_id=args.site,
                secret_id=args.secret_id,
                actor_id=args.actor,
            )
        elif args.command == "delete":
            deleted = vault.delete(
                tenant_id=args.tenant,
                site_id=args.site,
                secret_id=args.secret_id,
                actor_id=args.actor,
            )
            result = {"deleted": deleted}
        else:
            result = vault.metadata(
                args.tenant,
                args.site,
                args.secret_id,
            )
        if isinstance(result, BaseModel):
            output = result.model_dump(mode="json")
        else:
            output = result
        sys.stdout.write(json.dumps(output, sort_keys=True) + "\n")
        return 0
    except ConnectorSecretError as exc:
        sys.stderr.write(f"connector-secret operation failed: {exc}\n")
        return 2
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
