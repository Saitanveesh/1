import base64
import datetime as dt
import json
import os
from dataclasses import replace

import pytest
from sqlalchemy import text

from mon.connector_secrets import (
    ConnectorSecretCipher,
    ConnectorSecretIntegrityError,
    ConnectorSecretKeyUnavailable,
    ConnectorSecretKeyring,
    ConnectorSecretNotFound,
    ConnectorSecretVault,
)
from mon.database import DatabaseStore


def keyring(
    active_key_id: str,
    keys: dict[str, bytes] | None = None,
) -> ConnectorSecretKeyring:
    return ConnectorSecretKeyring(
        active_key_id=active_key_id,
        keys=keys or {active_key_id: active_key_id.encode().ljust(32, b"-")[:32]},
    )


def test_vault_encrypts_at_rest_and_audits_without_plaintext(tmp_path) -> None:
    store = DatabaseStore(
        f"sqlite+pysqlite:///{tmp_path / 'secrets.db'}",
        create_schema=True,
    )
    plaintext = b"connector-api-token-value"
    vault = ConnectorSecretVault(store, keyring("key-a"))
    now = dt.datetime(2026, 9, 19, 9, 0, tzinfo=dt.UTC)

    try:
        metadata = vault.put(
            tenant_id="tenant-a",
            site_id="site-1",
            secret_id="edge-firewall",
            plaintext=plaintext,
            actor_id="operator-1",
            now=now,
        )

        assert metadata.secret_id == "edge-firewall"
        assert metadata.key_id == "key-a"
        assert vault.resolve(
            "tenant-a",
            "site-1",
            "edge-firewall",
        ) == plaintext

        with store.engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT nonce, ciphertext, key_id "
                    "FROM connector_secrets WHERE secret_id = :secret_id"
                ),
                {"secret_id": "edge-firewall"},
            ).mappings().one()
        assert len(row["nonce"]) == 12
        assert plaintext not in bytes(row["ciphertext"])
        assert row["key_id"] == "key-a"

        audits = store.list_audit_records("tenant-a", "site-1")
        assert [record.action for record in audits] == ["PUT"]
        serialized = json.dumps(
            [record.model_dump(mode="json") for record in audits],
            sort_keys=True,
        )
        assert plaintext.decode() not in serialized
        assert audits[0].details == {"key_id": "key-a"}

        with pytest.raises(ConnectorSecretNotFound):
            vault.resolve("tenant-b", "site-1", "edge-firewall")
    finally:
        store.close()


def test_cipher_aad_rejects_cross_scope_record_swap() -> None:
    cipher = ConnectorSecretCipher(keyring("key-a"))
    record = cipher.encrypt(
        tenant_id="tenant-a",
        site_id="site-1",
        secret_id="router",
        plaintext=b"opaque-secret",
        now=dt.datetime(2026, 9, 19, 9, 0, tzinfo=dt.UTC),
    )

    swapped = replace(record, tenant_id="tenant-b")
    with pytest.raises(ConnectorSecretIntegrityError):
        cipher.decrypt(swapped)


def test_missing_old_key_fails_closed() -> None:
    old_cipher = ConnectorSecretCipher(keyring("old-key"))
    record = old_cipher.encrypt(
        tenant_id="tenant-a",
        site_id="site-1",
        secret_id="waf",
        plaintext=b"secret",
    )

    new_cipher = ConnectorSecretCipher(keyring("new-key"))
    with pytest.raises(ConnectorSecretKeyUnavailable):
        new_cipher.decrypt(record)


def test_rotate_reencrypts_with_active_key_and_preserves_plaintext(tmp_path) -> None:
    store = DatabaseStore(
        f"sqlite+pysqlite:///{tmp_path / 'rotate.db'}",
        create_schema=True,
    )
    old_key = b"a" * 32
    new_key = b"b" * 32
    old_vault = ConnectorSecretVault(
        store,
        keyring("old", {"old": old_key}),
    )
    value = b"cloud-connector-secret"

    try:
        old_vault.put(
            tenant_id="tenant-a",
            site_id="site-1",
            secret_id="cloud-a",
            plaintext=value,
            actor_id="operator-1",
        )
        rotating = ConnectorSecretVault(
            store,
            keyring(
                "new",
                {
                    "old": old_key,
                    "new": new_key,
                },
            ),
        )
        metadata = rotating.rotate(
            tenant_id="tenant-a",
            site_id="site-1",
            secret_id="cloud-a",
            actor_id="operator-2",
        )

        assert metadata.key_id == "new"
        assert rotating.resolve("tenant-a", "site-1", "cloud-a") == value
        assert [
            item.action
            for item in store.list_audit_records("tenant-a", "site-1")
        ] == ["PUT", "REKEY"]
    finally:
        store.close()


def test_delete_removes_ciphertext_and_writes_nonsecret_audit(tmp_path) -> None:
    store = DatabaseStore(
        f"sqlite+pysqlite:///{tmp_path / 'delete.db'}",
        create_schema=True,
    )
    vault = ConnectorSecretVault(store, keyring("key-a"))
    try:
        vault.put(
            tenant_id="tenant-a",
            site_id="site-1",
            secret_id="nac-a",
            plaintext=b"delete-me",
            actor_id="operator-1",
        )
        assert vault.delete(
            tenant_id="tenant-a",
            site_id="site-1",
            secret_id="nac-a",
            actor_id="operator-2",
        )
        assert not vault.delete(
            tenant_id="tenant-a",
            site_id="site-1",
            secret_id="nac-a",
            actor_id="operator-2",
        )
        with pytest.raises(ConnectorSecretNotFound):
            vault.resolve("tenant-a", "site-1", "nac-a")
        assert [
            item.action
            for item in store.list_audit_records("tenant-a", "site-1")
        ] == ["PUT", "DELETE"]
    finally:
        store.close()


def test_keyring_file_requires_private_permissions(tmp_path) -> None:
    path = tmp_path / "connector-keyring.json"
    document = {
        "active_key_id": "key-a",
        "keys": {
            "key-a": base64.b64encode(b"k" * 32).decode(),
        },
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o644)
        with pytest.raises(Exception, match="group or others"):
            ConnectorSecretKeyring.from_file(path)
        path.chmod(0o600)

    loaded = ConnectorSecretKeyring.from_file(path)
    assert loaded.active_key_id == "key-a"
    assert loaded.key("key-a") == b"k" * 32
