import datetime as dt

import pytest
from sqlalchemy import text

from mon.audit_integrity import AuditIntegrityError, audit_record_sha256
from mon.database import DatabaseStore
from mon.domain import AuditRecord
from mon.store import InMemoryStore


def audit_record(*, outcome: str = "APPLIED") -> AuditRecord:
    return AuditRecord(
        audit_id="audit-1",
        tenant_id="tenant-a",
        site_id="site-1",
        actor_id="operator-1",
        category="RESPONSE",
        object_type="response_execution",
        object_id="response-1",
        action="EXECUTE",
        outcome=outcome,
        occurred_at=dt.datetime(2026, 9, 19, 8, 0, tzinfo=dt.UTC),
        details={"reason": "confirmed response", "confidence": 0.9},
    )


def test_audit_digest_is_stable_for_the_same_record() -> None:
    record = audit_record()
    assert audit_record_sha256(record) == audit_record_sha256(record.model_copy())


def test_in_memory_audit_identity_is_append_only() -> None:
    store = InMemoryStore()
    record = audit_record()
    assert store.add_audit_record(record) == record
    assert store.add_audit_record(record) == record

    with pytest.raises(AuditIntegrityError):
        store.add_audit_record(audit_record(outcome="ROLLED_BACK"))


def test_database_audit_identity_is_append_only_and_replay_safe(tmp_path) -> None:
    store = DatabaseStore(
        f"sqlite+pysqlite:///{tmp_path / 'audit.db'}",
        create_schema=True,
    )
    try:
        record = audit_record()
        assert store.add_audit_record(record) == record
        assert store.add_audit_record(record) == record

        with pytest.raises(AuditIntegrityError):
            store.add_audit_record(audit_record(outcome="ROLLED_BACK"))

        assert store.list_audit_records("tenant-a", "site-1") == [record]
    finally:
        store.close()


def test_database_detects_audit_payload_tampering(tmp_path) -> None:
    store = DatabaseStore(
        f"sqlite+pysqlite:///{tmp_path / 'tamper.db'}",
        create_schema=True,
    )
    try:
        record = audit_record()
        store.add_audit_record(record)
        with store.engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE audit_records "
                    "SET record_sha256 = :digest "
                    "WHERE audit_id = :audit_id"
                ),
                {
                    "digest": "0" * 64,
                    "audit_id": record.audit_id,
                },
            )

        with pytest.raises(AuditIntegrityError):
            store.list_audit_records("tenant-a", "site-1")
    finally:
        store.close()
