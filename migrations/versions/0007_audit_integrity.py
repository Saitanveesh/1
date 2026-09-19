"""seal audit records and reject PostgreSQL mutation

Revision ID: 0007_audit_integrity
Revises: 0006_fabric_ingress
Create Date: 2026-09-19
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0007_audit_integrity"
down_revision: str | None = "0006_fabric_ingress"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        dict(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def upgrade() -> None:
    op.add_column(
        "audit_records",
        sa.Column("record_sha256", sa.String(length=64), nullable=True),
    )

    connection = op.get_bind()
    rows = connection.execute(
        sa.text("SELECT pk, payload FROM audit_records")
    ).mappings()
    for row in rows:
        payload = row["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        if not isinstance(payload, dict):
            raise RuntimeError("audit record payload is not a JSON object")
        connection.execute(
            sa.text(
                "UPDATE audit_records "
                "SET record_sha256 = :record_sha256 "
                "WHERE pk = :pk"
            ),
            {
                "pk": row["pk"],
                "record_sha256": _digest(payload),
            },
        )

    op.alter_column(
        "audit_records",
        "record_sha256",
        existing_type=sa.String(length=64),
        nullable=False,
    )

    if connection.dialect.name == "postgresql":
        op.execute(
            """
            CREATE FUNCTION mon_reject_audit_record_mutation()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION 'audit_records are append-only'
                    USING ERRCODE = '55000';
                RETURN NULL;
            END;
            $$
            """
        )
        op.execute(
            """
            CREATE TRIGGER trg_audit_records_append_only
            BEFORE UPDATE OR DELETE ON audit_records
            FOR EACH ROW
            EXECUTE FUNCTION mon_reject_audit_record_mutation()
            """
        )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS trg_audit_records_append_only "
            "ON audit_records"
        )
        op.execute(
            "DROP FUNCTION IF EXISTS mon_reject_audit_record_mutation()"
        )
    op.drop_column("audit_records", "record_sha256")
