"""add durable response execution and audit records

Revision ID: 0003_response_audit
Revises: 0002_site_identity
Create Date: 2026-09-18
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_response_audit"
down_revision: str | None = "0002_site_identity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "response_executions",
        sa.Column("pk", sa.String(length=900), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("execution_id", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_response_executions_scope",
        "response_executions",
        ["tenant_id", "site_id"],
    )
    op.create_index(
        "ix_response_executions_status",
        "response_executions",
        ["tenant_id", "site_id", "status"],
    )

    op.create_table(
        "audit_records",
        sa.Column("pk", sa.String(length=900), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("audit_id", sa.String(length=256), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_audit_records_scope",
        "audit_records",
        ["tenant_id", "site_id", "occurred_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_audit_records_scope", table_name="audit_records")
    op.drop_table("audit_records")
    op.drop_index("ix_response_executions_status", table_name="response_executions")
    op.drop_index("ix_response_executions_scope", table_name="response_executions")
    op.drop_table("response_executions")
