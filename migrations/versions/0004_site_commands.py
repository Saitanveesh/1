"""add durable site command queue

Revision ID: 0004_site_commands
Revises: 0003_response_audit
Create Date: 2026-09-19
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_site_commands"
down_revision: str | None = "0003_response_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "site_commands",
        sa.Column("pk", sa.String(length=900), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("command_id", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_site_commands_scope",
        "site_commands",
        ["tenant_id", "site_id"],
    )
    op.create_index(
        "ix_site_commands_pending",
        "site_commands",
        ["tenant_id", "site_id", "status", "not_after"],
    )


def downgrade() -> None:
    op.drop_index("ix_site_commands_pending", table_name="site_commands")
    op.drop_index("ix_site_commands_scope", table_name="site_commands")
    op.drop_table("site_commands")
