"""Persist tenant/site-scoped range exercise receipts.

Revision ID: 0014_range_exercise_receipts
Revises: 0013_topology_observations
Create Date: 2026-10-15
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_range_exercise_receipts"
down_revision: str | None = "0013_topology_observations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "range_exercise_receipts",
        sa.Column("pk", sa.String(length=900), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("exercise_id", sa.String(length=128), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_range_exercise_receipts_scope_time",
        "range_exercise_receipts",
        ["tenant_id", "site_id", "finished_at"],
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE range_exercise_receipts ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE range_exercise_receipts FORCE ROW LEVEL SECURITY")
        predicate = (
            "tenant_id = current_setting('mon.tenant_id', true) "
            "AND site_id = current_setting('mon.site_id', true)"
        )
        op.execute(
            "CREATE POLICY mon_tenant_site_scope ON range_exercise_receipts "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS mon_tenant_site_scope ON range_exercise_receipts")
        op.execute("ALTER TABLE range_exercise_receipts NO FORCE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE range_exercise_receipts DISABLE ROW LEVEL SECURITY")
    op.drop_index(
        "ix_range_exercise_receipts_scope_time", table_name="range_exercise_receipts"
    )
    op.drop_table("range_exercise_receipts")
