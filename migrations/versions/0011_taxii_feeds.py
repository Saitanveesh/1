"""add TAXII threat intelligence feeds

Revision ID: 0011_taxii_feeds
Revises: 0010_threat_intel
Create Date: 2026-09-19
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_taxii_feeds"
down_revision: str | None = "0010_threat_intel"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _enable_rls(table_name: str) -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    predicate = (
        "tenant_id = current_setting('mon.tenant_id', true) "
        "AND site_id = current_setting('mon.site_id', true)"
    )
    op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"""
        CREATE POLICY mon_tenant_site_scope ON {table_name}
        USING ({predicate})
        WITH CHECK ({predicate})
        """
    )


def _disable_rls(table_name: str) -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return
    op.execute(f"DROP POLICY IF EXISTS mon_tenant_site_scope ON {table_name}")
    op.execute(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY")


def upgrade() -> None:
    op.create_table(
        "taxii_feeds",
        sa.Column("pk", sa.String(length=900), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("feed_id", sa.String(length=256), nullable=False),
        sa.Column("enabled", sa.String(length=5), nullable=False),
        sa.Column("health", sa.String(length=64), nullable=False),
        sa.Column("next_attempt_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_successful_sync", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_taxii_feeds_scope",
        "taxii_feeds",
        ["tenant_id", "site_id"],
    )
    op.create_index(
        "ix_taxii_feeds_due",
        "taxii_feeds",
        ["tenant_id", "site_id", "enabled", "next_attempt_after"],
    )
    _enable_rls("taxii_feeds")


def downgrade() -> None:
    _disable_rls("taxii_feeds")
    op.drop_index("ix_taxii_feeds_due", table_name="taxii_feeds")
    op.drop_index("ix_taxii_feeds_scope", table_name="taxii_feeds")
    op.drop_table("taxii_feeds")
