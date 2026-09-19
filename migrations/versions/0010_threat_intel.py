"""add STIX threat intelligence indicators

Revision ID: 0010_threat_intel
Revises: 0009_connector_secrets
Create Date: 2026-09-19
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_threat_intel"
down_revision: str | None = "0009_connector_secrets"
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
        "threat_intel_sources",
        sa.Column("pk", sa.String(length=900), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("source_id", sa.String(length=256), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_threat_intel_sources_scope",
        "threat_intel_sources",
        ["tenant_id", "site_id"],
    )

    op.create_table(
        "threat_indicators",
        sa.Column("pk", sa.String(length=900), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("indicator_id", sa.String(length=256), nullable=False),
        sa.Column("source_id", sa.String(length=256), nullable=False),
        sa.Column("stix_id", sa.String(length=512), nullable=False),
        sa.Column("indicator_type", sa.String(length=32), nullable=False),
        sa.Column("normalized_value", sa.String(length=2048), nullable=False),
        sa.Column("revoked", sa.String(length=5), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stix_modified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_threat_indicators_scope",
        "threat_indicators",
        ["tenant_id", "site_id"],
    )
    op.create_index(
        "ix_threat_indicators_match",
        "threat_indicators",
        ["tenant_id", "site_id", "indicator_type", "normalized_value"],
    )
    op.create_index(
        "ix_threat_indicators_source",
        "threat_indicators",
        ["tenant_id", "site_id", "source_id"],
    )
    _enable_rls("threat_intel_sources")
    _enable_rls("threat_indicators")


def downgrade() -> None:
    _disable_rls("threat_indicators")
    _disable_rls("threat_intel_sources")
    op.drop_index("ix_threat_indicators_source", table_name="threat_indicators")
    op.drop_index("ix_threat_indicators_match", table_name="threat_indicators")
    op.drop_index("ix_threat_indicators_scope", table_name="threat_indicators")
    op.drop_table("threat_indicators")
    op.drop_index(
        "ix_threat_intel_sources_scope",
        table_name="threat_intel_sources",
    )
    op.drop_table("threat_intel_sources")
