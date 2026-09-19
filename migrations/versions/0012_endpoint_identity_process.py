"""add endpoint identity and process state

Revision ID: 0012_endpoint_identity_process
Revises: 0011_taxii_feeds
Create Date: 2026-09-19
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_endpoint_identity_process"
down_revision: str | None = "0011_taxii_feeds"
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
        "identities",
        sa.Column("pk", sa.String(length=900), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("identity_id", sa.String(length=512), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("principal", sa.String(length=512), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_identities_scope", "identities", ["tenant_id", "site_id"])
    op.create_index(
        "ix_identities_principal",
        "identities",
        ["tenant_id", "site_id", "source", "principal"],
    )
    op.create_table(
        "processes",
        sa.Column("pk", sa.String(length=900), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("process_id", sa.String(length=512), nullable=False),
        sa.Column("asset_id", sa.String(length=256), nullable=False),
        sa.Column("identity_id", sa.String(length=512), nullable=True),
        sa.Column("parent_process_id", sa.String(length=512), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_processes_scope", "processes", ["tenant_id", "site_id"])
    op.create_index(
        "ix_processes_asset",
        "processes",
        ["tenant_id", "site_id", "asset_id"],
    )
    op.create_index(
        "ix_processes_identity",
        "processes",
        ["tenant_id", "site_id", "identity_id"],
    )
    _enable_rls("identities")
    _enable_rls("processes")


def downgrade() -> None:
    _disable_rls("processes")
    _disable_rls("identities")
    op.drop_index("ix_processes_identity", table_name="processes")
    op.drop_index("ix_processes_asset", table_name="processes")
    op.drop_index("ix_processes_scope", table_name="processes")
    op.drop_table("processes")
    op.drop_index("ix_identities_principal", table_name="identities")
    op.drop_index("ix_identities_scope", table_name="identities")
    op.drop_table("identities")
