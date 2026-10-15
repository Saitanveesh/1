"""Persist immutable, scoped topology observations.

Revision ID: 0013_topology_observations
Revises: 0012_endpoint_identity_process
Create Date: 2026-10-15
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_topology_observations"
down_revision: str | None = "0012_endpoint_identity_process"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "topology_observations",
        sa.Column("pk", sa.String(length=900), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("observation_id", sa.String(length=256), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_topology_observations_scope_time",
        "topology_observations",
        ["tenant_id", "site_id", "observed_at"],
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE topology_observations ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE topology_observations FORCE ROW LEVEL SECURITY")
        predicate = (
            "tenant_id = current_setting('mon.tenant_id', true) "
            "AND site_id = current_setting('mon.site_id', true)"
        )
        op.execute(
            "CREATE POLICY mon_tenant_site_scope ON topology_observations "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS mon_tenant_site_scope ON topology_observations")
        op.execute("ALTER TABLE topology_observations NO FORCE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE topology_observations DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_topology_observations_scope_time", table_name="topology_observations")
    op.drop_table("topology_observations")
