"""create initial control-plane tables

Revision ID: 0001_control_plane
Revises:
Create Date: 2026-09-18
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_control_plane"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _payload_table(
    name: str,
    id_column: str,
    *,
    asset_column: bool = False,
) -> None:
    columns = [
        sa.Column("pk", sa.String(length=900), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column(id_column, sa.String(length=256), nullable=False),
    ]
    if asset_column:
        columns.append(sa.Column("asset_id", sa.String(length=256), nullable=False))
    columns.append(sa.Column("payload", sa.JSON(), nullable=False))
    op.create_table(name, *columns)
    op.create_index(f"ix_{name}_scope", name, ["tenant_id", "site_id"])


def upgrade() -> None:
    _payload_table("security_events", "event_id")
    op.create_index(
        "ix_security_events_event_id",
        "security_events",
        ["event_id"],
    )
    _payload_table("findings", "finding_id")
    _payload_table("incidents", "incident_id")
    _payload_table("assets", "asset_id")
    _payload_table("enforcement_points", "enforcement_point_id")
    _payload_table(
        "enforcement_bindings",
        "binding_id",
        asset_column=True,
    )
    op.create_index(
        "ix_enforcement_bindings_asset",
        "enforcement_bindings",
        ["tenant_id", "site_id", "asset_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_enforcement_bindings_asset", table_name="enforcement_bindings")
    op.drop_table("enforcement_bindings")
    op.drop_table("enforcement_points")
    op.drop_table("assets")
    op.drop_table("incidents")
    op.drop_table("findings")
    op.drop_index("ix_security_events_event_id", table_name="security_events")
    op.drop_table("security_events")
