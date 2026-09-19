"""add atomic event processing receipts and fabric receipts

Revision ID: 0006_fabric_ingress
Revises: 0005_sensor_fleet
Create Date: 2026-09-19
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_fabric_ingress"
down_revision: str | None = "0005_sensor_fleet"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "event_processing_receipts",
        sa.Column("pk", sa.String(length=900), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("event_id", sa.String(length=256), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_event_processing_scope",
        "event_processing_receipts",
        ["tenant_id", "site_id", "processed_at"],
    )

    op.create_table(
        "fabric_receipts",
        sa.Column("pk", sa.String(length=900), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("event_id", sa.String(length=256), nullable=False),
        sa.Column("envelope_sha256", sa.String(length=64), nullable=False),
        sa.Column("envelope_json", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_fabric_receipts_scope",
        "fabric_receipts",
        ["tenant_id", "site_id", "received_at"],
    )
    op.create_index(
        "ix_fabric_receipts_status",
        "fabric_receipts",
        ["tenant_id", "site_id", "status", "received_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_fabric_receipts_status", table_name="fabric_receipts")
    op.drop_index("ix_fabric_receipts_scope", table_name="fabric_receipts")
    op.drop_table("fabric_receipts")

    op.drop_index(
        "ix_event_processing_scope",
        table_name="event_processing_receipts",
    )
    op.drop_table("event_processing_receipts")
