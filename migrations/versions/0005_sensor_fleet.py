"""add sensor fleet enrollment identities and health

Revision ID: 0005_sensor_fleet
Revises: 0004_site_commands
Create Date: 2026-09-19
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_sensor_fleet"
down_revision: str | None = "0004_site_commands"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sensor_enrollment_tokens",
        sa.Column("token_hash", sa.String(length=64), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("sensor_id", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_sensor_enrollment_tokens_scope",
        "sensor_enrollment_tokens",
        ["tenant_id", "site_id", "sensor_id"],
    )
    op.create_index(
        "ix_sensor_enrollment_tokens_expiry",
        "sensor_enrollment_tokens",
        ["expires_at"],
    )

    op.create_table(
        "sensor_fleet",
        sa.Column("pk", sa.String(length=900), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("sensor_id", sa.String(length=128), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_sensor_fleet_scope",
        "sensor_fleet",
        ["tenant_id", "site_id"],
    )
    op.create_index(
        "ix_sensor_fleet_last_seen",
        "sensor_fleet",
        ["tenant_id", "site_id", "last_seen_at"],
    )

    op.create_table(
        "sensor_identities",
        sa.Column("identity_id", sa.String(length=64), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("sensor_id", sa.String(length=128), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accept_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_sensor_identities_scope",
        "sensor_identities",
        ["tenant_id", "site_id", "sensor_id"],
    )
    op.create_index(
        "ix_sensor_identities_fingerprint",
        "sensor_identities",
        ["fingerprint_sha256"],
        unique=True,
    )
    op.create_index(
        "ix_sensor_identities_status",
        "sensor_identities",
        ["tenant_id", "site_id", "status", "expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_sensor_identities_status", table_name="sensor_identities")
    op.drop_index(
        "ix_sensor_identities_fingerprint",
        table_name="sensor_identities",
    )
    op.drop_index("ix_sensor_identities_scope", table_name="sensor_identities")
    op.drop_table("sensor_identities")

    op.drop_index("ix_sensor_fleet_last_seen", table_name="sensor_fleet")
    op.drop_index("ix_sensor_fleet_scope", table_name="sensor_fleet")
    op.drop_table("sensor_fleet")

    op.drop_index(
        "ix_sensor_enrollment_tokens_expiry",
        table_name="sensor_enrollment_tokens",
    )
    op.drop_index(
        "ix_sensor_enrollment_tokens_scope",
        table_name="sensor_enrollment_tokens",
    )
    op.drop_table("sensor_enrollment_tokens")
