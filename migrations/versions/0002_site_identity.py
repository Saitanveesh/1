"""add site enrollment and certificate identities

Revision ID: 0002_site_identity
Revises: 0001_control_plane
Create Date: 2026-09-18
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_site_identity"
down_revision: str | None = "0001_control_plane"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "site_enrollment_tokens",
        sa.Column("token_hash", sa.String(length=64), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_site_enrollment_tokens_scope",
        "site_enrollment_tokens",
        ["tenant_id", "site_id"],
    )
    op.create_index(
        "ix_site_enrollment_tokens_expiry",
        "site_enrollment_tokens",
        ["expires_at"],
    )

    op.create_table(
        "site_identities",
        sa.Column("identity_id", sa.String(length=64), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_site_identities_scope",
        "site_identities",
        ["tenant_id", "site_id"],
    )
    op.create_index(
        "ix_site_identities_fingerprint",
        "site_identities",
        ["fingerprint_sha256"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_site_identities_fingerprint", table_name="site_identities")
    op.drop_index("ix_site_identities_scope", table_name="site_identities")
    op.drop_table("site_identities")
    op.drop_index(
        "ix_site_enrollment_tokens_expiry",
        table_name="site_enrollment_tokens",
    )
    op.drop_index(
        "ix_site_enrollment_tokens_scope",
        table_name="site_enrollment_tokens",
    )
    op.drop_table("site_enrollment_tokens")
