"""add encrypted connector secret vault

Revision ID: 0009_connector_secrets
Revises: 0008_postgres_rls
Create Date: 2026-09-19
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_connector_secrets"
down_revision: str | None = "0008_postgres_rls"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "connector_secrets",
        sa.Column("pk", sa.String(length=900), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("site_id", sa.String(length=128), nullable=False),
        sa.Column("secret_id", sa.String(length=256), nullable=False),
        sa.Column("key_id", sa.String(length=128), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_connector_secrets_scope",
        "connector_secrets",
        ["tenant_id", "site_id", "secret_id"],
    )

    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        predicate = (
            "tenant_id = current_setting('mon.tenant_id', true) "
            "AND site_id = current_setting('mon.site_id', true)"
        )
        op.execute("ALTER TABLE connector_secrets ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE connector_secrets FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY mon_tenant_site_scope ON connector_secrets
            USING ({predicate})
            WITH CHECK ({predicate})
            """
        )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        op.execute(
            "DROP POLICY IF EXISTS mon_tenant_site_scope "
            "ON connector_secrets"
        )
        op.execute(
            "ALTER TABLE connector_secrets NO FORCE ROW LEVEL SECURITY"
        )
        op.execute(
            "ALTER TABLE connector_secrets DISABLE ROW LEVEL SECURITY"
        )

    op.drop_index(
        "ix_connector_secrets_scope",
        table_name="connector_secrets",
    )
    op.drop_table("connector_secrets")
