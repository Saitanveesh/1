"""enforce PostgreSQL tenant and site row-level security

Revision ID: 0008_postgres_rls
Revises: 0007_audit_integrity
Create Date: 2026-09-19
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0008_postgres_rls"
down_revision: str | None = "0007_audit_integrity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCOPED_TABLES = (
    "security_events",
    "event_processing_receipts",
    "fabric_receipts",
    "findings",
    "incidents",
    "assets",
    "enforcement_points",
    "enforcement_bindings",
    "response_executions",
    "audit_records",
    "site_commands",
    "site_identities",
    "sensor_fleet",
    "sensor_identities",
)

_TOKEN_TABLES = (
    "site_enrollment_tokens",
    "sensor_enrollment_tokens",
)


def _scope_predicate() -> str:
    return (
        "tenant_id = current_setting('mon.tenant_id', true) "
        "AND site_id = current_setting('mon.site_id', true)"
    )


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return

    predicate = _scope_predicate()
    for table_name in _SCOPED_TABLES:
        op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY mon_tenant_site_scope ON {table_name}
            USING ({predicate})
            WITH CHECK ({predicate})
            """
        )

    for table_name in _TOKEN_TABLES:
        lookup = (
            "token_hash = "
            "current_setting('mon.enrollment_token_hash', true)"
        )
        op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY mon_tenant_site_or_token_lookup ON {table_name}
            USING (({predicate}) OR ({lookup}))
            WITH CHECK ({predicate})
            """
        )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return

    for table_name in _TOKEN_TABLES:
        op.execute(
            f"DROP POLICY IF EXISTS mon_tenant_site_or_token_lookup "
            f"ON {table_name}"
        )
        op.execute(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY")

    for table_name in _SCOPED_TABLES:
        op.execute(
            f"DROP POLICY IF EXISTS mon_tenant_site_scope ON {table_name}"
        )
        op.execute(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY")
