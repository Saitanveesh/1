from __future__ import annotations

import datetime as dt
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import JSON, DateTime, Index, String, Text, create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from mon.audit_integrity import AuditIntegrityError, audit_record_sha256
from mon.domain import (
    Asset,
    AuditRecord,
    EnforcementBinding,
    EnforcementPoint,
    Finding,
    Incident,
    ResponseExecution,
    SecurityEvent,
)
from mon.event_fabric import FabricReceipt, FabricReceiptStatus
from mon.sensor_fleet_models import (
    SensorEnrollmentTokenRecord,
    SensorHeartbeat,
    SensorIdentityRecord,
    SensorIdentityStatus,
    SensorRecord,
)
from mon.site_command_models import SiteCommandRecord
from mon.site_identity_models import EnrollmentTokenRecord, SiteIdentityRecord
from mon.store import InMemoryStore, Store


class Base(DeclarativeBase):
    pass


class EventRow(Base):
    __tablename__ = "security_events"

    pk: Mapped[str] = mapped_column(String(900), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_id: Mapped[str] = mapped_column(String(256), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (
        Index("ix_security_events_scope", "tenant_id", "site_id"),
        Index("ix_security_events_event_id", "event_id"),
    )


class EventProcessingRow(Base):
    __tablename__ = "event_processing_receipts"

    pk: Mapped[str] = mapped_column(String(900), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_id: Mapped[str] = mapped_column(String(256), nullable=False)
    processed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    __table_args__ = (
        Index(
            "ix_event_processing_scope",
            "tenant_id",
            "site_id",
            "processed_at",
        ),
    )


class FabricReceiptRow(Base):
    __tablename__ = "fabric_receipts"

    pk: Mapped[str] = mapped_column(String(900), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_id: Mapped[str] = mapped_column(String(256), nullable=False)
    envelope_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    envelope_json: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    received_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    processed_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        Index(
            "ix_fabric_receipts_scope",
            "tenant_id",
            "site_id",
            "received_at",
        ),
        Index(
            "ix_fabric_receipts_status",
            "tenant_id",
            "site_id",
            "status",
            "received_at",
        ),
    )


class FindingRow(Base):
    __tablename__ = "findings"

    pk: Mapped[str] = mapped_column(String(900), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(256), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (Index("ix_findings_scope", "tenant_id", "site_id"),)


class IncidentRow(Base):
    __tablename__ = "incidents"

    pk: Mapped[str] = mapped_column(String(900), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(256), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (Index("ix_incidents_scope", "tenant_id", "site_id"),)


class AssetRow(Base):
    __tablename__ = "assets"

    pk: Mapped[str] = mapped_column(String(900), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(256), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (Index("ix_assets_scope", "tenant_id", "site_id"),)


class EnforcementPointRow(Base):
    __tablename__ = "enforcement_points"

    pk: Mapped[str] = mapped_column(String(900), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    enforcement_point_id: Mapped[str] = mapped_column(String(256), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (Index("ix_enforcement_points_scope", "tenant_id", "site_id"),)


class EnforcementBindingRow(Base):
    __tablename__ = "enforcement_bindings"

    pk: Mapped[str] = mapped_column(String(900), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    binding_id: Mapped[str] = mapped_column(String(256), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(256), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (
        Index("ix_enforcement_bindings_scope", "tenant_id", "site_id"),
        Index("ix_enforcement_bindings_asset", "tenant_id", "site_id", "asset_id"),
    )


class ResponseExecutionRow(Base):
    __tablename__ = "response_executions"

    pk: Mapped[str] = mapped_column(String(900), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    execution_id: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (
        Index("ix_response_executions_scope", "tenant_id", "site_id"),
        Index("ix_response_executions_status", "tenant_id", "site_id", "status"),
    )


class AuditRecordRow(Base):
    __tablename__ = "audit_records"

    pk: Mapped[str] = mapped_column(String(900), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    audit_id: Mapped[str] = mapped_column(String(256), nullable=False)
    occurred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    record_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (
        Index("ix_audit_records_scope", "tenant_id", "site_id", "occurred_at"),
    )


class SiteCommandRow(Base):
    __tablename__ = "site_commands"

    pk: Mapped[str] = mapped_column(String(900), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    command_id: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    not_after: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (
        Index("ix_site_commands_scope", "tenant_id", "site_id"),
        Index("ix_site_commands_pending", "tenant_id", "site_id", "status", "not_after"),
    )


class EnrollmentTokenRow(Base):
    __tablename__ = "site_enrollment_tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (
        Index("ix_site_enrollment_tokens_scope", "tenant_id", "site_id"),
        Index("ix_site_enrollment_tokens_expiry", "expires_at"),
    )


class SiteIdentityRow(Base):
    __tablename__ = "site_identities"

    identity_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (
        Index("ix_site_identities_scope", "tenant_id", "site_id"),
        Index(
            "ix_site_identities_fingerprint",
            "fingerprint_sha256",
            unique=True,
        ),
    )


class SensorEnrollmentTokenRow(Base):
    __tablename__ = "sensor_enrollment_tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sensor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (
        Index(
            "ix_sensor_enrollment_tokens_scope",
            "tenant_id",
            "site_id",
            "sensor_id",
        ),
        Index("ix_sensor_enrollment_tokens_expiry", "expires_at"),
    )


class SensorRecordRow(Base):
    __tablename__ = "sensor_fleet"

    pk: Mapped[str] = mapped_column(String(900), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sensor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (
        Index("ix_sensor_fleet_scope", "tenant_id", "site_id"),
        Index("ix_sensor_fleet_last_seen", "tenant_id", "site_id", "last_seen_at"),
    )


class SensorIdentityRow(Base):
    __tablename__ = "sensor_identities"

    identity_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    site_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sensor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accept_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    __table_args__ = (
        Index(
            "ix_sensor_identities_scope",
            "tenant_id",
            "site_id",
            "sensor_id",
        ),
        Index(
            "ix_sensor_identities_fingerprint",
            "fingerprint_sha256",
            unique=True,
        ),
        Index(
            "ix_sensor_identities_status",
            "tenant_id",
            "site_id",
            "status",
            "expires_at",
        ),
    )


def _key(tenant_id: str, site_id: str, object_id: str) -> str:
    return f"{tenant_id}\x1f{site_id}\x1f{object_id}"


class DatabaseStore:
    """Durable tenant-scoped control-plane repository."""

    def __init__(self, database_url: str, *, create_schema: bool = False) -> None:
        self.database_url = database_url
        self.engine = create_engine(database_url, pool_pre_ping=True)
        self._session_factory = sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
            class_=Session,
        )
        self._transaction_state = threading.local()
        if create_schema:
            Base.metadata.create_all(self.engine)

    def close(self) -> None:
        if getattr(self._transaction_state, "session", None) is not None:
            raise RuntimeError("cannot close DatabaseStore during an active transaction")
        self.engine.dispose()

    def _active_session(self) -> Session | None:
        value = getattr(self._transaction_state, "session", None)
        return value if isinstance(value, Session) else None

    def _apply_rls_scope(
        self,
        session: Session,
        tenant_id: str,
        site_id: str,
    ) -> None:
        """Bind PostgreSQL row-level security to one tenant/site transaction."""
        if self.engine.dialect.name != "postgresql":
            return
        if not tenant_id or not site_id:
            raise ValueError("tenant_id and site_id are required for PostgreSQL scope")

        if self._active_session() is session:
            current = getattr(self._transaction_state, "rls_scope", None)
            requested = (tenant_id, site_id)
            if current is not None and current != requested:
                raise RuntimeError(
                    "one database transaction cannot cross tenant/site RLS scope"
                )
            self._transaction_state.rls_scope = requested

        session.execute(
            text(
                "SELECT "
                "set_config('mon.tenant_id', :tenant_id, true), "
                "set_config('mon.site_id', :site_id, true)"
            ),
            {"tenant_id": tenant_id, "site_id": site_id},
        )

    def _apply_enrollment_token_lookup(
        self,
        session: Session,
        token_hash: str,
    ) -> None:
        """Permit exact opaque enrollment-token lookup without widening tenant scope."""
        if self.engine.dialect.name != "postgresql":
            return
        if not token_hash:
            raise ValueError("enrollment token hash is required")
        session.execute(
            text(
                "SELECT set_config("
                "'mon.enrollment_token_hash', :token_hash, true"
                ")"
            ),
            {"token_hash": token_hash},
        )

    @contextmanager
    def transaction(self) -> Iterator[None]:
        if self._active_session() is not None:
            raise RuntimeError("nested database transactions are not supported")
        with self._session_factory.begin() as session:
            self._transaction_state.session = session
            self._transaction_state.rls_scope = None
            try:
                yield
            finally:
                self._transaction_state.rls_scope = None
                self._transaction_state.session = None

    def event_exists(self, tenant_id: str, site_id: str, event_id: str) -> bool:
        return self.get_event(tenant_id, site_id, event_id) is not None

    def get_event(
        self,
        tenant_id: str,
        site_id: str,
        event_id: str,
    ) -> SecurityEvent | None:
        row = self._get(EventRow, tenant_id, site_id, event_id)
        return SecurityEvent.model_validate(row.payload) if row else None

    def event_processed(
        self,
        tenant_id: str,
        site_id: str,
        event_id: str,
    ) -> bool:
        row = self._get(
            EventProcessingRow,
            tenant_id,
            site_id,
            event_id,
        )
        return row is not None

    def add_event(self, event: SecurityEvent) -> SecurityEvent:
        existing = self.get_event(
            event.tenant_id,
            event.site_id,
            event.event_id,
        )
        if existing is not None:
            if existing != event:
                raise ValueError(
                    "event_id already exists with different content "
                    "in control-plane store"
                )
            return existing

        row = EventRow(
            pk=_key(event.tenant_id, event.site_id, event.event_id),
            tenant_id=event.tenant_id,
            site_id=event.site_id,
            event_id=event.event_id,
            payload=event.model_dump(mode="json"),
        )
        active = self._active_session()
        if active is not None:
            self._apply_rls_scope(active, event.tenant_id, event.site_id)
            active.add(row)
            active.flush()
            return event

        try:
            with self._session_factory.begin() as session:
                self._apply_rls_scope(session, event.tenant_id, event.site_id)
                session.add(row)
                session.flush()
        except IntegrityError:
            existing = self.get_event(
                event.tenant_id,
                event.site_id,
                event.event_id,
            )
            if existing is None:
                raise
            if existing != event:
                raise ValueError(
                    "event_id already exists with different content "
                    "in control-plane store"
                ) from None
            return existing
        return event

    def mark_event_processed(self, event: SecurityEvent) -> None:
        current = self.get_event(
            event.tenant_id,
            event.site_id,
            event.event_id,
        )
        if current is None:
            raise ValueError(
                "cannot mark an event processed before its durable event record"
            )
        if current != event:
            raise ValueError(
                "processed event content does not match durable event record"
            )

        row = EventProcessingRow(
            pk=_key(event.tenant_id, event.site_id, event.event_id),
            tenant_id=event.tenant_id,
            site_id=event.site_id,
            event_id=event.event_id,
            processed_at=dt.datetime.now(dt.UTC),
        )
        active = self._active_session()
        if active is not None:
            self._apply_rls_scope(active, event.tenant_id, event.site_id)
            if active.get(EventProcessingRow, row.pk) is None:
                active.add(row)
                active.flush()
            return

        with self._session_factory.begin() as session:
            self._apply_rls_scope(session, event.tenant_id, event.site_id)
            if session.get(EventProcessingRow, row.pk) is None:
                session.add(row)

    def list_events(
        self,
        tenant_id: str,
        site_id: str,
        *,
        since: dt.datetime | None = None,
    ) -> list[SecurityEvent]:
        rows = self._list_scope(EventRow, tenant_id, site_id)
        events = [SecurityEvent.model_validate(row.payload) for row in rows]
        if since is not None:
            events = [event for event in events if event.observed_at >= since]
        return sorted(events, key=lambda event: (event.observed_at, event.event_id))

    def list_unprocessed_events(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[SecurityEvent]:
        statement = (
            select(EventRow)
            .outerjoin(
                EventProcessingRow,
                EventProcessingRow.pk == EventRow.pk,
            )
            .where(
                EventRow.tenant_id == tenant_id,
                EventRow.site_id == site_id,
                EventProcessingRow.pk.is_(None),
            )
            .order_by(EventRow.event_id)
        )
        active = self._active_session()
        if active is not None:
            self._apply_rls_scope(active, tenant_id, site_id)
            rows = active.scalars(statement).all()
        else:
            with self._session_factory() as session:
                self._apply_rls_scope(session, tenant_id, site_id)
                rows = session.scalars(statement).all()
        return [
            SecurityEvent.model_validate(row.payload)
            for row in rows
        ]

    def add_finding(self, finding: Finding) -> Finding:
        self._merge(
            FindingRow(
                pk=_key(finding.tenant_id, finding.site_id, finding.finding_id),
                tenant_id=finding.tenant_id,
                site_id=finding.site_id,
                finding_id=finding.finding_id,
                payload=finding.model_dump(mode="json"),
            )
        )
        return finding

    def list_findings(self, tenant_id: str, site_id: str) -> list[Finding]:
        rows = self._list_scope(FindingRow, tenant_id, site_id)
        return [Finding.model_validate(row.payload) for row in rows]

    def add_incident(self, incident: Incident) -> Incident:
        self._merge(
            IncidentRow(
                pk=_key(incident.tenant_id, incident.site_id, incident.incident_id),
                tenant_id=incident.tenant_id,
                site_id=incident.site_id,
                incident_id=incident.incident_id,
                payload=incident.model_dump(mode="json"),
            )
        )
        return incident

    def list_incidents(self, tenant_id: str, site_id: str) -> list[Incident]:
        rows = self._list_scope(IncidentRow, tenant_id, site_id)
        return [Incident.model_validate(row.payload) for row in rows]

    def get_incident(
        self,
        tenant_id: str,
        site_id: str,
        incident_id: str,
    ) -> Incident | None:
        row = self._get(IncidentRow, tenant_id, site_id, incident_id)
        return Incident.model_validate(row.payload) if row else None

    def add_asset(self, asset: Asset) -> Asset:
        self._merge(
            AssetRow(
                pk=_key(asset.tenant_id, asset.site_id, asset.asset_id),
                tenant_id=asset.tenant_id,
                site_id=asset.site_id,
                asset_id=asset.asset_id,
                payload=asset.model_dump(mode="json"),
            )
        )
        return asset

    def get_asset(self, tenant_id: str, site_id: str, asset_id: str) -> Asset | None:
        row = self._get(AssetRow, tenant_id, site_id, asset_id)
        return Asset.model_validate(row.payload) if row else None

    def list_assets(self, tenant_id: str, site_id: str) -> list[Asset]:
        rows = self._list_scope(AssetRow, tenant_id, site_id)
        return [Asset.model_validate(row.payload) for row in rows]

    def add_enforcement_point(self, point: EnforcementPoint) -> EnforcementPoint:
        self._merge(
            EnforcementPointRow(
                pk=_key(point.tenant_id, point.site_id, point.enforcement_point_id),
                tenant_id=point.tenant_id,
                site_id=point.site_id,
                enforcement_point_id=point.enforcement_point_id,
                payload=point.model_dump(mode="json"),
            )
        )
        return point

    def get_enforcement_point(
        self,
        tenant_id: str,
        site_id: str,
        enforcement_point_id: str,
    ) -> EnforcementPoint | None:
        row = self._get(
            EnforcementPointRow,
            tenant_id,
            site_id,
            enforcement_point_id,
        )
        return EnforcementPoint.model_validate(row.payload) if row else None

    def list_enforcement_points(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[EnforcementPoint]:
        rows = self._list_scope(EnforcementPointRow, tenant_id, site_id)
        return [EnforcementPoint.model_validate(row.payload) for row in rows]

    def add_enforcement_binding(self, binding: EnforcementBinding) -> EnforcementBinding:
        self._merge(
            EnforcementBindingRow(
                pk=_key(binding.tenant_id, binding.site_id, binding.binding_id),
                tenant_id=binding.tenant_id,
                site_id=binding.site_id,
                binding_id=binding.binding_id,
                asset_id=binding.asset_id,
                payload=binding.model_dump(mode="json"),
            )
        )
        return binding

    def list_enforcement_bindings(
        self,
        tenant_id: str,
        site_id: str,
        asset_id: str | None = None,
    ) -> list[EnforcementBinding]:
        statement = select(EnforcementBindingRow).where(
            EnforcementBindingRow.tenant_id == tenant_id,
            EnforcementBindingRow.site_id == site_id,
        )
        if asset_id is not None:
            statement = statement.where(EnforcementBindingRow.asset_id == asset_id)
        with self._session_factory() as session:
            self._apply_rls_scope(session, tenant_id, site_id)
            rows = session.scalars(statement).all()
        return [EnforcementBinding.model_validate(row.payload) for row in rows]

    def add_response_execution(
        self,
        execution: ResponseExecution,
    ) -> ResponseExecution:
        self._merge(
            ResponseExecutionRow(
                pk=_key(
                    execution.tenant_id,
                    execution.site_id,
                    execution.execution_id,
                ),
                tenant_id=execution.tenant_id,
                site_id=execution.site_id,
                execution_id=execution.execution_id,
                status=execution.status.value,
                payload=execution.model_dump(mode="json"),
            )
        )
        return execution

    def get_response_execution(
        self,
        tenant_id: str,
        site_id: str,
        execution_id: str,
    ) -> ResponseExecution | None:
        row = self._get(
            ResponseExecutionRow,
            tenant_id,
            site_id,
            execution_id,
        )
        return ResponseExecution.model_validate(row.payload) if row else None

    def list_response_executions(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[ResponseExecution]:
        rows = self._list_scope(ResponseExecutionRow, tenant_id, site_id)
        return [ResponseExecution.model_validate(row.payload) for row in rows]

    @staticmethod
    def _verified_audit_record(row: AuditRecordRow) -> AuditRecord:
        record = AuditRecord.model_validate(row.payload)
        expected = audit_record_sha256(record)
        if row.record_sha256 != expected:
            raise AuditIntegrityError(
                f"audit record {record.audit_id} failed SHA-256 verification"
            )
        return record

    def add_audit_record(self, record: AuditRecord) -> AuditRecord:
        existing_row = self._get(
            AuditRecordRow,
            record.tenant_id,
            record.site_id,
            record.audit_id,
        )
        if existing_row is not None:
            existing = self._verified_audit_record(existing_row)
            if existing != record:
                raise AuditIntegrityError(
                    "audit_id already exists with different immutable content"
                )
            return existing

        row = AuditRecordRow(
            pk=_key(record.tenant_id, record.site_id, record.audit_id),
            tenant_id=record.tenant_id,
            site_id=record.site_id,
            audit_id=record.audit_id,
            occurred_at=record.occurred_at,
            record_sha256=audit_record_sha256(record),
            payload=record.model_dump(mode="json"),
        )
        active = self._active_session()
        if active is not None:
            self._apply_rls_scope(active, record.tenant_id, record.site_id)
            active.add(row)
            active.flush()
            return record

        try:
            with self._session_factory.begin() as session:
                self._apply_rls_scope(session, record.tenant_id, record.site_id)
                session.add(row)
                session.flush()
        except IntegrityError:
            existing_row = self._get(
                AuditRecordRow,
                record.tenant_id,
                record.site_id,
                record.audit_id,
            )
            if existing_row is None:
                raise
            existing = self._verified_audit_record(existing_row)
            if existing != record:
                raise AuditIntegrityError(
                    "audit_id already exists with different immutable content"
                ) from None
            return existing
        return record

    def list_audit_records(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[AuditRecord]:
        statement = (
            select(AuditRecordRow)
            .where(
                AuditRecordRow.tenant_id == tenant_id,
                AuditRecordRow.site_id == site_id,
            )
            .order_by(AuditRecordRow.occurred_at, AuditRecordRow.audit_id)
        )
        active = self._active_session()
        if active is not None:
            self._apply_rls_scope(active, tenant_id, site_id)
            rows = active.scalars(statement).all()
        else:
            with self._session_factory() as session:
                self._apply_rls_scope(session, tenant_id, site_id)
                rows = session.scalars(statement).all()
        return [self._verified_audit_record(row) for row in rows]

    def add_site_command(self, record: SiteCommandRecord) -> SiteCommandRecord:
        command = record.command
        self._merge(
            SiteCommandRow(
                pk=_key(command.tenant_id, command.site_id, command.command_id),
                tenant_id=command.tenant_id,
                site_id=command.site_id,
                command_id=command.command_id,
                status=record.status.value,
                not_after=command.not_after,
                payload=record.model_dump(mode="json"),
            )
        )
        return record

    def get_site_command(
        self,
        tenant_id: str,
        site_id: str,
        command_id: str,
    ) -> SiteCommandRecord | None:
        row = self._get(SiteCommandRow, tenant_id, site_id, command_id)
        return SiteCommandRecord.model_validate(row.payload) if row else None

    def list_site_commands(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[SiteCommandRecord]:
        rows = self._list_scope(SiteCommandRow, tenant_id, site_id)
        return [SiteCommandRecord.model_validate(row.payload) for row in rows]

    def add_enrollment_token(
        self,
        record: EnrollmentTokenRecord,
    ) -> EnrollmentTokenRecord:
        self._merge(
            EnrollmentTokenRow(
                token_hash=record.token_hash,
                tenant_id=record.tenant_id,
                site_id=record.site_id,
                expires_at=record.expires_at,
                used_at=record.used_at,
                payload=record.model_dump(mode="json"),
            )
        )
        return record

    def get_enrollment_token(self, token_hash: str) -> EnrollmentTokenRecord | None:
        with self._session_factory() as session:
            self._apply_enrollment_token_lookup(session, token_hash)
            row = session.get(EnrollmentTokenRow, token_hash)
        return EnrollmentTokenRecord.model_validate(row.payload) if row else None

    def consume_enrollment_token(
        self,
        token_hash: str,
        now: dt.datetime,
    ) -> EnrollmentTokenRecord | None:
        statement = (
            select(EnrollmentTokenRow)
            .where(EnrollmentTokenRow.token_hash == token_hash)
            .with_for_update()
        )
        with self._session_factory.begin() as session:
            self._apply_enrollment_token_lookup(session, token_hash)
            row = session.scalar(statement)
            if row is None:
                return None
            record = EnrollmentTokenRecord.model_validate(row.payload)
            if record.used_at is not None or record.expires_at <= now:
                return None
            self._apply_rls_scope(session, record.tenant_id, record.site_id)
            consumed = record.model_copy(update={"used_at": now})
            row.used_at = now
            row.payload = consumed.model_dump(mode="json")
            return consumed

    def add_site_identity(self, record: SiteIdentityRecord) -> SiteIdentityRecord:
        self._merge(
            SiteIdentityRow(
                identity_id=record.identity_id,
                tenant_id=record.tenant_id,
                site_id=record.site_id,
                fingerprint_sha256=record.fingerprint_sha256,
                status=record.status.value,
                payload=record.model_dump(mode="json"),
            )
        )
        return record

    def list_site_identities(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[SiteIdentityRecord]:
        statement = select(SiteIdentityRow).where(
            SiteIdentityRow.tenant_id == tenant_id,
            SiteIdentityRow.site_id == site_id,
        )
        with self._session_factory() as session:
            self._apply_rls_scope(session, tenant_id, site_id)
            rows = session.scalars(statement).all()
        return [SiteIdentityRecord.model_validate(row.payload) for row in rows]

    def add_sensor_enrollment_token(
        self,
        record: SensorEnrollmentTokenRecord,
    ) -> SensorEnrollmentTokenRecord:
        self._merge(
            SensorEnrollmentTokenRow(
                token_hash=record.token_hash,
                tenant_id=record.tenant_id,
                site_id=record.site_id,
                sensor_id=record.sensor_id,
                expires_at=record.expires_at,
                used_at=record.used_at,
                payload=record.model_dump(mode="json"),
            )
        )
        return record

    def get_sensor_enrollment_token(
        self,
        token_hash: str,
    ) -> SensorEnrollmentTokenRecord | None:
        with self._session_factory() as session:
            self._apply_enrollment_token_lookup(session, token_hash)
            row = session.get(SensorEnrollmentTokenRow, token_hash)
        return (
            SensorEnrollmentTokenRecord.model_validate(row.payload)
            if row is not None
            else None
        )

    def complete_sensor_enrollment(
        self,
        token_hash: str,
        now: dt.datetime,
        sensor: SensorRecord,
        identity: SensorIdentityRecord,
    ) -> bool:
        statement = (
            select(SensorEnrollmentTokenRow)
            .where(SensorEnrollmentTokenRow.token_hash == token_hash)
            .with_for_update()
        )
        with self._session_factory.begin() as session:
            self._apply_enrollment_token_lookup(session, token_hash)
            token_row = session.scalar(statement)
            if token_row is None:
                return False
            token = SensorEnrollmentTokenRecord.model_validate(token_row.payload)
            if (
                token.used_at is not None
                or token.expires_at <= now
                or token.tenant_id != sensor.tenant_id
                or token.site_id != sensor.site_id
                or token.sensor_id != sensor.sensor_id
                or identity.tenant_id != sensor.tenant_id
                or identity.site_id != sensor.site_id
                or identity.sensor_id != sensor.sensor_id
            ):
                return False

            self._apply_rls_scope(session, sensor.tenant_id, sensor.site_id)
            consumed = token.model_copy(
                update={
                    "used_at": now,
                    "used_identity_id": identity.identity_id,
                }
            )
            token_row.used_at = now
            token_row.payload = consumed.model_dump(mode="json")
            session.merge(
                SensorRecordRow(
                    pk=_key(sensor.tenant_id, sensor.site_id, sensor.sensor_id),
                    tenant_id=sensor.tenant_id,
                    site_id=sensor.site_id,
                    sensor_id=sensor.sensor_id,
                    last_seen_at=sensor.last_seen_at,
                    revoked_at=sensor.revoked_at,
                    payload=sensor.model_dump(mode="json"),
                )
            )
            session.add(
                SensorIdentityRow(
                    identity_id=identity.identity_id,
                    tenant_id=identity.tenant_id,
                    site_id=identity.site_id,
                    sensor_id=identity.sensor_id,
                    fingerprint_sha256=identity.fingerprint_sha256,
                    status=identity.status.value,
                    expires_at=identity.expires_at,
                    accept_until=identity.accept_until,
                    payload=identity.model_dump(mode="json"),
                )
            )
        return True

    def get_sensor_record(
        self,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
    ) -> SensorRecord | None:
        row = self._get(SensorRecordRow, tenant_id, site_id, sensor_id)
        return SensorRecord.model_validate(row.payload) if row else None

    def list_sensor_records(
        self,
        tenant_id: str,
        site_id: str,
    ) -> list[SensorRecord]:
        rows = self._list_scope(SensorRecordRow, tenant_id, site_id)
        return sorted(
            [SensorRecord.model_validate(row.payload) for row in rows],
            key=lambda item: item.sensor_id,
        )

    def get_sensor_identity(
        self,
        tenant_id: str,
        site_id: str,
        identity_id: str,
    ) -> SensorIdentityRecord | None:
        statement = select(SensorIdentityRow).where(
            SensorIdentityRow.identity_id == identity_id,
            SensorIdentityRow.tenant_id == tenant_id,
            SensorIdentityRow.site_id == site_id,
        )
        with self._session_factory() as session:
            self._apply_rls_scope(session, tenant_id, site_id)
            row = session.scalar(statement)
        return SensorIdentityRecord.model_validate(row.payload) if row else None

    def get_sensor_identity_by_fingerprint(
        self,
        tenant_id: str,
        site_id: str,
        fingerprint_sha256: str,
    ) -> SensorIdentityRecord | None:
        statement = select(SensorIdentityRow).where(
            SensorIdentityRow.tenant_id == tenant_id,
            SensorIdentityRow.site_id == site_id,
            SensorIdentityRow.fingerprint_sha256 == fingerprint_sha256,
        )
        with self._session_factory() as session:
            self._apply_rls_scope(session, tenant_id, site_id)
            row = session.scalar(statement)
        return SensorIdentityRecord.model_validate(row.payload) if row else None

    def list_sensor_identities(
        self,
        tenant_id: str,
        site_id: str,
        sensor_id: str | None = None,
    ) -> list[SensorIdentityRecord]:
        statement = select(SensorIdentityRow).where(
            SensorIdentityRow.tenant_id == tenant_id,
            SensorIdentityRow.site_id == site_id,
        )
        if sensor_id is not None:
            statement = statement.where(SensorIdentityRow.sensor_id == sensor_id)
        statement = statement.order_by(
            SensorIdentityRow.expires_at,
            SensorIdentityRow.identity_id,
        )
        with self._session_factory() as session:
            self._apply_rls_scope(session, tenant_id, site_id)
            rows = session.scalars(statement).all()
        return [
            SensorIdentityRecord.model_validate(row.payload)
            for row in rows
        ]

    def save_sensor_lifecycle(
        self,
        sensor: SensorRecord,
        identities: list[SensorIdentityRecord],
    ) -> None:
        for identity in identities:
            if (
                identity.tenant_id != sensor.tenant_id
                or identity.site_id != sensor.site_id
                or identity.sensor_id != sensor.sensor_id
            ):
                raise ValueError("sensor lifecycle identity scope mismatch")

        with self._session_factory.begin() as session:
            self._apply_rls_scope(session, sensor.tenant_id, sensor.site_id)
            session.merge(
                SensorRecordRow(
                    pk=_key(sensor.tenant_id, sensor.site_id, sensor.sensor_id),
                    tenant_id=sensor.tenant_id,
                    site_id=sensor.site_id,
                    sensor_id=sensor.sensor_id,
                    last_seen_at=sensor.last_seen_at,
                    revoked_at=sensor.revoked_at,
                    payload=sensor.model_dump(mode="json"),
                )
            )
            for identity in identities:
                session.merge(
                    SensorIdentityRow(
                        identity_id=identity.identity_id,
                        tenant_id=identity.tenant_id,
                        site_id=identity.site_id,
                        sensor_id=identity.sensor_id,
                        fingerprint_sha256=identity.fingerprint_sha256,
                        status=identity.status.value,
                        expires_at=identity.expires_at,
                        accept_until=identity.accept_until,
                        payload=identity.model_dump(mode="json"),
                    )
                )

    def complete_sensor_renewal(
        self,
        previous_identity_id: str,
        sensor: SensorRecord,
        previous: SensorIdentityRecord,
        successor: SensorIdentityRecord,
    ) -> bool:
        identity_statement = (
            select(SensorIdentityRow)
            .where(SensorIdentityRow.identity_id == previous_identity_id)
            .with_for_update()
        )
        sensor_pk = _key(sensor.tenant_id, sensor.site_id, sensor.sensor_id)
        sensor_statement = (
            select(SensorRecordRow)
            .where(SensorRecordRow.pk == sensor_pk)
            .with_for_update()
        )
        with self._session_factory.begin() as session:
            self._apply_rls_scope(session, sensor.tenant_id, sensor.site_id)
            sensor_row = session.scalar(sensor_statement)
            previous_row = session.scalar(identity_statement)
            if previous_row is None or sensor_row is None:
                return False
            stored_previous = SensorIdentityRecord.model_validate(
                previous_row.payload
            )
            stored_sensor = SensorRecord.model_validate(sensor_row.payload)
            if (
                stored_previous.status.value != "ACTIVE"
                or stored_previous.tenant_id != sensor.tenant_id
                or stored_previous.site_id != sensor.site_id
                or stored_previous.sensor_id != sensor.sensor_id
                or previous.identity_id != stored_previous.identity_id
                or previous.status.value != "RETIRING"
                or successor.tenant_id != sensor.tenant_id
                or successor.site_id != sensor.site_id
                or successor.sensor_id != sensor.sensor_id
                or stored_sensor.revoked_at is not None
            ):
                return False

            previous_row.status = previous.status.value
            previous_row.expires_at = previous.expires_at
            previous_row.accept_until = previous.accept_until
            previous_row.payload = previous.model_dump(mode="json")
            session.add(
                SensorIdentityRow(
                    identity_id=successor.identity_id,
                    tenant_id=successor.tenant_id,
                    site_id=successor.site_id,
                    sensor_id=successor.sensor_id,
                    fingerprint_sha256=successor.fingerprint_sha256,
                    status=successor.status.value,
                    expires_at=successor.expires_at,
                    accept_until=successor.accept_until,
                    payload=successor.model_dump(mode="json"),
                )
            )
            sensor_row.last_seen_at = sensor.last_seen_at
            sensor_row.revoked_at = sensor.revoked_at
            sensor_row.payload = sensor.model_dump(mode="json")
        return True

    def revoke_sensor_lifecycle(
        self,
        tenant_id: str,
        site_id: str,
        sensor_id: str,
        *,
        actor_id: str,
        reason: str,
        now: dt.datetime,
    ) -> SensorRecord | None:
        sensor_pk = _key(tenant_id, site_id, sensor_id)
        sensor_statement = (
            select(SensorRecordRow)
            .where(SensorRecordRow.pk == sensor_pk)
            .with_for_update()
        )
        identities_statement = (
            select(SensorIdentityRow)
            .where(
                SensorIdentityRow.tenant_id == tenant_id,
                SensorIdentityRow.site_id == site_id,
                SensorIdentityRow.sensor_id == sensor_id,
            )
            .with_for_update()
        )
        with self._session_factory.begin() as session:
            self._apply_rls_scope(session, tenant_id, site_id)
            sensor_row = session.scalar(sensor_statement)
            if sensor_row is None:
                return None
            stored = SensorRecord.model_validate(sensor_row.payload)
            if stored.revoked_at is not None:
                return stored

            updated = stored.model_copy(
                update={
                    "updated_at": now,
                    "revoked_at": now,
                    "revoked_by": actor_id,
                    "revocation_reason": reason,
                }
            )
            sensor_row.revoked_at = now
            sensor_row.payload = updated.model_dump(mode="json")

            identity_rows = session.scalars(identities_statement).all()
            for row in identity_rows:
                identity = SensorIdentityRecord.model_validate(row.payload)
                revoked = identity.model_copy(
                    update={
                        "status": SensorIdentityStatus.REVOKED,
                        "accept_until": None,
                        "revoked_at": now,
                        "revoked_by": actor_id,
                        "revocation_reason": reason,
                    }
                )
                row.status = revoked.status.value
                row.accept_until = None
                row.payload = revoked.model_dump(mode="json")
            return updated

    def record_sensor_heartbeat(
        self,
        heartbeat: SensorHeartbeat,
        received_at: dt.datetime,
    ) -> SensorRecord | None:
        sensor_pk = _key(
            heartbeat.tenant_id,
            heartbeat.site_id,
            heartbeat.sensor_id,
        )
        sensor_statement = (
            select(SensorRecordRow)
            .where(SensorRecordRow.pk == sensor_pk)
            .with_for_update()
        )
        identity_statement = (
            select(SensorIdentityRow)
            .where(
                SensorIdentityRow.tenant_id == heartbeat.tenant_id,
                SensorIdentityRow.site_id == heartbeat.site_id,
                SensorIdentityRow.sensor_id == heartbeat.sensor_id,
                SensorIdentityRow.fingerprint_sha256
                == heartbeat.fingerprint_sha256,
            )
            .with_for_update()
        )
        with self._session_factory.begin() as session:
            self._apply_rls_scope(
                session,
                heartbeat.tenant_id,
                heartbeat.site_id,
            )
            sensor_row = session.scalar(sensor_statement)
            if sensor_row is None:
                return None
            sensor = SensorRecord.model_validate(sensor_row.payload)
            if sensor.revoked_at is not None:
                return None

            identity_row = session.scalar(identity_statement)
            if identity_row is None:
                return None
            identity = SensorIdentityRecord.model_validate(
                identity_row.payload
            )
            if identity.expires_at <= received_at:
                return None
            accepted = identity.status.value == "ACTIVE" or (
                identity.status.value == "RETIRING"
                and identity.accept_until is not None
                and identity.accept_until > received_at
            )
            if not accepted:
                return None

            updates: dict[str, object] = {
                "updated_at": received_at,
                "last_seen_at": received_at,
            }
            if (
                sensor.last_heartbeat_observed_at is None
                or heartbeat.observed_at >= sensor.last_heartbeat_observed_at
            ):
                updates.update(
                    {
                        "last_heartbeat_observed_at": heartbeat.observed_at,
                        "last_health_state": heartbeat.state,
                        "collector_kind": heartbeat.collector_kind,
                        "version": heartbeat.version,
                        "last_error": heartbeat.last_error,
                    }
                )
            updated = sensor.model_copy(update=updates)
            sensor_row.last_seen_at = updated.last_seen_at
            sensor_row.revoked_at = updated.revoked_at
            sensor_row.payload = updated.model_dump(mode="json")
            return updated

    def get_fabric_receipt(
        self,
        tenant_id: str,
        site_id: str,
        event_id: str,
    ) -> FabricReceipt | None:
        row = self._get(
            FabricReceiptRow,
            tenant_id,
            site_id,
            event_id,
        )
        if row is None:
            return None
        received_at = row.received_at
        if received_at.tzinfo is None or received_at.utcoffset() is None:
            received_at = received_at.replace(tzinfo=dt.UTC)
        processed_at = row.processed_at
        if processed_at is not None and (
            processed_at.tzinfo is None
            or processed_at.utcoffset() is None
        ):
            processed_at = processed_at.replace(tzinfo=dt.UTC)
        return FabricReceipt(
            event_id=row.event_id,
            tenant_id=row.tenant_id,
            site_id=row.site_id,
            envelope_sha256=row.envelope_sha256,
            envelope_json=row.envelope_json,
            status=FabricReceiptStatus(row.status),
            received_at=received_at,
            processed_at=processed_at,
        )

    @staticmethod
    def _receipt_matches(
        existing: FabricReceipt,
        receipt: FabricReceipt,
    ) -> bool:
        return (
            existing.event_id == receipt.event_id
            and existing.tenant_id == receipt.tenant_id
            and existing.site_id == receipt.site_id
            and existing.envelope_sha256 == receipt.envelope_sha256
            and existing.envelope_json == receipt.envelope_json
        )

    def add_fabric_receipt(
        self,
        receipt: FabricReceipt,
    ) -> FabricReceipt:
        existing = self.get_fabric_receipt(
            receipt.tenant_id,
            receipt.site_id,
            receipt.event_id,
        )
        if existing is not None:
            if not self._receipt_matches(existing, receipt):
                raise ValueError(
                    "fabric receipt already exists with different envelope"
                )
            return existing

        row = FabricReceiptRow(
            pk=_key(receipt.tenant_id, receipt.site_id, receipt.event_id),
            tenant_id=receipt.tenant_id,
            site_id=receipt.site_id,
            event_id=receipt.event_id,
            envelope_sha256=receipt.envelope_sha256,
            envelope_json=receipt.envelope_json,
            status=receipt.status.value,
            received_at=receipt.received_at,
            processed_at=receipt.processed_at,
        )
        active = self._active_session()
        if active is not None:
            self._apply_rls_scope(active, receipt.tenant_id, receipt.site_id)
            active.add(row)
            active.flush()
            return receipt

        try:
            with self._session_factory.begin() as session:
                self._apply_rls_scope(session, receipt.tenant_id, receipt.site_id)
                session.add(row)
                session.flush()
        except IntegrityError:
            existing = self.get_fabric_receipt(
                receipt.tenant_id,
                receipt.site_id,
                receipt.event_id,
            )
            if (
                existing is None
                or not self._receipt_matches(existing, receipt)
            ):
                raise ValueError(
                    "fabric receipt already exists with different envelope"
                ) from None
            return existing
        return receipt

    def complete_fabric_receipt(
        self,
        tenant_id: str,
        site_id: str,
        event_id: str,
        *,
        processed_at: dt.datetime,
    ) -> FabricReceipt:
        if processed_at.tzinfo is None or processed_at.utcoffset() is None:
            raise ValueError("fabric receipt processed_at must be timezone-aware")
        key = _key(tenant_id, site_id, event_id)
        active = self._active_session()
        if active is not None:
            self._apply_rls_scope(active, tenant_id, site_id)
            row = active.get(FabricReceiptRow, key)
            if row is None:
                raise ValueError("fabric receipt does not exist")
            if row.status != FabricReceiptStatus.PROCESSED.value:
                row.status = FabricReceiptStatus.PROCESSED.value
                row.processed_at = processed_at.astimezone(dt.UTC)
                active.flush()
            return self.get_fabric_receipt(tenant_id, site_id, event_id)

        with self._session_factory.begin() as session:
            self._apply_rls_scope(session, tenant_id, site_id)
            row = session.get(FabricReceiptRow, key)
            if row is None:
                raise ValueError("fabric receipt does not exist")
            if row.status != FabricReceiptStatus.PROCESSED.value:
                row.status = FabricReceiptStatus.PROCESSED.value
                row.processed_at = processed_at.astimezone(dt.UTC)
        completed = self.get_fabric_receipt(tenant_id, site_id, event_id)
        if completed is None:
            raise RuntimeError("completed fabric receipt disappeared")
        return completed

    def _merge(self, row: Any) -> None:
        tenant_id = getattr(row, "tenant_id", None)
        site_id = getattr(row, "site_id", None)
        if not isinstance(tenant_id, str) or not isinstance(site_id, str):
            raise ValueError("scoped database rows require tenant_id and site_id")

        active = self._active_session()
        if active is not None:
            self._apply_rls_scope(active, tenant_id, site_id)
            active.merge(row)
            active.flush()
            return
        with self._session_factory.begin() as session:
            self._apply_rls_scope(session, tenant_id, site_id)
            session.merge(row)

    def _get(
        self,
        row_type: type[Any],
        tenant_id: str,
        site_id: str,
        object_id: str,
    ) -> Any | None:
        key = _key(tenant_id, site_id, object_id)
        active = self._active_session()
        if active is not None:
            self._apply_rls_scope(active, tenant_id, site_id)
            return active.get(row_type, key)
        with self._session_factory() as session:
            self._apply_rls_scope(session, tenant_id, site_id)
            return session.get(row_type, key)

    def _list_scope(
        self,
        row_type: type[Any],
        tenant_id: str,
        site_id: str,
    ) -> list[Any]:
        statement = select(row_type).where(
            row_type.tenant_id == tenant_id,
            row_type.site_id == site_id,
        )
        active = self._active_session()
        if active is not None:
            self._apply_rls_scope(active, tenant_id, site_id)
            return list(active.scalars(statement).all())
        with self._session_factory() as session:
            self._apply_rls_scope(session, tenant_id, site_id)
            return list(session.scalars(statement).all())


def create_control_plane_store() -> Store:
    database_url = os.environ.get("MON_DATABASE_URL", "").strip()
    if not database_url:
        return InMemoryStore()
    return DatabaseStore(database_url)
