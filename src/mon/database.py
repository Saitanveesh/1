from __future__ import annotations

import os
from typing import Any

from sqlalchemy import JSON, Index, String, create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from mon.domain import (
    Asset,
    EnforcementBinding,
    EnforcementPoint,
    Finding,
    Incident,
    SecurityEvent,
)
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
        if create_schema:
            Base.metadata.create_all(self.engine)

    def close(self) -> None:
        self.engine.dispose()

    def event_exists(self, tenant_id: str, site_id: str, event_id: str) -> bool:
        with self._session_factory() as session:
            return session.get(EventRow, _key(tenant_id, site_id, event_id)) is not None

    def add_event(self, event: SecurityEvent) -> SecurityEvent:
        row = EventRow(
            pk=_key(event.tenant_id, event.site_id, event.event_id),
            tenant_id=event.tenant_id,
            site_id=event.site_id,
            event_id=event.event_id,
            payload=event.model_dump(mode="json"),
        )
        with self._session_factory() as session:
            try:
                session.add(row)
                session.commit()
            except IntegrityError:
                session.rollback()
        return event

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
            rows = session.scalars(statement).all()
        return [EnforcementBinding.model_validate(row.payload) for row in rows]

    def _merge(self, row: Any) -> None:
        with self._session_factory.begin() as session:
            session.merge(row)

    def _get(
        self,
        row_type: type[Any],
        tenant_id: str,
        site_id: str,
        object_id: str,
    ) -> Any | None:
        with self._session_factory() as session:
            return session.get(row_type, _key(tenant_id, site_id, object_id))

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
        with self._session_factory() as session:
            return list(session.scalars(statement).all())


def create_control_plane_store() -> Store:
    database_url = os.environ.get("MON_DATABASE_URL", "").strip()
    if not database_url:
        return InMemoryStore()
    return DatabaseStore(database_url)
