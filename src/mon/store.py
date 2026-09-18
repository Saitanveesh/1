from __future__ import annotations

from collections import defaultdict

from mon.domain import (
    Asset,
    EnforcementBinding,
    EnforcementPoint,
    Finding,
    Incident,
    SecurityEvent,
)


class InMemoryStore:
    """Development store with strict tenant/site scoping.

    Production persistence will implement the same repository boundary using durable
    storage. The explicit scope arguments prevent accidental global reads.
    """

    def __init__(self) -> None:
        self.events: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        self.incidents: dict[str, Incident] = {}
        self.findings: dict[str, Finding] = {}
        self.assets: dict[str, Asset] = {}
        self.enforcement_points: dict[str, EnforcementPoint] = {}
        self.enforcement_bindings: dict[str, EnforcementBinding] = {}

    def add_event(self, event: SecurityEvent) -> SecurityEvent:
        self.events[(event.tenant_id, event.site_id)].append(event)
        return event

    def add_finding(self, finding: Finding) -> Finding:
        self.findings[finding.finding_id] = finding
        return finding

    def list_findings(self, tenant_id: str, site_id: str) -> list[Finding]:
        return [
            value
            for value in self.findings.values()
            if value.tenant_id == tenant_id and value.site_id == site_id
        ]

    def add_incident(self, incident: Incident) -> Incident:
        self.incidents[incident.incident_id] = incident
        return incident

    def list_incidents(self, tenant_id: str, site_id: str) -> list[Incident]:
        return [
            value
            for value in self.incidents.values()
            if value.tenant_id == tenant_id and value.site_id == site_id
        ]

    def get_incident(self, tenant_id: str, site_id: str, incident_id: str) -> Incident | None:
        value = self.incidents.get(incident_id)
        if value and value.tenant_id == tenant_id and value.site_id == site_id:
            return value
        return None

    def add_asset(self, asset: Asset) -> Asset:
        self.assets[asset.asset_id] = asset
        return asset

    def get_asset(self, tenant_id: str, site_id: str, asset_id: str) -> Asset | None:
        value = self.assets.get(asset_id)
        if value and value.tenant_id == tenant_id and value.site_id == site_id:
            return value
        return None

    def add_enforcement_point(self, point: EnforcementPoint) -> EnforcementPoint:
        self.enforcement_points[point.enforcement_point_id] = point
        return point

    def get_enforcement_point(
        self,
        tenant_id: str,
        site_id: str,
        enforcement_point_id: str,
    ) -> EnforcementPoint | None:
        value = self.enforcement_points.get(enforcement_point_id)
        if value and value.tenant_id == tenant_id and value.site_id == site_id:
            return value
        return None

    def list_enforcement_points(self, tenant_id: str, site_id: str) -> list[EnforcementPoint]:
        return [
            value
            for value in self.enforcement_points.values()
            if value.tenant_id == tenant_id and value.site_id == site_id
        ]

    def add_enforcement_binding(self, binding: EnforcementBinding) -> EnforcementBinding:
        self.enforcement_bindings[binding.binding_id] = binding
        return binding

    def list_enforcement_bindings(
        self,
        tenant_id: str,
        site_id: str,
        asset_id: str | None = None,
    ) -> list[EnforcementBinding]:
        values = [
            value
            for value in self.enforcement_bindings.values()
            if value.tenant_id == tenant_id and value.site_id == site_id
        ]
        if asset_id is not None:
            values = [value for value in values if value.asset_id == asset_id]
        return values
