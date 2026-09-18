from __future__ import annotations

from collections import defaultdict

from mon.domain import Asset, EnforcementPoint, Incident, SecurityEvent


class InMemoryStore:
    """Development store with strict tenant/site scoping.

    Production persistence will implement the same repository boundary using durable
    storage. The explicit scope arguments prevent accidental global reads.
    """

    def __init__(self) -> None:
        self.events: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
        self.incidents: dict[str, Incident] = {}
        self.assets: dict[str, Asset] = {}
        self.enforcement_points: dict[str, EnforcementPoint] = {}

    def add_event(self, event: SecurityEvent) -> SecurityEvent:
        self.events[(event.tenant_id, event.site_id)].append(event)
        return event

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
