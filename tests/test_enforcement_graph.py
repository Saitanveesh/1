from mon.domain import (
    ActionType,
    Asset,
    EnforcementBinding,
    EnforcementKind,
    EnforcementPoint,
    ResponseRequest,
    ResponseTarget,
)
from mon.enforcement_graph import select_enforcement_point


def test_internal_endpoint_isolation_prefers_bound_endpoint_control() -> None:
    asset = Asset(
        asset_id="host-17",
        tenant_id="t1",
        site_id="s1",
        display_name="Host 17",
    )
    endpoint = EnforcementPoint(
        enforcement_point_id="agent-17",
        tenant_id="t1",
        site_id="s1",
        kind=EnforcementKind.ENDPOINT,
        vendor="windows",
        capabilities={ActionType.ISOLATE_ENDPOINT},
    )
    firewall = EnforcementPoint(
        enforcement_point_id="edge-fw",
        tenant_id="t1",
        site_id="s1",
        kind=EnforcementKind.FIREWALL,
        vendor="generic",
        capabilities={ActionType.ISOLATE_ENDPOINT},
    )
    bindings = [
        EnforcementBinding(
            tenant_id="t1",
            site_id="s1",
            asset_id="host-17",
            enforcement_point_id="agent-17",
            distance=0,
        ),
        EnforcementBinding(
            tenant_id="t1",
            site_id="s1",
            asset_id="host-17",
            enforcement_point_id="edge-fw",
            distance=4,
        ),
    ]
    request = ResponseRequest(
        tenant_id="t1",
        site_id="s1",
        incident_id="inc-1",
        target=ResponseTarget(asset_id="host-17"),
        action=ActionType.ISOLATE_ENDPOINT,
        ttl_seconds=900,
        reason="contain lateral activity",
    )

    selected = select_enforcement_point(request, [firewall, endpoint], bindings, asset)
    assert selected.point.enforcement_point_id == "agent-17"
    assert any("automatically" in reason for reason in selected.reasons)


def test_external_ip_block_prefers_firewall_over_upstream() -> None:
    firewall = EnforcementPoint(
        enforcement_point_id="edge-fw",
        tenant_id="t1",
        site_id="s1",
        kind=EnforcementKind.FIREWALL,
        vendor="generic",
        capabilities={ActionType.BLOCK_IP},
    )
    upstream = EnforcementPoint(
        enforcement_point_id="isp",
        tenant_id="t1",
        site_id="s1",
        kind=EnforcementKind.UPSTREAM,
        vendor="provider",
        capabilities={ActionType.BLOCK_IP},
    )
    request = ResponseRequest(
        tenant_id="t1",
        site_id="s1",
        incident_id="inc-2",
        target=ResponseTarget(ip_address="203.0.113.9"),
        action=ActionType.BLOCK_IP,
        ttl_seconds=600,
        reason="temporary containment",
    )

    selected = select_enforcement_point(request, [upstream, firewall], [])
    assert selected.point.enforcement_point_id == "edge-fw"
