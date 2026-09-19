import pytest
from pydantic import ValidationError

from mon.domain import (
    ActionType,
    EnforcementBinding,
    EnforcementKind,
    EnforcementPoint,
    ResponseRequest,
    ResponseTarget,
)


def test_disruptive_action_requires_ttl() -> None:
    with pytest.raises(ValidationError):
        ResponseRequest(
            tenant_id="tenant-a",
            site_id="site-1",
            incident_id="inc-1",
            target=ResponseTarget(ip_address="203.0.113.7"),
            action=ActionType.BLOCK_IP,
            enforcement_point_id="edge-fw",
            reason="confirmed external attack source",
        )


def test_response_target_requires_exactly_one_identifier() -> None:
    with pytest.raises(ValidationError):
        ResponseTarget()

    with pytest.raises(ValidationError):
        ResponseTarget(asset_id="host-1", ip_address="10.0.0.5")



def test_enforcement_point_rejects_inline_connector_credentials() -> None:
    with pytest.raises(ValidationError, match="credential_ref"):
        EnforcementPoint(
            enforcement_point_id="edge-fw",
            tenant_id="tenant-a",
            site_id="site-1",
            kind=EnforcementKind.FIREWALL,
            vendor="example",
            capabilities={ActionType.BLOCK_IP},
            attributes={
                "endpoint": "https://firewall.example.test",
                "auth": {"api_token": "must-not-be-stored-here"},
            },
        )


def test_enforcement_point_accepts_credential_reference() -> None:
    point = EnforcementPoint(
        enforcement_point_id="edge-fw",
        tenant_id="tenant-a",
        site_id="site-1",
        kind=EnforcementKind.FIREWALL,
        vendor="example",
        capabilities={ActionType.BLOCK_IP},
        credential_ref="edge-firewall-production",
        attributes={"endpoint": "https://firewall.example.test"},
    )
    assert point.credential_ref == "edge-firewall-production"



def test_enforcement_binding_rejects_inline_connector_credentials() -> None:
    with pytest.raises(ValidationError, match="inline connector credential"):
        EnforcementBinding(
            binding_id="binding-1",
            tenant_id="tenant-a",
            site_id="site-1",
            asset_id="asset-1",
            enforcement_point_id="edge-fw",
            attributes={"password": "must-not-be-stored-here"},
        )
