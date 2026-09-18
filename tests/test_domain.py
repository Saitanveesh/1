import pytest
from pydantic import ValidationError

from mon.domain import ActionType, ResponseRequest, ResponseTarget


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
