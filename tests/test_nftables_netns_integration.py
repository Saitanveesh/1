import os
import subprocess

import pytest

from mon.connectors.nftables_netns import DisposableNftablesAdapter
from mon.domain import (
    ActionType,
    EnforcementKind,
    EnforcementPoint,
    PolicyDecision,
    PolicyOutcome,
    ResponsePlan,
    ResponseRequest,
    ResponseTarget,
)


@pytest.mark.skipif(
    not os.environ.get("MON_TEST_NETNS"),
    reason="disposable Linux network namespace is not configured",
)
@pytest.mark.asyncio
async def test_real_nftables_adapter_is_confined_and_reversible() -> None:
    namespace = os.environ["MON_TEST_NETNS"]
    adapter = DisposableNftablesAdapter(namespace)
    request = ResponseRequest(
        request_id="netns-integration",
        tenant_id="ci",
        site_id="ci",
        incident_id="inc",
        target=ResponseTarget(ip_address="198.51.100.77"),
        action=ActionType.BLOCK_IP,
        enforcement_point_id="ci-fw",
        ttl_seconds=60,
        reason="integration test",
    )
    point = EnforcementPoint(
        enforcement_point_id="ci-fw",
        tenant_id="ci",
        site_id="ci",
        kind=EnforcementKind.FIREWALL,
        vendor="linux-nftables-netns",
        capabilities={ActionType.BLOCK_IP},
    )
    plan = ResponsePlan(
        request=request,
        decision=PolicyDecision(
            outcome=PolicyOutcome.ALLOW,
            reasons=["disposable integration test"],
        ),
        enforcement_point=point,
        blast_radius_estimate="disposable network namespace only",
    )

    first = await adapter.execute(plan, request.request_id)
    second = await adapter.execute(plan, request.request_id)
    assert first.success and second.success

    listed = subprocess.run(
        [
            "ip",
            "netns",
            "exec",
            namespace,
            "nft",
            "-a",
            "list",
            "chain",
            "inet",
            "mon_ci",
            "input",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert 'comment "mon:netns-integration"' in listed.stdout

    rollback = await adapter.rollback(plan, request.request_id)
    duplicate = await adapter.rollback(plan, request.request_id)
    assert rollback.success and duplicate.success

    listed_after = subprocess.run(
        [
            "ip",
            "netns",
            "exec",
            namespace,
            "nft",
            "-a",
            "list",
            "chain",
            "inet",
            "mon_ci",
            "input",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert 'comment "mon:netns-integration"' not in listed_after.stdout
