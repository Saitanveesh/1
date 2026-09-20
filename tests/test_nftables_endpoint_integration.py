import os
import subprocess

import pytest

from mon.connectors.nftables_endpoint import LinuxNftablesEndpointAdapter
from mon.domain import (
    ActionType,
    EnforcementKind,
    EnforcementPoint,
    EnforcementVerificationState,
    PolicyDecision,
    PolicyOutcome,
    ResponsePlan,
    ResponseRequest,
    ResponseTarget,
)

_REQUIRED_ENV = ("MON_TEST_NETNS", "MON_ENABLE_ENDPOINT_NFTABLES_ENFORCEMENT")


def _list_chain(namespace: str) -> str:
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
            "mon_endpoint",
            "mon_block_ip",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return listed.stdout


@pytest.mark.skipif(
    not all(os.environ.get(name) for name in _REQUIRED_ENV),
    reason="disposable Linux network namespace / endpoint enforcement gate is not configured",
)
@pytest.mark.asyncio
async def test_real_endpoint_nftables_adapter_full_lifecycle_in_disposable_namespace() -> None:
    """Certifies the endpoint adapter only in a disposable network namespace.

    Even though this adapter is designed for eventual endpoint-host use, this
    is the only place it touches a real `nft` binary, and it is deliberately
    still pointed at an isolated namespace rather than the CI runner's host
    firewall -- see ADR for why disposable-namespace success here does not
    itself certify arbitrary production hosts.
    """
    namespace = os.environ["MON_TEST_NETNS"]

    # An unrelated table/rule that MON must never touch.
    subprocess.run(
        [
            "ip",
            "netns",
            "exec",
            namespace,
            "nft",
            "-f",
            "-",
        ],
        input=(
            "table inet unrelated_owner {\n"
            "  chain input {\n"
            "    type filter hook input priority 0; policy accept;\n"
            '    ip saddr 203.0.113.55 drop comment "not-mon-owned"\n'
            "  }\n"
            "}\n"
        ),
        check=True,
        text=True,
    )

    def unrelated_rule_present() -> bool:
        listed = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                "nft",
                "list",
                "table",
                "inet",
                "unrelated_owner",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return "not-mon-owned" in listed.stdout

    assert unrelated_rule_present()

    adapter = LinuxNftablesEndpointAdapter(namespace=namespace)
    request = ResponseRequest(
        request_id="endpoint-integration",
        tenant_id="ci",
        site_id="ci",
        incident_id="inc",
        target=ResponseTarget(ip_address="198.51.100.88"),
        action=ActionType.BLOCK_IP,
        enforcement_point_id="ci-endpoint-fw",
        ttl_seconds=60,
        reason="integration test",
    )
    point = EnforcementPoint(
        enforcement_point_id="ci-endpoint-fw",
        tenant_id="ci",
        site_id="ci",
        kind=EnforcementKind.ENDPOINT,
        vendor="linux-nftables-endpoint",
        capabilities={ActionType.BLOCK_IP},
    )
    plan = ResponsePlan(
        request=request,
        decision=PolicyDecision(
            outcome=PolicyOutcome.ALLOW,
            reasons=["disposable endpoint integration test"],
        ),
        enforcement_point=point,
        blast_radius_estimate="disposable network namespace only",
    )

    # 1) namespace already created by CI; 2) MON table/chain is created here.
    applied = await adapter.execute(plan, request.request_id)
    assert applied.success

    # 3) verify PRESENT
    present = await adapter.verify(plan, request.request_id)
    assert present.state is EnforcementVerificationState.PRESENT

    # 4) apply again -> idempotent
    reapplied = await adapter.execute(plan, request.request_id)
    assert reapplied.success and reapplied.details.get("idempotent") is True

    # 5) reconcile: observed state matches expected PRESENT, no repair implied
    reconciled = await adapter.reconcile(
        plan, request.request_id, expected_state=EnforcementVerificationState.PRESENT
    )
    assert reconciled.observed_state is EnforcementVerificationState.PRESENT
    assert reconciled.drifted is False

    chain_listing = _list_chain(namespace)
    assert 'comment "mon:v1:ci:ci:endpoint-integration"' in chain_listing

    # 6) rollback
    rolled_back = await adapter.rollback(plan, request.request_id)
    assert rolled_back.success

    # 7) verify ABSENT
    absent = await adapter.verify(plan, request.request_id)
    assert absent.state is EnforcementVerificationState.ABSENT

    # 8) rollback again -> idempotent
    duplicate_rollback = await adapter.rollback(plan, request.request_id)
    assert duplicate_rollback.success and duplicate_rollback.details.get("idempotent") is True

    chain_listing_after = _list_chain(namespace)
    assert 'comment "mon:v1:ci:ci:endpoint-integration"' not in chain_listing_after

    # 9) unrelated rules remain unchanged throughout
    assert unrelated_rule_present()
