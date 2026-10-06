from __future__ import annotations

import os
import subprocess

import pytest

from mon.connectors.nftables_router import LinuxNftablesRouterAdapter
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

pytestmark = pytest.mark.skipif(
    not os.environ.get("MON_TEST_NETNS"),
    reason="disposable Linux router namespace is not configured",
)


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        check=check,
        capture_output=True,
        text=True,
    )


def in_ns(namespace: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run("ip", "netns", "exec", namespace, *args, check=check)


@pytest.mark.asyncio
async def test_router_adapter_changes_real_forwarded_packet_path() -> None:
    router = os.environ["MON_TEST_NETNS"]
    attacker = f"{router}-a"
    victim = f"{router}-v"

    for namespace in (attacker, victim):
        run("ip", "netns", "del", namespace, check=False)

    try:
        run("ip", "netns", "add", attacker)
        run("ip", "netns", "add", victim)

        # Two routed point-to-point LANs: attacker -> router -> victim.
        run("ip", "link", "add", "mra0", "type", "veth", "peer", "name", "ma0")
        run("ip", "link", "set", "mra0", "netns", router)
        run("ip", "link", "set", "ma0", "netns", attacker)

        run("ip", "link", "add", "mrv0", "type", "veth", "peer", "name", "mv0")
        run("ip", "link", "set", "mrv0", "netns", router)
        run("ip", "link", "set", "mv0", "netns", victim)

        for namespace in (router, attacker, victim):
            in_ns(namespace, "ip", "link", "set", "lo", "up")

        in_ns(router, "ip", "addr", "add", "10.201.1.1/24", "dev", "mra0")
        in_ns(router, "ip", "addr", "add", "10.201.2.1/24", "dev", "mrv0")
        in_ns(router, "ip", "link", "set", "mra0", "up")
        in_ns(router, "ip", "link", "set", "mrv0", "up")
        in_ns(router, "sysctl", "-w", "net.ipv4.ip_forward=1")

        in_ns(attacker, "ip", "addr", "add", "10.201.1.2/24", "dev", "ma0")
        in_ns(attacker, "ip", "link", "set", "ma0", "up")
        in_ns(attacker, "ip", "route", "add", "10.201.2.0/24", "via", "10.201.1.1")

        in_ns(victim, "ip", "addr", "add", "10.201.2.2/24", "dev", "mv0")
        in_ns(victim, "ip", "link", "set", "mv0", "up")
        in_ns(victim, "ip", "route", "add", "10.201.1.0/24", "via", "10.201.2.1")

        baseline = in_ns(
            attacker,
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            "10.201.2.2",
            check=False,
        )
        assert baseline.returncode == 0, baseline.stderr

        request = ResponseRequest(
            request_id="router-forward-integration",
            tenant_id="ci",
            site_id="ci",
            incident_id="inc-router",
            target=ResponseTarget(ip_address="10.201.1.2"),
            action=ActionType.BLOCK_IP,
            enforcement_point_id="ci-router",
            ttl_seconds=60,
            reason="prove forwarded-path containment in a disposable namespace",
        )
        point = EnforcementPoint(
            enforcement_point_id="ci-router",
            tenant_id="ci",
            site_id="ci",
            kind=EnforcementKind.ROUTER,
            vendor="linux-nftables-router",
            capabilities={ActionType.BLOCK_IP},
        )
        plan = ResponsePlan(
            request=request,
            decision=PolicyDecision(
                outcome=PolicyOutcome.ALLOW,
                reasons=["disposable router integration test"],
            ),
            enforcement_point=point,
            blast_radius_estimate="one disposable attacker source address",
        )
        adapter = LinuxNftablesRouterAdapter(namespace=router)

        applied = await adapter.execute(plan, request.request_id)
        assert applied.success
        verification = await adapter.verify(plan, request.request_id)
        assert verification.state is EnforcementVerificationState.PRESENT

        blocked = in_ns(
            attacker,
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            "10.201.2.2",
            check=False,
        )
        assert blocked.returncode != 0, "router containment did not stop forwarded traffic"

        listed = in_ns(
            router,
            "nft",
            "-a",
            "list",
            "chain",
            "inet",
            "mon_router",
            "mon_block_ip",
        )
        assert "hook forward" in listed.stdout
        assert "10.201.1.2 drop" in listed.stdout

        rolled_back = await adapter.rollback(plan, request.request_id)
        assert rolled_back.success
        verification_after = await adapter.verify(plan, request.request_id)
        assert verification_after.state is EnforcementVerificationState.ABSENT

        recovered = in_ns(
            attacker,
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            "10.201.2.2",
            check=False,
        )
        assert recovered.returncode == 0, recovered.stderr
    finally:
        run("ip", "netns", "del", attacker, check=False)
        run("ip", "netns", "del", victim, check=False)
