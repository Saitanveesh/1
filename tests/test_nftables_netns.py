import os
import sys
from pathlib import Path

import pytest

from mon.connectors.nftables_netns import (
    CommandResult,
    DisposableNftablesAdapter,
)
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
from mon.enforcement import EnforcementError

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="disposable nftables adapter requires Linux network namespaces",
)


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.rules = ""

    async def __call__(self, command, stdin_text, timeout_seconds):
        self.calls.append((command, stdin_text))
        if command[-4:] == ["list", "table", "inet", "mon_ci"]:
            return CommandResult(0 if self.rules else 1, "", "")
        if command[-6:] == ["-a", "list", "chain", "inet", "mon_ci", "input"]:
            return CommandResult(0, self.rules, "")
        script_text = stdin_text
        if len(command) >= 2 and command[-2] == "-f":
            script_text = Path(command[-1]).read_text(encoding="utf-8")
        if script_text and "add rule" in script_text:
            marker = script_text.split('comment "', 1)[1].split('"', 1)[0]
            self.rules = (
                f'ip saddr 198.51.100.7 drop comment "{marker}" # handle 7\n'
            )
        if script_text and "delete rule" in script_text:
            self.rules = ""
        return CommandResult(0, "", "")


def plan() -> ResponsePlan:
    request = ResponseRequest(
        request_id="exec-1",
        tenant_id="t1",
        site_id="s1",
        incident_id="inc-1",
        target=ResponseTarget(ip_address="198.51.100.7"),
        action=ActionType.BLOCK_IP,
        enforcement_point_id="fw-1",
        ttl_seconds=300,
        reason="test source block",
    )
    point = EnforcementPoint(
        enforcement_point_id="fw-1",
        tenant_id="t1",
        site_id="s1",
        kind=EnforcementKind.FIREWALL,
        vendor="linux-nftables-netns",
        capabilities={ActionType.BLOCK_IP},
    )
    return ResponsePlan(
        request=request,
        decision=PolicyDecision(
            outcome=PolicyOutcome.ALLOW,
            reasons=["test"],
        ),
        enforcement_point=point,
        blast_radius_estimate="disposable namespace only",
    )


def test_adapter_refuses_enablement_and_host_namespace(monkeypatch) -> None:
    monkeypatch.delenv("MON_ENABLE_DISPOSABLE_NETNS_ENFORCEMENT", raising=False)
    with pytest.raises(EnforcementError, match="required to enable"):
        DisposableNftablesAdapter(
            "mon-ci-test",
            ip_binary="/usr/sbin/ip",
            nft_binary="/usr/sbin/nft",
        )

    monkeypatch.setenv("MON_ENABLE_DISPOSABLE_NETNS_ENFORCEMENT", "1")
    with pytest.raises(EnforcementError, match="host namespace is forbidden"):
        DisposableNftablesAdapter(
            "default",
            ip_binary="/usr/sbin/ip",
            nft_binary="/usr/sbin/nft",
        )


@pytest.mark.asyncio
async def test_adapter_execute_and_rollback_are_idempotent(monkeypatch) -> None:
    monkeypatch.setenv("MON_ENABLE_DISPOSABLE_NETNS_ENFORCEMENT", "1")
    runner = FakeRunner()
    adapter = DisposableNftablesAdapter(
        "mon-ci-unit",
        runner=runner,
        ip_binary="/usr/sbin/ip",
        nft_binary="/usr/sbin/nft",
    )

    first = await adapter.execute(plan(), "exec-1")
    present = await adapter.verify(plan(), "exec-1")
    second = await adapter.execute(plan(), "exec-1")
    rolled = await adapter.rollback(plan(), "exec-1")
    absent = await adapter.verify(plan(), "exec-1")
    duplicate = await adapter.rollback(plan(), "exec-1")

    assert first.success
    assert present.state is EnforcementVerificationState.PRESENT
    assert second.success and second.details["idempotent"] is True
    assert rolled.success
    assert absent.state is EnforcementVerificationState.ABSENT
    assert duplicate.success and duplicate.details["idempotent"] is True
    assert all(
        call[0][1:4] == ["netns", "exec", "mon-ci-unit"]
        for call in runner.calls
    )
    assert not os.environ.get("MON_TEST_NETNS")


@pytest.mark.asyncio
async def test_verify_refuses_to_guess_on_ambiguous_or_failed_inspection(
    monkeypatch,
) -> None:
    monkeypatch.setenv("MON_ENABLE_DISPOSABLE_NETNS_ENFORCEMENT", "1")
    runner = FakeRunner()
    adapter = DisposableNftablesAdapter(
        "mon-ci-unit",
        runner=runner,
        ip_binary="/usr/sbin/ip",
        nft_binary="/usr/sbin/nft",
    )
    marker = 'comment "mon:exec-1"'
    runner.rules = (
        f'ip saddr 198.51.100.7 drop {marker} # handle 7\n'
        f'ip saddr 198.51.100.7 drop {marker} # handle 8\n'
    )
    ambiguous = await adapter.verify(plan(), "exec-1")
    assert ambiguous.state is EnforcementVerificationState.UNKNOWN
    assert ambiguous.details["matching_rules"] == 2

    async def failed_runner(command, stdin_text, timeout_seconds):
        if command[-6:] == ["-a", "list", "chain", "inet", "mon_ci", "input"]:
            return CommandResult(1, "", "permission denied")
        return CommandResult(0, "", "")

    failing = DisposableNftablesAdapter(
        "mon-ci-unit",
        runner=failed_runner,
        ip_binary="/usr/sbin/ip",
        nft_binary="/usr/sbin/nft",
    )
    unknown = await failing.verify(plan(), "exec-1")
    assert unknown.state is EnforcementVerificationState.UNKNOWN
    assert unknown.details["stderr"] == "permission denied"
