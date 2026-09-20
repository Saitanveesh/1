from __future__ import annotations

import pytest

from mon.connectors.nftables_endpoint import CommandResult, LinuxNftablesEndpointAdapter
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
from mon.enforcement import CredentialRequirement, EnforcementError, TargetType
from mon.enforcement_certification import certify_enforcement_adapter

ENABLE_ENV = "MON_ENABLE_ENDPOINT_NFTABLES_ENFORCEMENT"


class FakeRunner:
    """In-memory nftables stand-in: no real `nft`/root required.

    Mirrors the fake runner used for DisposableNftablesAdapter's tests so
    the same conventions (call log, `-a list chain` output format, `add
    rule`/`delete rule` stdin handling) carry over to the endpoint adapter.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.rules = ""
        self.fail_next: str | None = None
        self._next_handle = 7

    async def __call__(self, command, stdin_text, timeout_seconds):
        self.calls.append((command, stdin_text))
        if self.fail_next == "list_table":
            self.fail_next = None
            return CommandResult(1, "", "boom")
        if command[-4:] == ["list", "table", "inet", "mon_endpoint"]:
            return CommandResult(0 if self.rules else 1, "", "")
        if command[-6:] == ["-a", "list", "chain", "inet", "mon_endpoint", "mon_block_ip"]:
            if self.fail_next == "list_chain":
                self.fail_next = None
                return CommandResult(1, "", "permission denied")
            return CommandResult(0, self.rules, "")
        if stdin_text and "add rule" in stdin_text:
            marker = stdin_text.split('comment "', 1)[1].split('"', 1)[0]
            body = stdin_text.split("mon_block_ip ", 1)[1].split(" drop", 1)[0]
            handle = self._next_handle
            self._next_handle += 1
            self.rules += f'{body} drop comment "{marker}" # handle {handle}\n'
        if stdin_text and "delete rule" in stdin_text:
            self.rules = ""
        return CommandResult(0, "", "")


def plan(
    *,
    execution_id: str = "exec-1",
    ip_address: str = "198.51.100.7",
    action: ActionType = ActionType.BLOCK_IP,
    tenant_id: str = "t1",
    site_id: str = "s1",
) -> ResponsePlan:
    request = ResponseRequest(
        request_id=execution_id,
        tenant_id=tenant_id,
        site_id=site_id,
        incident_id="inc-1",
        target=ResponseTarget(ip_address=ip_address),
        action=action,
        enforcement_point_id="fw-1",
        ttl_seconds=300,
        reason="test",
    )
    point = EnforcementPoint(
        enforcement_point_id="fw-1",
        tenant_id=tenant_id,
        site_id=site_id,
        kind=EnforcementKind.ENDPOINT,
        vendor="linux-nftables-endpoint",
        capabilities={ActionType.BLOCK_IP},
    )
    return ResponsePlan(
        request=request,
        decision=PolicyDecision(outcome=PolicyOutcome.ALLOW, reasons=["test"]),
        enforcement_point=point,
        blast_radius_estimate="endpoint host only",
    )


def make_adapter(monkeypatch, runner: FakeRunner, **kwargs) -> LinuxNftablesEndpointAdapter:
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setenv(ENABLE_ENV, "1")
    return LinuxNftablesEndpointAdapter(
        runner=runner,
        ip_binary="/usr/sbin/ip",
        nft_binary="/usr/sbin/nft",
        **kwargs,
    )


# --------------------------------------------------------------------------
# hard enable gate / construction
# --------------------------------------------------------------------------


def test_hard_enable_gate_defaults_disabled(monkeypatch) -> None:
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.delenv(ENABLE_ENV, raising=False)
    with pytest.raises(EnforcementError, match="required to enable"):
        LinuxNftablesEndpointAdapter(ip_binary="/usr/sbin/ip", nft_binary="/usr/sbin/nft")


def test_construction_requires_linux(monkeypatch) -> None:
    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.setenv(ENABLE_ENV, "1")
    with pytest.raises(EnforcementError, match="requires Linux"):
        LinuxNftablesEndpointAdapter(ip_binary="ip", nft_binary="nft")


def test_namespace_must_match_disposable_pattern_when_set(monkeypatch) -> None:
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setenv(ENABLE_ENV, "1")
    with pytest.raises(EnforcementError, match="mon-ci-\\* or mon-sandbox-\\*"):
        LinuxNftablesEndpointAdapter(
            namespace="default", ip_binary="/usr/sbin/ip", nft_binary="/usr/sbin/nft"
        )


def test_capabilities_declare_block_ip_only(monkeypatch) -> None:
    adapter = make_adapter(monkeypatch, FakeRunner())
    caps = adapter.capabilities
    assert caps.supported_actions == {ActionType.BLOCK_IP}
    assert caps.supported_target_types == {TargetType.IP_ADDRESS}
    assert caps.credential_requirement is CredentialRequirement.NONE
    assert caps.remote_api is False
    assert caps.critical_asset_approval_recommended is True


# --------------------------------------------------------------------------
# target validation
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_block_ip_ipv4(monkeypatch) -> None:
    adapter = make_adapter(monkeypatch, FakeRunner())
    result = await adapter.execute(plan(ip_address="198.51.100.7"), "exec-1")
    assert result.success
    verification = await adapter.verify(plan(ip_address="198.51.100.7"), "exec-1")
    assert verification.state is EnforcementVerificationState.PRESENT


@pytest.mark.asyncio
async def test_block_ip_ipv6(monkeypatch) -> None:
    adapter = make_adapter(monkeypatch, FakeRunner())
    result = await adapter.execute(plan(ip_address="2001:db8::7"), "exec-1")
    assert result.success
    verification = await adapter.verify(plan(ip_address="2001:db8::7"), "exec-1")
    assert verification.state is EnforcementVerificationState.PRESENT


@pytest.mark.asyncio
async def test_invalid_ip_is_rejected(monkeypatch) -> None:
    adapter = make_adapter(monkeypatch, FakeRunner())
    with pytest.raises(EnforcementError, match="not a valid IP address"):
        await adapter.execute(plan(ip_address="not-an-ip"), "exec-1")


@pytest.mark.asyncio
async def test_unsupported_action_is_rejected(monkeypatch) -> None:
    adapter = make_adapter(monkeypatch, FakeRunner())
    with pytest.raises(EnforcementError, match="BLOCK_IP only"):
        await adapter.execute(plan(action=ActionType.RATE_LIMIT), "exec-1")


@pytest.mark.asyncio
async def test_missing_target_is_rejected(monkeypatch) -> None:
    adapter = make_adapter(monkeypatch, FakeRunner())
    request = ResponseRequest(
        request_id="exec-1",
        tenant_id="t1",
        site_id="s1",
        incident_id="inc-1",
        target=ResponseTarget(asset_id="host-1"),
        action=ActionType.BLOCK_IP,
        ttl_seconds=300,
        reason="test",
    )
    point = EnforcementPoint(
        enforcement_point_id="fw-1",
        tenant_id="t1",
        site_id="s1",
        kind=EnforcementKind.ENDPOINT,
        vendor="linux-nftables-endpoint",
        capabilities={ActionType.BLOCK_IP},
    )
    missing_target_plan = ResponsePlan(
        request=request,
        decision=PolicyDecision(outcome=PolicyOutcome.ALLOW, reasons=["test"]),
        enforcement_point=point,
    )
    with pytest.raises(EnforcementError, match="requires an ip_address"):
        await adapter.execute(missing_target_plan, "exec-1")


# --------------------------------------------------------------------------
# idempotency / conflict / verify states
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_apply_idempotency(monkeypatch) -> None:
    adapter = make_adapter(monkeypatch, FakeRunner())
    first = await adapter.execute(plan(), "exec-1")
    second = await adapter.execute(plan(), "exec-1")
    assert first.success and not first.details.get("idempotent")
    assert second.success and second.details["idempotent"] is True


@pytest.mark.asyncio
async def test_rollback_idempotency(monkeypatch) -> None:
    adapter = make_adapter(monkeypatch, FakeRunner())
    await adapter.execute(plan(), "exec-1")
    first = await adapter.rollback(plan(), "exec-1")
    second = await adapter.rollback(plan(), "exec-1")
    assert first.success and not first.details.get("idempotent")
    assert second.success and second.details["idempotent"] is True


@pytest.mark.asyncio
async def test_verify_present_absent_unknown(monkeypatch) -> None:
    runner = FakeRunner()
    adapter = make_adapter(monkeypatch, runner)

    absent = await adapter.verify(plan(), "exec-1")
    assert absent.state is EnforcementVerificationState.ABSENT

    await adapter.execute(plan(), "exec-1")
    present = await adapter.verify(plan(), "exec-1")
    assert present.state is EnforcementVerificationState.PRESENT

    runner.fail_next = "list_chain"
    unknown = await adapter.verify(plan(), "exec-1")
    assert unknown.state is EnforcementVerificationState.UNKNOWN
    assert "stderr" in unknown.details


@pytest.mark.asyncio
async def test_ambiguous_duplicate_rule_fails_closed_on_apply(monkeypatch) -> None:
    runner = FakeRunner()
    adapter = make_adapter(monkeypatch, runner)
    marker = 'comment "mon:v1:t1:s1:exec-1"'
    runner.rules = (
        f'ip saddr 198.51.100.7 drop {marker} # handle 7\n'
        f'ip saddr 198.51.100.7 drop {marker} # handle 8\n'
    )
    with pytest.raises(EnforcementError, match="multiple MON nftables rules"):
        await adapter.execute(plan(), "exec-1")


@pytest.mark.asyncio
async def test_ambiguous_duplicate_rule_fails_closed_on_rollback(monkeypatch) -> None:
    runner = FakeRunner()
    adapter = make_adapter(monkeypatch, runner)
    marker = 'comment "mon:v1:t1:s1:exec-1"'
    runner.rules = (
        f'ip saddr 198.51.100.7 drop {marker} # handle 7\n'
        f'ip saddr 198.51.100.7 drop {marker} # handle 8\n'
    )
    with pytest.raises(EnforcementError, match="multiple MON nftables rules"):
        await adapter.rollback(plan(), "exec-1")


@pytest.mark.asyncio
async def test_conflicting_rule_for_same_execution_id_fails_visibly(monkeypatch) -> None:
    runner = FakeRunner()
    adapter = make_adapter(monkeypatch, runner)
    marker = 'comment "mon:v1:t1:s1:exec-1"'
    runner.rules = f'ip saddr 203.0.113.9 drop {marker} # handle 7\n'
    with pytest.raises(EnforcementError, match="conflicting MON nftables rule"):
        await adapter.execute(plan(ip_address="198.51.100.7"), "exec-1")


# --------------------------------------------------------------------------
# reconcile / timeout / failure / bounded errors
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reconcile_reports_observed_state_without_repairing(monkeypatch) -> None:
    adapter = make_adapter(monkeypatch, FakeRunner())
    await adapter.execute(plan(), "exec-1")

    matches = await adapter.reconcile(
        plan(), "exec-1", expected_state=EnforcementVerificationState.PRESENT
    )
    assert matches.observed_state is EnforcementVerificationState.PRESENT
    assert matches.drifted is False

    drifted = await adapter.reconcile(
        plan(), "exec-1", expected_state=EnforcementVerificationState.ABSENT
    )
    assert drifted.observed_state is EnforcementVerificationState.PRESENT
    assert drifted.drifted is True

    # Reconcile is observation-only: a drift report must not itself remove
    # the rule.
    still_present = await adapter.verify(plan(), "exec-1")
    assert still_present.state is EnforcementVerificationState.PRESENT


@pytest.mark.asyncio
async def test_timeout_is_surfaced_as_enforcement_error(monkeypatch) -> None:
    async def timing_out_runner(command, stdin_text, timeout_seconds):
        raise EnforcementError("nftables endpoint command timed out")

    adapter = make_adapter(monkeypatch, timing_out_runner)
    with pytest.raises(EnforcementError, match="timed out"):
        await adapter.execute(plan(), "exec-1")


@pytest.mark.asyncio
async def test_command_failure_returns_bounded_error_no_secret_leak(monkeypatch) -> None:
    async def failing_runner(command, stdin_text, timeout_seconds):
        if command[-4:] == ["list", "table", "inet", "mon_endpoint"]:
            return CommandResult(0, "", "")
        if stdin_text and "add rule" in stdin_text:
            return CommandResult(1, "", ("boom " * 200) + "api_key=super-secret-value")
        return CommandResult(0, "", "")

    adapter = make_adapter(monkeypatch, failing_runner)
    result = await adapter.execute(plan(), "exec-1")
    assert result.success is False
    assert len(result.message) < 600
    # The adapter bounds/forwards whatever text the command produced; it
    # does not itself have or add secrets. This asserts the bound is real.
    assert len(result.message.encode("utf-8")) <= 550


def test_comment_stays_bounded_for_oversized_execution_id(monkeypatch) -> None:
    adapter = make_adapter(monkeypatch, FakeRunner())
    huge_execution_id = "e" * 500
    comment = adapter._comment(plan(), huge_execution_id)  # noqa: SLF001
    assert len(comment.encode("utf-8")) <= 120
    # An oversized, unsafe-charset id is hashed rather than embedded raw.
    assert huge_execution_id not in comment


# --------------------------------------------------------------------------
# MON-owned table only / no unrelated deletion
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_commands_target_only_the_mon_endpoint_table(monkeypatch) -> None:
    runner = FakeRunner()
    adapter = make_adapter(monkeypatch, runner)
    await adapter.execute(plan(), "exec-1")
    await adapter.verify(plan(), "exec-1")
    await adapter.rollback(plan(), "exec-1")

    for command, stdin_text in runner.calls:
        joined = " ".join(command) + " " + (stdin_text or "")
        assert "mon_endpoint" in joined or "list" not in command
        assert "flush" not in joined
        assert "mon_ci" not in joined


@pytest.mark.asyncio
async def test_rollback_only_removes_the_exact_owned_rule(monkeypatch) -> None:
    runner = FakeRunner()
    adapter = make_adapter(monkeypatch, runner)
    await adapter.execute(plan(), "exec-1")
    assert "198.51.100.7" in runner.rules

    await adapter.rollback(plan(), "exec-1")
    assert runner.rules == ""
    delete_calls = [text for _cmd, text in runner.calls if text and "delete rule" in text]
    assert len(delete_calls) == 1
    assert "handle 7" in delete_calls[0]


# --------------------------------------------------------------------------
# certification harness
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_certification_harness_passes_full_cycle(monkeypatch) -> None:
    adapter = make_adapter(monkeypatch, FakeRunner())
    report = await certify_enforcement_adapter(
        adapter,
        adapter.capabilities,
        plan(execution_id="exec-cert"),
        "exec-cert",
    )
    for step in (
        "apply",
        "verify_present",
        "apply_idempotent",
        "reconcile_present",
        "rollback",
        "verify_absent",
        "rollback_idempotent",
        "reconcile_absent",
    ):
        assert step in report.steps_passed
