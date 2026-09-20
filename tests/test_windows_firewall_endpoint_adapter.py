from __future__ import annotations

import base64
import json

import pytest

from mon.connectors import windows_firewall_endpoint as wf
from mon.connectors.windows_firewall_endpoint import (
    CommandResult,
    WindowsFirewallEndpointAdapter,
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
from mon.enforcement import CredentialRequirement, EnforcementError, TargetType
from mon.enforcement_certification import certify_enforcement_adapter

ENABLE_ENV = "MON_ENABLE_WINDOWS_FIREWALL_ENFORCEMENT"


class FakeFirewall:
    """In-memory stand-in that interprets the adapter's environment protocol."""

    def __init__(self) -> None:
        self.rules: list[dict] = []
        self.calls: list[tuple[list[str], dict[str, str]]] = []
        self.fail_op: str | None = None

    async def __call__(self, command, env, timeout_seconds):
        self.calls.append((command, dict(env)))
        op = env["MON_FW_OP"]
        if self.fail_op == op:
            return CommandResult(1, "", "Access is denied " * 100)
        if op == "add":
            self.rules.append(
                {
                    "name": env["MON_FW_NAME"],
                    "display": env["MON_FW_DISPLAY"],
                    "enabled": "True",
                    "action": "Block",
                    "direction": "Inbound",
                    "remote": [env["MON_FW_ADDR"]],
                }
            )
        elif op == "remove":
            self.rules = [r for r in self.rules if r["name"] != env["MON_FW_NAME"]]
        return CommandResult(0, json.dumps(self.rules), "")


def plan(*, execution_id="exec-1", ip="198.51.100.7", action=ActionType.BLOCK_IP):
    request = ResponseRequest(
        request_id=execution_id,
        tenant_id="t1",
        site_id="s1",
        incident_id="inc-1",
        target=ResponseTarget(ip_address=ip),
        action=action,
        enforcement_point_id="fw-1",
        ttl_seconds=300,
        reason="test",
    )
    point = EnforcementPoint(
        enforcement_point_id="fw-1",
        tenant_id="t1",
        site_id="s1",
        kind=EnforcementKind.ENDPOINT,
        vendor="windows-defender-firewall",
        capabilities={ActionType.BLOCK_IP},
    )
    return ResponsePlan(
        request=request,
        decision=PolicyDecision(outcome=PolicyOutcome.ALLOW, reasons=["test"]),
        enforcement_point=point,
        blast_radius_estimate="endpoint host only",
    )


def make(monkeypatch, runner=None, **kwargs):
    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.setenv(ENABLE_ENV, "1")
    return WindowsFirewallEndpointAdapter(
        runner=runner or FakeFirewall(), powershell_binary="powershell.exe", **kwargs
    )


def test_disabled_by_default_and_platform_gated(monkeypatch) -> None:
    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.delenv(ENABLE_ENV, raising=False)
    with pytest.raises(EnforcementError, match=ENABLE_ENV):
        WindowsFirewallEndpointAdapter(powershell_binary="powershell.exe")
    monkeypatch.setenv(ENABLE_ENV, "true")
    with pytest.raises(EnforcementError):
        WindowsFirewallEndpointAdapter(powershell_binary="powershell.exe")
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setenv(ENABLE_ENV, "1")
    with pytest.raises(EnforcementError, match="requires Windows"):
        WindowsFirewallEndpointAdapter(powershell_binary="powershell.exe")


def test_capabilities_are_block_ip_only(monkeypatch) -> None:
    caps = make(monkeypatch).capabilities
    assert caps.supported_actions == {ActionType.BLOCK_IP}
    assert caps.supported_target_types == {TargetType.IP_ADDRESS}
    assert caps.supports_verify and caps.supports_rollback and caps.supports_reconcile
    assert caps.credential_requirement is CredentialRequirement.NONE


@pytest.mark.asyncio
@pytest.mark.parametrize("ip", ["198.51.100.7", "2001:db8::7"])
async def test_apply_verify_rollback_idempotent(monkeypatch, ip) -> None:
    fake = FakeFirewall()
    adapter = make(monkeypatch, fake)
    p = plan(ip=ip)
    assert (await adapter.execute(p, "exec-1")).success
    again = await adapter.execute(p, "exec-1")
    assert again.success and again.details["idempotent"] is True
    assert len(fake.rules) == 1
    assert (await adapter.verify(p, "exec-1")).state is EnforcementVerificationState.PRESENT
    assert (await adapter.rollback(p, "exec-1")).success
    assert (await adapter.rollback(p, "exec-1")).details["idempotent"] is True
    assert fake.rules == []
    assert (await adapter.verify(p, "exec-1")).state is EnforcementVerificationState.ABSENT


@pytest.mark.asyncio
async def test_no_shell_and_no_untrusted_value_in_script(monkeypatch) -> None:
    fake = FakeFirewall()
    adapter = make(monkeypatch, fake)
    await adapter.execute(plan(ip="203.0.113.99"), "exec-1")
    for command, env in fake.calls:
        assert command[0] == "powershell.exe"
        assert "-Command" not in command and "-EncodedCommand" in command
        script = base64.b64decode(command[-1]).decode("utf-16-le")
        assert "203.0.113.99" not in script and "exec-1" not in script
        assert "Remove-NetFirewallRule" in script and "$existing.Group -eq $group" in script
        assert "Set-NetFirewallProfile" not in script and "Disable" not in script
        assert env["MON_FW_GROUP"] == "MON Endpoint Containment"
    add_env = [e for _, e in fake.calls if e["MON_FW_OP"] == "add"][0]
    assert add_env["MON_FW_ADDR"] == "203.0.113.99"
    assert add_env["MON_FW_DISPLAY"] == "mon:v1:t1:s1:exec-1"
    assert add_env["MON_FW_NAME"].startswith("mon-v1-")


@pytest.mark.asyncio
async def test_conflicting_rule_fails_closed(monkeypatch) -> None:
    fake = FakeFirewall()
    adapter = make(monkeypatch, fake)
    await adapter.execute(plan(ip="198.51.100.7"), "exec-1")
    with pytest.raises(EnforcementError, match="conflicting"):
        await adapter.execute(plan(ip="198.51.100.8"), "exec-1")
    fake.rules[0]["enabled"] = "False"
    verification = await adapter.verify(plan(ip="198.51.100.7"), "exec-1")
    assert verification.state is EnforcementVerificationState.UNKNOWN
    assert len(fake.rules) == 1


@pytest.mark.asyncio
async def test_ambiguous_rules_fail_closed(monkeypatch) -> None:
    fake = FakeFirewall()
    adapter = make(monkeypatch, fake)
    p = plan()
    await adapter.execute(p, "exec-1")
    fake.rules.append({**fake.rules[0], "name": "someone-else", "remote": ["198.51.100.99"]})
    with pytest.raises(EnforcementError, match="multiple"):
        await adapter.execute(p, "exec-1")
    with pytest.raises(EnforcementError, match="multiple"):
        await adapter.rollback(p, "exec-1")
    assert (await adapter.verify(p, "exec-1")).state is EnforcementVerificationState.UNKNOWN
    assert len(fake.rules) == 2


@pytest.mark.asyncio
async def test_reconcile_observes_and_never_repairs(monkeypatch) -> None:
    fake = FakeFirewall()
    adapter = make(monkeypatch, fake)
    p = plan()
    result = await adapter.reconcile(
        p, "exec-1", expected_state=EnforcementVerificationState.PRESENT
    )
    assert result.drifted and result.observed_state is EnforcementVerificationState.ABSENT
    assert fake.rules == []
    assert not any(env["MON_FW_OP"] == "add" for _, env in fake.calls)
    await adapter.execute(p, "exec-1")
    fresh = make(monkeypatch, fake)
    same = await fresh.reconcile(p, "exec-1", expected_state=EnforcementVerificationState.PRESENT)
    assert not same.drifted


@pytest.mark.asyncio
async def test_failures_and_timeouts_are_surfaced_and_bounded(monkeypatch) -> None:
    fake = FakeFirewall()
    adapter = make(monkeypatch, fake)
    p = plan()
    fake.fail_op = "add"
    failed = await adapter.execute(p, "exec-1")
    assert failed.success is False and len(failed.message) < 700
    fake.fail_op = "list"
    with pytest.raises(EnforcementError):
        await adapter.execute(p, "exec-1")
    assert (await adapter.verify(p, "exec-1")).state is EnforcementVerificationState.UNKNOWN
    assert (await adapter.rollback(p, "exec-1")).success is False

    async def hangs(command, env, timeout):
        raise EnforcementError("windows firewall command timed out")

    with pytest.raises(EnforcementError, match="timed out"):
        await make(monkeypatch, hangs).execute(p, "exec-1")


@pytest.mark.asyncio
async def test_invalid_and_unsupported_inputs_rejected(monkeypatch) -> None:
    adapter = make(monkeypatch)
    with pytest.raises(EnforcementError):
        await adapter.execute(plan(ip="not-an-ip"), "exec-1")
    with pytest.raises(EnforcementError):
        await adapter.execute(plan(action=ActionType.RATE_LIMIT), "exec-1")
    assert wf._safe_token("bad token; rm -rf").startswith("h")


@pytest.mark.asyncio
async def test_certification_harness_passes_full_cycle(monkeypatch) -> None:
    adapter = make(monkeypatch)
    report = await certify_enforcement_adapter(
        adapter, adapter.capabilities, plan(execution_id="exec-cert"), "exec-cert"
    )
    for step in (
        "apply", "verify_present", "apply_idempotent", "reconcile_present",
        "rollback", "verify_absent", "rollback_idempotent", "reconcile_absent",
    ):  # fmt: skip
        assert step in report.steps_passed
