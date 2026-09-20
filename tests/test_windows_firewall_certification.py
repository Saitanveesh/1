"""Windows Defender Firewall adapter certification (disposable Windows runner only).

Requires MON_WINDOWS_FW_CERT=1 (set by .github/workflows/windows-firewall-certification.yml),
Windows and an elevated session. Rules are created only inside the MON-owned
group with documentation-range addresses; an operator-owned control rule and the
complete unrelated rule/profile snapshot are compared before and after.
"""

from __future__ import annotations

import contextlib
import ctypes
import datetime as dt
import json
import os
import platform
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from mon.connectors.windows_firewall_endpoint import WindowsFirewallEndpointAdapter
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
from mon.enforcement_certification import certify_enforcement_adapter

REPORT_PATH = Path("windows-firewall-certification-report.json")
MON_GROUP = "MON Endpoint Containment"
OPERATOR_GROUP = "MON Cert Operator Rules"


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(
    not (
        sys.platform == "win32"
        and os.environ.get("MON_WINDOWS_FW_CERT") == "1"
        and os.environ.get("MON_ENABLE_WINDOWS_FIREWALL_ENFORCEMENT") == "1"
        and _is_admin()
    ),
    reason="requires a disposable elevated Windows runner (MON_WINDOWS_FW_CERT=1)",
)


def ps(script: str, timeout: float = 90) -> str:
    """Independent Windows PowerShell 5.1 probe (never goes through the adapter)."""
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"powershell failed: {result.stderr[:500]}")
    return result.stdout.strip()


def unrelated_snapshot() -> str:
    return ps(
        "$r = Get-NetFirewallRule | Where-Object { $_.Group -ne 'MON Endpoint Containment' } "
        "| Sort-Object Name | Select-Object Name,Enabled,Action,Direction,Group,DisplayName; "
        "$p = Get-NetFirewallProfile | Sort-Object Name | "
        "Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction; "
        "ConvertTo-Json -Compress -Depth 4 -InputObject @{rules=@($r);profiles=@($p)}"
    )


def mon_group_rules() -> list[dict]:
    out = ps(
        "$o=@(); foreach($r in @(Get-NetFirewallRule -Group 'MON Endpoint Containment' "
        "-ErrorAction SilentlyContinue)){ $f = Get-NetFirewallAddressFilter "
        "-AssociatedNetFirewallRule $r; $o += [pscustomobject]@{name=$r.Name;"
        "display=$r.DisplayName;enabled=[string]$r.Enabled;action=[string]$r.Action;"
        "remote=@($f.RemoteAddress|%{[string]$_})} }; ConvertTo-Json -Compress -InputObject @($o)"
    )
    data = json.loads(out or "[]")
    return data if isinstance(data, list) else [data]


def plan(execution_id: str, ip: str) -> ResponsePlan:
    request = ResponseRequest(
        request_id=execution_id,
        tenant_id="cert",
        site_id="cert",
        incident_id="inc",
        target=ResponseTarget(ip_address=ip),
        action=ActionType.BLOCK_IP,
        enforcement_point_id="winfw",
        ttl_seconds=60,
        reason="windows firewall certification",
    )
    point = EnforcementPoint(
        enforcement_point_id="winfw",
        tenant_id="cert",
        site_id="cert",
        kind=EnforcementKind.ENDPOINT,
        vendor="windows-defender-firewall",
        capabilities={ActionType.BLOCK_IP},
    )
    return ResponsePlan(
        request=request,
        decision=PolicyDecision(outcome=PolicyOutcome.ALLOW, reasons=["disposable certification"]),
        enforcement_point=point,
        blast_radius_estimate="disposable Windows CI runner; documentation addresses only",
    )


@pytest.mark.asyncio
async def test_windows_firewall_adapter_certification(tmp_path: Path) -> None:
    run = uuid.uuid4().hex[:8]
    report: dict = {
        "schema": "mon.windows-firewall-certification.v1",
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "runner": {"platform": platform.platform(), "version": platform.version()},
        "stages": {},
        "not_proven": [
            "packet-flow blocking (rule state and independent Get-NetFirewallRule only)",
            "Windows versions beyond the runner image",
            "enterprise Group Policy / third-party firewall coexistence",
            "reboot persistence and Windows Firewall service restart behaviour",
        ],
    }
    operator_name = f"mon-cert-operator-{run}"

    def stage(name: str, **facts: object) -> None:
        report["stages"][name] = {"status": "PROVEN", **facts}
        REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True))

    baseline_mon = mon_group_rules()
    baseline_unrelated = None
    try:
        # Operator-owned control rule the adapter must never touch.
        ps(
            f"New-NetFirewallRule -Name '{operator_name}' -DisplayName '{operator_name}' "
            f"-Group '{OPERATOR_GROUP}' -Direction Inbound -Action Allow -Protocol TCP "
            "-LocalPort 65010 -RemoteAddress 198.51.100.250 -Profile Any -Enabled True | Out-Null"
        )
        baseline_unrelated = unrelated_snapshot()
        assert operator_name in baseline_unrelated
        stage("baseline", mon_owned_rules=len(baseline_mon), operator_control_rule=operator_name)

        adapter = WindowsFirewallEndpointAdapter(timeout_seconds=45)
        stage("explicit_enable_gate", gate="MON_ENABLE_WINDOWS_FIREWALL_ENFORCEMENT=1")

        for label, ip, exec_id in (
            ("ipv4", "198.51.100.77", f"cert-{run}-v4"),
            ("ipv6", "2001:db8::77", f"cert-{run}-v6"),
        ):
            p = plan(exec_id, ip)
            marker = adapter._marker(p, exec_id)
            name = adapter._rule_name(marker)
            first = await adapter.execute(p, exec_id)
            assert first.success, first.message
            independent = [r for r in mon_group_rules() if r["name"] == name]
            assert len(independent) == 1
            assert independent[0]["action"] == "Block" and independent[0]["display"] == marker
            assert independent[0]["enabled"] in ("True", "1")
            assert (await adapter.verify(p, exec_id)).state is EnforcementVerificationState.PRESENT

            again = await adapter.execute(p, exec_id)
            assert again.success and again.details.get("idempotent") is True
            assert len([r for r in mon_group_rules() if r["name"] == name]) == 1

            fresh = WindowsFirewallEndpointAdapter(timeout_seconds=45)
            recon = await fresh.reconcile(
                p, exec_id, expected_state=EnforcementVerificationState.PRESENT
            )
            assert not recon.drifted

            rolled = await adapter.rollback(p, exec_id)
            assert rolled.success, rolled.message
            assert [r for r in mon_group_rules() if r["name"] == name] == []
            assert (await adapter.verify(p, exec_id)).state is EnforcementVerificationState.ABSENT
            repeat = await adapter.rollback(p, exec_id)
            assert repeat.success and repeat.details.get("idempotent") is True
            drift = await fresh.reconcile(
                p, exec_id, expected_state=EnforcementVerificationState.PRESENT
            )
            assert drift.drifted and drift.observed_state is EnforcementVerificationState.ABSENT
            assert [r for r in mon_group_rules() if r["name"] == name] == [], "reconcile repaired"
            stage(
                f"{label}_block_ip_lifecycle",
                address=ip,
                apply="ok",
                independent_verify_present=True,
                repeated_apply_duplicates=0,
                fresh_adapter_reconcile_present=True,
                rollback="ok",
                independent_verify_absent=True,
                repeated_rollback_idempotent=True,
                reconcile_did_not_recreate=True,
            )

        # Controlled conflicting rule -> fail closed.
        cid = f"cert-{run}-conflict"
        cp = plan(cid, "198.51.100.90")
        cmarker = adapter._marker(cp, cid)
        cname = adapter._rule_name(cmarker)
        ps(
            f"New-NetFirewallRule -Name '{cname}' -DisplayName '{cmarker}' -Group '{MON_GROUP}' "
            "-Direction Inbound -Action Block -RemoteAddress 198.51.100.222 "
            "-Profile Any -Enabled True | Out-Null"
        )
        before = mon_group_rules()
        with pytest.raises(EnforcementError, match="conflicting"):
            await adapter.execute(cp, cid)
        assert (await adapter.verify(cp, cid)).state is EnforcementVerificationState.UNKNOWN
        assert mon_group_rules() == before
        # Ambiguity: a second rule with the same marker but a different name.
        ps(
            f"New-NetFirewallRule -Name 'mon-cert-dup-{run}' -DisplayName '{cmarker}' "
            f"-Group '{MON_GROUP}' -Direction Inbound -Action Block "
            "-RemoteAddress 198.51.100.223 -Profile Any -Enabled True | Out-Null"
        )
        with pytest.raises(EnforcementError, match="multiple"):
            await adapter.rollback(cp, cid)
        assert len(mon_group_rules()) == len(before) + 1
        for rule_name in (cname, f"mon-cert-dup-{run}"):
            ps(f"Remove-NetFirewallRule -Name '{rule_name}'")
        stage("conflicting_and_ambiguous_rules_fail_closed", rules_modified_by_refusal=0)

        # Common harness against the real firewall.
        hid = f"cert-{run}-harness"
        harness = await certify_enforcement_adapter(
            adapter, adapter.capabilities, plan(hid, "198.51.100.91"), hid
        )
        stage("shared_certification_harness", steps=sorted(harness.steps_passed))

        # Bounded timeout: hung child must be killed with its whole tree.
        hang = tmp_path / "hang.cmd"
        hang.write_text("@echo off\r\nping -n 60 127.0.0.1 >nul\r\n")
        slow = WindowsFirewallEndpointAdapter(timeout_seconds=1, powershell_binary=str(hang))
        started = time.monotonic()
        with pytest.raises(EnforcementError, match="timed out"):
            await slow.execute(plan(f"cert-{run}-timeout", "198.51.100.92"), f"cert-{run}-timeout")
        elapsed = time.monotonic() - started
        assert elapsed < 15
        time.sleep(1)
        leftover = ps("@(Get-Process -Name ping -ErrorAction SilentlyContinue).Count")
        assert leftover == "0", f"ping children survived: {leftover}"
        stage("bounded_timeout_no_process_leak", elapsed_seconds=round(elapsed, 2))

        after_unrelated = unrelated_snapshot()
        assert after_unrelated == baseline_unrelated, "unrelated firewall state changed"
        assert mon_group_rules() == baseline_mon
        stage("unrelated_firewall_state_unchanged", rules_and_profiles_identical=True)
        report["overall"] = "PASS"
    except BaseException:
        report["overall"] = "FAIL"
        raise
    finally:
        with contextlib.suppress(Exception):
            ps(
                "Get-NetFirewallRule -Group 'MON Endpoint Containment' -ErrorAction "
                "SilentlyContinue | Where-Object { $_.DisplayName -like 'mon:v1:cert:*' -or "
                "$_.Name -like 'mon-cert-*' } | Remove-NetFirewallRule; "
                f"Remove-NetFirewallRule -Name '{operator_name}' -ErrorAction SilentlyContinue"
            )
        residue = mon_group_rules()
        cleanup_ok = residue == baseline_mon and operator_name not in unrelated_snapshot()
        report["cleanup"] = {"mon_group_matches_baseline": residue == baseline_mon,
                             "operator_control_rule_removed": cleanup_ok}  # fmt: skip
        REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True))
    assert cleanup_ok
