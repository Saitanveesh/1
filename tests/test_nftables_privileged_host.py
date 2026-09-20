"""Privileged-host certification for LinuxNftablesEndpointAdapter.

These tests run the adapter against the *host* network namespace (no
``namespace=``) and therefore mutate real nftables state. They only run on a
disposable Linux host (the GitHub Actions runner or a throwaway VM) and are
skipped everywhere else, including developer laptops. Every test restores the
host ruleset and the fixture asserts nothing unrelated changed.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

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
from mon.enforcement import EnforcementError

_ENABLE_ENV = "MON_ENABLE_ENDPOINT_NFTABLES_ENFORCEMENT"
_ALLOWED = (
    sys.platform == "linux"
    and os.environ.get("MON_TEST_PRIVILEGED_HOST") == "1"
    and os.environ.get(_ENABLE_ENV) == "1"
    and hasattr(os, "geteuid")
    and os.geteuid() == 0
    and shutil.which("nft") is not None
)

pytestmark = [
    pytest.mark.skipif(
        not _ALLOWED,
        reason=(
            "privileged host certification requires a disposable Linux host: "
            "MON_TEST_PRIVILEGED_HOST=1, MON_ENABLE_ENDPOINT_NFTABLES_ENFORCEMENT=1, "
            "root and nft"
        ),
    ),
]

MON_TABLE = "mon_endpoint"
FOREIGN_TABLE = "operator_ci_owned"
PV = "PRESENT"

REPORT: dict[str, object] = {}


def _nft(*args: str, stdin: str | None = None, check: bool = True) -> str:
    completed = subprocess.run(
        ["nft", *args],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if check and completed.returncode != 0:
        raise AssertionError(f"nft {args} failed: {completed.stderr}")
    return completed.stdout


def _ruleset() -> str:
    return _nft("list", "ruleset", check=False)


def _table_exists(family: str, name: str) -> bool:
    completed = subprocess.run(
        ["nft", "list", "table", family, name],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return completed.returncode == 0


def _plan(ip: str, request_id: str) -> ResponsePlan:
    request = ResponseRequest(
        request_id=request_id,
        tenant_id="ci",
        site_id="ci",
        incident_id="inc",
        target=ResponseTarget(ip_address=ip),
        action=ActionType.BLOCK_IP,
        enforcement_point_id="host-fw",
        ttl_seconds=60,
        reason="privileged host certification",
    )
    point = EnforcementPoint(
        enforcement_point_id="host-fw",
        tenant_id="ci",
        site_id="ci",
        kind=EnforcementKind.FIREWALL,
        vendor="linux-nftables-host",
        capabilities={ActionType.BLOCK_IP},
    )
    return ResponsePlan(
        request=request,
        decision=PolicyDecision(
            outcome=PolicyOutcome.ALLOW, reasons=["disposable host certification"]
        ),
        enforcement_point=point,
        blast_radius_estimate="disposable CI host only; TEST-NET/documentation addresses",
    )


@pytest.fixture
def host():
    """Snapshot host state; always clean MON/test tables; assert nothing else moved."""
    baseline = _ruleset()
    try:
        yield baseline
    finally:
        for family, name in (("inet", MON_TABLE), ("inet", FOREIGN_TABLE), ("ip", FOREIGN_TABLE)):
            subprocess.run(
                ["nft", "delete", "table", family, name],
                capture_output=True,
                timeout=20,
                check=False,
            )
        after = _ruleset()
        assert after == baseline, "host nftables ruleset changed by the test run"


@pytest.fixture(scope="session", autouse=True)
def _write_report():
    yield
    if not _ALLOWED:
        return
    REPORT["environment"] = {
        "kernel": platform.release(),
        "platform": platform.platform(),
        "nft_version": subprocess.run(
            ["nft", "--version"], capture_output=True, text=True, timeout=10, check=False
        ).stdout.strip(),
        "os_release": _os_release(),
        "python": platform.python_version(),
    }
    Path("nftables-host-certification-report.json").write_text(
        json.dumps(REPORT, indent=2, sort_keys=True), encoding="utf-8"
    )


def _os_release() -> str:
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip('"')
    except OSError:
        pass
    return "unknown"


def _fresh() -> LinuxNftablesEndpointAdapter:
    return LinuxNftablesEndpointAdapter(timeout_seconds=10)


def _mon_rules() -> str:
    return _nft("-a", "list", "chain", "inet", MON_TABLE, "mon_block_ip")


def test_explicit_enable_gate_is_required(monkeypatch: pytest.MonkeyPatch, host) -> None:
    monkeypatch.delenv(_ENABLE_ENV)
    with pytest.raises(EnforcementError, match="MON_ENABLE"):
        LinuxNftablesEndpointAdapter()
    monkeypatch.setenv(_ENABLE_ENV, "0")
    with pytest.raises(EnforcementError):
        LinuxNftablesEndpointAdapter()
    assert not _table_exists("inet", MON_TABLE)
    REPORT["enable_gate"] = "PROVEN"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "ip", "needle"),
    [
        ("ipv4", "198.51.100.77", "ip saddr 198.51.100.77 drop"),
        ("ipv6", "2001:db8::77", "ip6 saddr 2001:db8::77 drop"),
    ],
)
async def test_block_ip_lifecycle_on_host(label: str, ip: str, needle: str, host) -> None:
    adapter = _fresh()
    plan = _plan(ip, f"host-{label}")
    assert not _table_exists("inet", MON_TABLE)

    first = await adapter.execute(plan, plan.request.request_id)
    second = await adapter.execute(plan, plan.request.request_id)  # idempotent
    assert first.success and second.success
    assert second.details.get("idempotent") is True

    rules = _mon_rules()
    assert needle in rules
    assert rules.count(f'comment "mon:v1:ci:ci:host-{label}"') == 1, "apply duplicated the rule"
    assert (await adapter.verify(plan, plan.request.request_id)).state is (
        EnforcementVerificationState.PRESENT
    )

    rollback = await adapter.rollback(plan, plan.request.request_id)
    repeat = await adapter.rollback(plan, plan.request.request_id)  # idempotent
    assert rollback.success and repeat.success
    assert needle not in _mon_rules()
    assert (await adapter.verify(plan, plan.request.request_id)).state is (
        EnforcementVerificationState.ABSENT
    )
    REPORT[f"{label}_block_ip_lifecycle"] = "PROVEN"
    REPORT[f"{label}_idempotent_apply_and_rollback"] = "PROVEN"


@pytest.mark.asyncio
async def test_mon_owned_table_created_and_foreign_state_untouched(host) -> None:
    # Operator-owned tables, in both inet and ip families, each with a rule.
    _nft(
        "-f",
        "-",
        stdin=(
            f"table inet {FOREIGN_TABLE} {{\n"
            "  chain guard {\n"
            "    type filter hook input priority 10; policy accept;\n"
            '    tcp dport 65001 counter accept comment "operator-owned"\n'
            "  }\n"
            "}\n"
            f"table ip {FOREIGN_TABLE} {{\n"
            "  chain guard4 {\n"
            "    type filter hook forward priority 10; policy accept;\n"
            '    udp dport 65002 accept comment "operator-owned-ip"\n'
            "  }\n"
            "}\n"
        ),
    )
    foreign_inet = _nft("list", "table", "inet", FOREIGN_TABLE)
    foreign_ip = _nft("list", "table", "ip", FOREIGN_TABLE)

    adapter = _fresh()
    v4, v6 = _plan("198.51.100.10", "coexist-a"), _plan("2001:db8::10", "coexist-b")
    for plan in (v4, v6):
        assert (await adapter.execute(plan, plan.request.request_id)).success

    assert _table_exists("inet", MON_TABLE)
    chain = _nft("list", "chain", "inet", MON_TABLE, "mon_block_ip")
    assert "type filter hook input" in chain and "policy accept" in chain, (
        "MON chain must never default-deny"
    )
    assert _nft("list", "table", "inet", FOREIGN_TABLE) == foreign_inet
    assert _nft("list", "table", "ip", FOREIGN_TABLE) == foreign_ip

    for plan in (v4, v6):
        assert (await adapter.rollback(plan, plan.request.request_id)).success
    assert _nft("list", "table", "inet", FOREIGN_TABLE) == foreign_inet
    assert _nft("list", "table", "ip", FOREIGN_TABLE) == foreign_ip
    REPORT["mon_owned_table_safe_creation"] = "PROVEN"
    REPORT["coexistence_with_foreign_nftables_tables"] = "PROVEN"


@pytest.mark.asyncio
async def test_coexists_with_iptables_nft_backend(host) -> None:
    iptables = shutil.which("iptables")
    if iptables is None:
        REPORT["coexistence_iptables_nft"] = "NOT_PROVEN (iptables not installed)"
        pytest.skip("iptables not installed")
    version = subprocess.run(
        [iptables, "--version"], capture_output=True, text=True, timeout=10, check=False
    ).stdout
    if "nf_tables" not in version:
        REPORT["coexistence_iptables_nft"] = f"NOT_PROVEN (iptables backend: {version.strip()})"
        pytest.skip("iptables is not the nf_tables backend")

    chain = "MONCICERT"
    run = lambda *a: subprocess.run(  # noqa: E731
        [iptables, *a], capture_output=True, text=True, timeout=20, check=False
    )
    run("-N", chain)
    try:
        assert run("-A", chain, "-s", "203.0.113.5", "-j", "DROP").returncode == 0
        before = run("-S", chain).stdout
        adapter = _fresh()
        plan = _plan("198.51.100.20", "coexist-ipt")
        assert (await adapter.execute(plan, plan.request.request_id)).success
        assert run("-S", chain).stdout == before
        assert (await adapter.rollback(plan, plan.request.request_id)).success
        assert run("-S", chain).stdout == before
    finally:
        run("-F", chain)
        run("-X", chain)
    REPORT["coexistence_iptables_nft"] = "PROVEN"


@pytest.mark.asyncio
async def test_conflicting_and_ambiguous_owned_rules_fail_closed(host) -> None:
    adapter = _fresh()
    plan = _plan("198.51.100.30", "ambig")
    assert (await adapter.execute(plan, "ambig")).success
    comment = "mon:v1:ci:ci:ambig"

    # Conflict: same execution marker, different address.
    other = _plan("198.51.100.31", "ambig")
    with pytest.raises(EnforcementError, match="conflicting"):
        await adapter.execute(other, "ambig")

    # Ambiguity: a second rule carrying the same marker.
    _nft(
        "-f",
        "-",
        stdin=(
            f"add rule inet {MON_TABLE} mon_block_ip "
            f'ip saddr 198.51.100.32 drop comment "{comment}"
'
        ),
    )
    with pytest.raises(EnforcementError, match="multiple"):
        await adapter.execute(plan, "ambig")
    with pytest.raises(EnforcementError, match="multiple"):
        await adapter.rollback(plan, "ambig")
    verification = await adapter.verify(plan, "ambig")
    assert verification.state is EnforcementVerificationState.UNKNOWN
    # Fail-closed means no rule was deleted or added by the refused operations.
    assert _mon_rules().count(comment) == 2
    REPORT["conflicting_or_ambiguous_owned_rule_fails_closed"] = "PROVEN"


def _fake_nft(tmp_path: Path, body: str) -> str:
    script = tmp_path / "fake-nft"
    script.write_text("#!/bin/sh\n" + body + "\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


def _sleepers(needle: str) -> list[str]:
    out = subprocess.run(
        ["pgrep", "-af", needle], capture_output=True, text=True, timeout=10, check=False
    ).stdout
    return [line for line in out.splitlines() if "pgrep" not in line]


def _zombie_children() -> list[str]:
    out = subprocess.run(
        ["ps", "--ppid", str(os.getpid()), "-o", "pid=,stat=,comm="],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    ).stdout
    return [line for line in out.splitlines() if line.split()[1:2] and "Z" in line.split()[1]]


@pytest.mark.asyncio
async def test_timeout_is_bounded_surfaced_and_leaves_no_processes(
    tmp_path: Path, host
) -> None:
    needle = "sleep 3601.7351"
    adapter = LinuxNftablesEndpointAdapter(
        timeout_seconds=1, nft_binary=_fake_nft(tmp_path, f"{needle}\nexit 0")
    )
    started = time.monotonic()
    with pytest.raises(EnforcementError, match="timed out"):
        await adapter.execute(_plan("198.51.100.40", "timeout"), "timeout")
    elapsed = time.monotonic() - started
    assert elapsed < 6, f"timeout was not bounded: {elapsed:.1f}s"
    time.sleep(0.3)
    assert _sleepers(needle) == [], "timed-out subprocess tree survived"
    assert _zombie_children() == []
    assert not _table_exists("inet", MON_TABLE)
    REPORT["timeout_bounded_no_orphans_no_zombies"] = "PROVEN"


@pytest.mark.asyncio
async def test_command_failure_is_surfaced_honestly(tmp_path: Path, host) -> None:
    failing = LinuxNftablesEndpointAdapter(
        timeout_seconds=5,
        nft_binary=_fake_nft(tmp_path, 'echo "Error: Operation not permitted" >&2\nexit 1'),
    )
    plan = _plan("198.51.100.41", "fail")
    with pytest.raises(EnforcementError, match="failed"):
        await failing.execute(plan, "fail")
    assert (await failing.verify(plan, "fail")).state is EnforcementVerificationState.UNKNOWN
    reconciliation = await failing.reconcile(
        plan, "fail", expected_state=EnforcementVerificationState.PRESENT
    )
    assert reconciliation.drifted and (
        reconciliation.observed_state is EnforcementVerificationState.UNKNOWN
    )
    assert not _table_exists("inet", MON_TABLE)
    REPORT["command_failure_surfaced_honestly"] = "PROVEN"


@pytest.mark.asyncio
async def test_restart_reconcile_observes_actual_host_state(host) -> None:
    plan = _plan("198.51.100.50", "restart")
    first = _fresh()
    assert (await first.execute(plan, "restart")).success
    del first  # simulated process restart: a brand-new adapter has no memory

    second = _fresh()
    same = await second.reconcile(plan, "restart", expected_state=EnforcementVerificationState.PRESENT)
    assert not same.drifted and same.observed_state is EnforcementVerificationState.PRESENT

    # Out-of-band removal (operator or crash) must be observed, not repaired.
    _nft("flush", "chain", "inet", MON_TABLE, "mon_block_ip")
    drift = await _fresh().reconcile(
        plan, "restart", expected_state=EnforcementVerificationState.PRESENT
    )
    assert drift.drifted and drift.observed_state is EnforcementVerificationState.ABSENT
    assert "198.51.100.50" not in _mon_rules(), "reconcile must not re-apply"

    # TTL-style rollback after restart of an already-absent rule stays honest.
    assert (await _fresh().rollback(plan, "restart")).success
    absent = await _fresh().reconcile(
        plan, "restart", expected_state=EnforcementVerificationState.ABSENT
    )
    assert not absent.drifted
    REPORT["restart_reconcile_observes_actual_state"] = "PROVEN"
