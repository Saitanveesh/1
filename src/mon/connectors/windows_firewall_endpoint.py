from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from mon.domain import (
    ActionType,
    EnforcementReconciliation,
    EnforcementResult,
    EnforcementVerification,
    EnforcementVerificationState,
    ResponsePlan,
)
from mon.enforcement import (
    CredentialRequirement,
    EnforcementAdapterCapabilities,
    EnforcementError,
    EnforcementExecutionPlane,
    TargetType,
)


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


# (argv, environment, timeout_seconds)
CommandRunner = Callable[[list[str], dict[str, str], float], Awaitable[CommandResult]]

# Hard production-host safety gate. Absent by default; this alone is a
# deployment guard, not authorization -- policy gating and approval remain
# authoritative (see mon.policy).
_ENABLE_ENV = "MON_ENABLE_WINDOWS_FIREWALL_ENFORCEMENT"
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_MARKER_PREFIX = "mon:v1:"
_MAX_MARKER_CHARS = 120
_MAX_ERROR_CHARS = 500
_MAX_OUTPUT_CHARS = 1_000_000
_GROUP = "MON Endpoint Containment"

# One constant script. No value derived from telemetry is ever interpolated
# into it: the operation, group, rule name/display name and (already
# ipaddress-validated) address travel in environment variables.
_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$op = $env:MON_FW_OP
$group = $env:MON_FW_GROUP
$name = $env:MON_FW_NAME
switch ($op) {
  'list' { }
  'add' {
    New-NetFirewallRule -Name $name -DisplayName $env:MON_FW_DISPLAY -Group $group `
      -Direction Inbound -Action Block -RemoteAddress $env:MON_FW_ADDR `
      -Profile Any -Enabled True | Out-Null
  }
  'remove' {
    $existing = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
    if ($existing -and $existing.Group -eq $group) { Remove-NetFirewallRule -Name $name }
  }
  default { throw 'unsupported operation' }
}
$out = @()
foreach ($rule in @(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue)) {
  $filter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule
  $out += [pscustomobject]@{
    name = [string]$rule.Name
    display = [string]$rule.DisplayName
    enabled = [string]$rule.Enabled
    action = [string]$rule.Action
    direction = [string]$rule.Direction
    remote = @($filter.RemoteAddress | ForEach-Object { [string]$_ })
  }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


def _encoded_script() -> str:
    return base64.b64encode(_SCRIPT.encode("utf-16-le")).decode("ascii")


async def _default_runner(
    command: list[str],
    env: dict[str, str],
    timeout_seconds: float,
) -> CommandResult:
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout_seconds
        )
    except TimeoutError as exc:
        # Kill the whole tree so no powershell/child survives the timeout.
        with contextlib.suppress(Exception):
            subprocess.run(  # noqa: S603
                ["taskkill.exe", "/F", "/T", "/PID", str(process.pid)],
                capture_output=True,
                timeout=10,
                check=False,
            )
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(process.wait(), timeout=5)
        raise EnforcementError("windows firewall command timed out") from exc
    return CommandResult(
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=stdout.decode("utf-8", errors="replace")[:_MAX_OUTPUT_CHARS],
        stderr=stderr.decode("utf-8", errors="replace")[:_MAX_ERROR_CHARS * 4],
    )


def _bounded(text: str, limit: int = _MAX_ERROR_CHARS) -> str:
    return text[:limit]


def _safe_token(value: str) -> str:
    if _SAFE_TOKEN_RE.fullmatch(value):
        return value
    return "h" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


class WindowsFirewallEndpointAdapter:
    """Windows Defender Firewall endpoint enforcement adapter (BLOCK_IP only).

    Safety invariants:
      - disabled unless ``MON_ENABLE_WINDOWS_FIREWALL_ENFORCEMENT=1``;
      - only creates and removes rules in the MON-owned group
        ``MON Endpoint Containment``; removal is additionally guarded by group
        membership inside the script;
      - never disables the firewall, never touches profiles or unrelated rules;
      - no shell: fixed argv, fixed script, values passed through environment
        variables, the only untrusted value (the IP) parsed by ``ipaddress``;
      - every rule carries a bounded deterministic marker as its display name
        and a hash-derived unique rule name;
      - a conflicting or ambiguous MON-owned rule fails closed.
    """

    group = _GROUP

    def __init__(
        self,
        *,
        timeout_seconds: float = 20.0,
        runner: CommandRunner | None = None,
        powershell_binary: str | None = None,
    ) -> None:
        if sys.platform != "win32":
            raise EnforcementError("Windows firewall endpoint adapter requires Windows")
        if os.environ.get(_ENABLE_ENV) != "1":
            raise EnforcementError(
                f"{_ENABLE_ENV}=1 is required to enable Windows firewall enforcement"
            )
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError("timeout_seconds must be greater than 0 and at most 60")
        self.timeout_seconds = timeout_seconds
        self._runner = runner or _default_runner
        self.powershell_binary = powershell_binary or shutil.which("powershell.exe")
        if self.powershell_binary is None:
            raise EnforcementError("powershell.exe is required")

    @property
    def capabilities(self) -> EnforcementAdapterCapabilities:
        return EnforcementAdapterCapabilities(
            supported_actions={ActionType.BLOCK_IP},
            execution_plane=EnforcementExecutionPlane.SITE,
            supports_verify=True,
            supports_rollback=True,
            supports_reconcile=True,
            apply_idempotent=True,
            rollback_idempotent=True,
            credential_requirement=CredentialRequirement.NONE,
            supports_credential_ref=True,
            external_timeout_seconds=self.timeout_seconds,
            remote_api=False,
            critical_asset_approval_recommended=True,
            supported_target_types={TargetType.IP_ADDRESS},
        )

    # ---- helpers ---------------------------------------------------------

    @staticmethod
    def _address(plan: ResponsePlan) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        if plan.request.action is not ActionType.BLOCK_IP:
            raise EnforcementError(
                "Windows firewall endpoint adapter currently supports BLOCK_IP only"
            )
        value = plan.request.target.ip_address
        if value is None:
            raise EnforcementError("BLOCK_IP requires an ip_address response target")
        try:
            return ipaddress.ip_address(value)
        except ValueError as exc:
            raise EnforcementError("BLOCK_IP target is not a valid IP address") from exc

    @staticmethod
    def _marker(plan: ResponsePlan, execution_id: str) -> str:
        marker = (
            f"{_MARKER_PREFIX}{_safe_token(plan.request.tenant_id)}:"
            f"{_safe_token(plan.request.site_id)}:{_safe_token(execution_id)}"
        )
        if len(marker) > _MAX_MARKER_CHARS:
            raise EnforcementError("firewall rule marker exceeds bounded length")
        return marker

    @staticmethod
    def _rule_name(marker: str) -> str:
        return "mon-v1-" + hashlib.sha256(marker.encode("utf-8")).hexdigest()[:32]

    def _reference(self, marker: str) -> str:
        return f"winfw:{_GROUP}/{self._rule_name(marker)}:{marker}"

    async def _run(
        self,
        op: str,
        *,
        name: str = "",
        display: str = "",
        address: str = "",
    ) -> list[dict[str, Any]]:
        env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
        env.update(
            {
                "MON_FW_OP": op,
                "MON_FW_GROUP": _GROUP,
                "MON_FW_NAME": name,
                "MON_FW_DISPLAY": display,
                "MON_FW_ADDR": address,
            }
        )
        command = [
            str(self.powershell_binary),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            _encoded_script(),
        ]
        result = await self._runner(command, env, self.timeout_seconds)
        if result.returncode != 0:
            raise _FirewallCommandError(_bounded(result.stderr or result.stdout))
        try:
            parsed = json.loads(result.stdout.strip() or "[]")
        except ValueError as exc:
            raise _FirewallCommandError("firewall command returned unparseable output") from exc
        if isinstance(parsed, dict):
            parsed = [parsed]
        if not isinstance(parsed, list):
            raise _FirewallCommandError("firewall command returned unexpected output")
        return [item for item in parsed if isinstance(item, dict)]

    @staticmethod
    def _well_formed(rule: dict[str, Any], name: str, address: Any) -> bool:
        if rule.get("name") != name:
            return False
        if str(rule.get("enabled")).lower() not in {"true", "1"}:
            return False
        if str(rule.get("action")).lower() != "block":
            return False
        if str(rule.get("direction")).lower() != "inbound":
            return False
        remotes = rule.get("remote") or []
        if isinstance(remotes, str):
            remotes = [remotes]
        if len(remotes) != 1:
            return False
        try:
            network = ipaddress.ip_network(str(remotes[0]), strict=False)
        except ValueError:
            return False
        return network == ipaddress.ip_network(address)

    @staticmethod
    def _owned(rules: list[dict[str, Any]], marker: str, name: str) -> list[dict[str, Any]]:
        return [r for r in rules if r.get("display") == marker or r.get("name") == name]

    # ---- adapter contract --------------------------------------------------

    async def verify(self, plan: ResponsePlan, execution_id: str) -> EnforcementVerification:
        address = self._address(plan)
        marker = self._marker(plan, execution_id)
        name = self._rule_name(marker)
        reference = self._reference(marker)
        try:
            rules = await self._run("list")
        except _FirewallCommandError as exc:
            return EnforcementVerification(
                state=EnforcementVerificationState.UNKNOWN,
                message="unable to verify MON Windows firewall rule state",
                external_reference=reference,
                details={"address": str(address), "stderr": str(exc)},
            )
        owned = self._owned(rules, marker, name)
        if not owned:
            return EnforcementVerification(
                state=EnforcementVerificationState.ABSENT,
                message="MON Windows firewall rule is absent",
                external_reference=reference,
                details={"address": str(address)},
            )
        if len(owned) == 1 and self._well_formed(owned[0], name, address):
            return EnforcementVerification(
                state=EnforcementVerificationState.PRESENT,
                message="MON Windows firewall rule is present",
                external_reference=reference,
                details={"address": str(address)},
            )
        return EnforcementVerification(
            state=EnforcementVerificationState.UNKNOWN,
            message="MON Windows firewall rules are ambiguous or do not match the plan",
            external_reference=reference,
            details={"address": str(address), "matching_rules": len(owned)},
        )

    async def execute(self, plan: ResponsePlan, execution_id: str) -> EnforcementResult:
        address = self._address(plan)
        marker = self._marker(plan, execution_id)
        name = self._rule_name(marker)
        reference = self._reference(marker)
        try:
            rules = await self._run("list")
        except _FirewallCommandError as exc:
            raise EnforcementError(f"failed to inspect MON firewall group: {exc}") from exc
        owned = self._owned(rules, marker, name)
        if len(owned) > 1:
            raise EnforcementError("multiple MON firewall rules already share this execution id")
        if len(owned) == 1:
            if self._well_formed(owned[0], name, address):
                return EnforcementResult(
                    success=True,
                    message="MON Windows firewall rule already present",
                    external_reference=reference,
                    details={"address": str(address), "idempotent": True},
                )
            raise EnforcementError(
                "a conflicting MON firewall rule already exists for this execution id"
            )
        try:
            after = await self._run(
                "add", name=name, display=marker, address=str(address)
            )
        except _FirewallCommandError as exc:
            return EnforcementResult(
                success=False,
                message=f"windows firewall rule application failed: {exc}",
                details={"address": str(address)},
            )
        created = self._owned(after, marker, name)
        if len(created) != 1 or not self._well_formed(created[0], name, address):
            return EnforcementResult(
                success=False,
                message="windows firewall rule was not observed after creation",
                details={"address": str(address)},
            )
        return EnforcementResult(
            success=True,
            message="MON Windows firewall source block applied",
            external_reference=reference,
            details={"address": str(address)},
        )

    async def rollback(self, plan: ResponsePlan, execution_id: str) -> EnforcementResult:
        address = self._address(plan)
        marker = self._marker(plan, execution_id)
        name = self._rule_name(marker)
        reference = self._reference(marker)
        try:
            rules = await self._run("list")
        except _FirewallCommandError as exc:
            return EnforcementResult(
                success=False,
                message=f"unable to inspect MON firewall group for rollback: {exc}",
                details={"address": str(address)},
            )
        owned = self._owned(rules, marker, name)
        if not owned:
            return EnforcementResult(
                success=True,
                message="MON Windows firewall rule already removed",
                external_reference=reference,
                details={"address": str(address), "idempotent": True},
            )
        if len(owned) != 1 or owned[0].get("name") != name:
            raise EnforcementError("multiple or foreign MON firewall rules share the marker")
        try:
            after = await self._run("remove", name=name)
        except _FirewallCommandError as exc:
            return EnforcementResult(
                success=False,
                message=f"windows firewall rollback failed: {exc}",
                details={"address": str(address)},
            )
        if self._owned(after, marker, name):
            return EnforcementResult(
                success=False,
                message="windows firewall rule was still observed after removal",
                details={"address": str(address)},
            )
        return EnforcementResult(
            success=True,
            message="MON Windows firewall source block removed",
            external_reference=reference,
            details={"address": str(address)},
        )

    async def reconcile(
        self,
        plan: ResponsePlan,
        execution_id: str,
        *,
        expected_state: EnforcementVerificationState,
    ) -> EnforcementReconciliation:
        """Observation-first reconciliation: report drift, never repair it."""
        verification = await self.verify(plan, execution_id)
        drifted = verification.state != expected_state
        message = (
            "observed Windows firewall state matches the expected containment state"
            if not drifted
            else f"observed {verification.state.value} but expected {expected_state.value}"
        )
        return EnforcementReconciliation(
            observed_state=verification.state,
            expected_state=expected_state,
            drifted=drifted,
            message=message,
            external_reference=verification.external_reference,
            details=verification.details,
        )


class _FirewallCommandError(RuntimeError):
    pass
