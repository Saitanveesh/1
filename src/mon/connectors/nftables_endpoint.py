from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import os
import re
import shutil
import signal
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

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


CommandRunner = Callable[
    [list[str], str | None, float],
    Awaitable[CommandResult],
]

# Hard production-host safety gate. Absent by default; this alone is a
# deployment guard, not authorization -- policy gating and approval remain
# authoritative (see mon.policy).
_ENABLE_ENV = "MON_ENABLE_ENDPOINT_NFTABLES_ENFORCEMENT"
_NAMESPACE_PATTERN = re.compile(r"^mon-(?:ci|sandbox)-[A-Za-z0-9_.-]{1,64}$")
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_MON_MARKER_PREFIX = "mon:v1:"
_MAX_COMMENT_BYTES = 120
_MAX_ERROR_CHARS = 500


async def _default_runner(
    command: list[str],
    stdin_text: str | None,
    timeout_seconds: float,
) -> CommandResult:
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE if stdin_text is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(
                stdin_text.encode("utf-8") if stdin_text is not None else None
            ),
            timeout=timeout_seconds,
        )
    except TimeoutError as exc:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        await process.wait()
        raise EnforcementError("nftables endpoint command timed out") from exc

    return CommandResult(
        returncode=process.returncode,
        stdout=stdout.decode("utf-8", errors="replace"),
        stderr=stderr.decode("utf-8", errors="replace"),
    )


def _bounded(text: str, limit: int = _MAX_ERROR_CHARS) -> str:
    return text[:limit]


def _safe_token(value: str) -> str:
    if _SAFE_TOKEN_RE.fullmatch(value):
        return value
    return "h" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


class LinuxNftablesEndpointAdapter:
    """Linux endpoint host nftables enforcement adapter (BLOCK_IP only).

    Unlike `DisposableNftablesAdapter` (netns-only, CI-only), this adapter is
    designed to eventually run against a real endpoint host's own network
    namespace. It is gated behind `MON_ENABLE_ENDPOINT_NFTABLES_ENFORCEMENT=1`
    (disabled by default) and, when constructed with `namespace=...`, can
    still be pointed at a disposable network namespace for certification --
    which is how this milestone's CI exercises it. It is not yet certified
    for arbitrary production hosts; see ADR for the documented scope.

    Safety invariants:
      - never flushes tables or touches rules it did not create;
      - only ever creates/deletes rules inside its own MON-owned table/chain;
      - never invokes a shell and never interpolates untrusted telemetry into
        one -- the only untrusted value (the target IP) is parsed through
        `ipaddress.ip_address()` before it can reach any command text;
      - every owned rule carries a bounded, deterministic ownership comment
        tagging execution id and tenant/site scope.
    """

    table_name = "mon_endpoint"
    chain_name = "mon_block_ip"

    def __init__(
        self,
        *,
        namespace: str | None = None,
        timeout_seconds: float = 5.0,
        runner: CommandRunner | None = None,
        ip_binary: str | None = None,
        nft_binary: str | None = None,
    ) -> None:
        if sys.platform != "linux":
            raise EnforcementError("Linux nftables endpoint adapter requires Linux")
        if os.environ.get(_ENABLE_ENV) != "1":
            raise EnforcementError(
                f"{_ENABLE_ENV}=1 is required to enable endpoint nftables enforcement"
            )
        if namespace is not None and not _NAMESPACE_PATTERN.fullmatch(namespace):
            raise EnforcementError(
                "namespace must match mon-ci-* or mon-sandbox-* when set"
            )
        if timeout_seconds <= 0 or timeout_seconds > 30:
            raise ValueError("timeout_seconds must be greater than 0 and at most 30")

        self.namespace = namespace
        self.timeout_seconds = timeout_seconds
        self._runner = runner or _default_runner
        self.nft_binary = nft_binary or shutil.which("nft")
        self.ip_binary = ip_binary or shutil.which("ip")
        if self.nft_binary is None:
            raise EnforcementError("nft executable is required")
        if self.namespace is not None and self.ip_binary is None:
            raise EnforcementError("ip executable is required for namespace-scoped operation")

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

    def _command(self, *nft_args: str) -> list[str]:
        if self.namespace is not None:
            return [
                self.ip_binary,
                "netns",
                "exec",
                self.namespace,
                self.nft_binary,
                *nft_args,
            ]
        return [self.nft_binary, *nft_args]

    async def _run(self, *nft_args: str, stdin_text: str | None = None) -> CommandResult:
        return await self._runner(self._command(*nft_args), stdin_text, self.timeout_seconds)

    async def _ensure_table(self) -> None:
        existing = await self._run("list", "table", "inet", self.table_name)
        if existing.returncode == 0:
            return
        script = (
            f"table inet {self.table_name} {{\n"
            f"  chain {self.chain_name} {{\n"
            "    type filter hook input priority 0; policy accept;\n"
            "  }\n"
            "}\n"
        )
        created = await self._run("-f", "-", stdin_text=script)
        if created.returncode != 0:
            raise EnforcementError(
                f"failed to create MON nftables table: {_bounded(created.stderr)}"
            )

    async def _rules(self) -> CommandResult:
        return await self._run(
            "-a",
            "list",
            "chain",
            "inet",
            self.table_name,
            self.chain_name,
        )

    @staticmethod
    def _address(plan: ResponsePlan) -> tuple[str, str]:
        if plan.request.action is not ActionType.BLOCK_IP:
            raise EnforcementError(
                "Linux nftables endpoint adapter currently supports BLOCK_IP only"
            )
        value = plan.request.target.ip_address
        if value is None:
            raise EnforcementError("BLOCK_IP requires an ip_address response target")
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise EnforcementError("BLOCK_IP target is not a valid IP address") from exc
        family = "ip" if address.version == 4 else "ip6"
        return family, str(address)

    def _comment(self, plan: ResponsePlan, execution_id: str) -> str:
        tenant = _safe_token(plan.request.tenant_id)
        site = _safe_token(plan.request.site_id)
        execution = _safe_token(execution_id)
        comment = f"{_MON_MARKER_PREFIX}{tenant}:{site}:{execution}"
        if len(comment.encode("utf-8")) > _MAX_COMMENT_BYTES:
            raise EnforcementError("nftables rule comment exceeds bounded length")
        return comment

    def _external_reference(self, comment: str) -> str:
        scope = f"netns/{self.namespace}" if self.namespace else "host"
        return f"nft:{scope}/inet/{self.table_name}/{self.chain_name}:{comment}"

    async def verify(
        self,
        plan: ResponsePlan,
        execution_id: str,
    ) -> EnforcementVerification:
        _, address = self._address(plan)
        comment = self._comment(plan, execution_id)
        rules = await self._rules()
        reference = self._external_reference(comment)
        if rules.returncode != 0:
            return EnforcementVerification(
                state=EnforcementVerificationState.UNKNOWN,
                message="unable to verify MON nftables rule state",
                external_reference=reference,
                details={"address": address, "stderr": _bounded(rules.stderr)},
            )

        marker = f'comment "{comment}"'
        matching = [line for line in rules.stdout.splitlines() if marker in line]
        if not matching:
            return EnforcementVerification(
                state=EnforcementVerificationState.ABSENT,
                message="MON nftables rule is absent",
                external_reference=reference,
                details={"address": address},
            )
        if len(matching) == 1:
            return EnforcementVerification(
                state=EnforcementVerificationState.PRESENT,
                message="MON nftables rule is present",
                external_reference=reference,
                details={"address": address},
            )
        return EnforcementVerification(
            state=EnforcementVerificationState.UNKNOWN,
            message="multiple MON nftables rules share the same execution marker",
            external_reference=reference,
            details={"address": address, "matching_rules": len(matching)},
        )

    async def execute(
        self,
        plan: ResponsePlan,
        execution_id: str,
    ) -> EnforcementResult:
        family, address = self._address(plan)
        comment = self._comment(plan, execution_id)
        await self._ensure_table()

        rules = await self._rules()
        if rules.returncode != 0:
            raise EnforcementError(
                f"failed to inspect MON nftables chain: {_bounded(rules.stderr)}"
            )
        marker = f'comment "{comment}"'
        matching = [line for line in rules.stdout.splitlines() if marker in line]
        if len(matching) > 1:
            raise EnforcementError(
                "multiple MON nftables rules already share this execution id"
            )
        if len(matching) == 1:
            if f"{family} saddr {address} drop" in matching[0]:
                return EnforcementResult(
                    success=True,
                    message="MON nftables rule already present",
                    external_reference=self._external_reference(comment),
                    details={"address": address, "idempotent": True},
                )
            raise EnforcementError(
                "a conflicting MON nftables rule already exists for this execution id"
            )

        script = (
            f"add rule inet {self.table_name} {self.chain_name} "
            f'{family} saddr {address} drop comment "{comment}"\n'
        )
        result = await self._run("-f", "-", stdin_text=script)
        if result.returncode != 0:
            return EnforcementResult(
                success=False,
                message=f"nftables rule application failed: {_bounded(result.stderr)}",
                details={"address": address},
            )
        return EnforcementResult(
            success=True,
            message="MON nftables source block applied",
            external_reference=self._external_reference(comment),
            details={"address": address},
        )

    async def rollback(
        self,
        plan: ResponsePlan,
        execution_id: str,
    ) -> EnforcementResult:
        _, address = self._address(plan)
        comment = self._comment(plan, execution_id)
        rules = await self._rules()
        if rules.returncode != 0:
            return EnforcementResult(
                success=True,
                message="MON nftables table is absent; rule already removed",
                details={"address": address, "idempotent": True},
            )

        marker = f'comment "{comment}"'
        matching = [line for line in rules.stdout.splitlines() if marker in line]
        if not matching:
            return EnforcementResult(
                success=True,
                message="MON nftables rule already removed",
                external_reference=self._external_reference(comment),
                details={"address": address, "idempotent": True},
            )
        if len(matching) != 1:
            raise EnforcementError(
                "multiple MON nftables rules share the same execution marker"
            )

        handle_match = re.search(r"\bhandle\s+(\d+)\b", matching[0])
        if handle_match is None:
            raise EnforcementError("MON nftables rule handle was not present")
        handle = handle_match.group(1)
        script = f"delete rule inet {self.table_name} {self.chain_name} handle {handle}\n"
        result = await self._run("-f", "-", stdin_text=script)
        if result.returncode != 0:
            return EnforcementResult(
                success=False,
                message=f"nftables rollback failed: {_bounded(result.stderr)}",
                details={"address": address},
            )
        return EnforcementResult(
            success=True,
            message="MON nftables source block removed",
            external_reference=self._external_reference(comment),
            details={"address": address},
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
            "observed nftables state matches the expected containment state"
            if not drifted
            else (
                f"observed {verification.state.value} but expected "
                f"{expected_state.value}"
            )
        )
        return EnforcementReconciliation(
            observed_state=verification.state,
            expected_state=expected_state,
            drifted=drifted,
            message=message,
            external_reference=verification.external_reference,
            details=verification.details,
        )
