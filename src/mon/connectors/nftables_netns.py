from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import re
import shutil
import signal
import sys
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from mon.domain import (
    ActionType,
    EnforcementResult,
    EnforcementVerification,
    EnforcementVerificationState,
    ResponsePlan,
)
from mon.enforcement import EnforcementError


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


CommandRunner = Callable[
    [list[str], str | None, float],
    Awaitable[CommandResult],
]

_ENABLE_ENV = "MON_ENABLE_DISPOSABLE_NETNS_ENFORCEMENT"
_NAMESPACE_PATTERN = re.compile(r"^mon-(?:ci|sandbox)-[A-Za-z0-9_.-]{1,64}$")
_EXECUTION_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


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
        raise EnforcementError("nftables namespace command timed out") from exc

    return CommandResult(
        returncode=process.returncode,
        stdout=stdout.decode("utf-8", errors="replace"),
        stderr=stderr.decode("utf-8", errors="replace"),
    )


class DisposableNftablesAdapter:
    """nftables adapter restricted to a disposable Linux network namespace.

    This adapter intentionally cannot operate in the host network namespace.
    """

    table_name = "mon_ci"
    chain_name = "input"

    def __init__(
        self,
        namespace: str,
        *,
        timeout_seconds: float = 3.0,
        runner: CommandRunner | None = None,
        ip_binary: str | None = None,
        nft_binary: str | None = None,
    ) -> None:
        if sys.platform != "linux":
            raise EnforcementError("disposable nftables adapter requires Linux")
        if os.environ.get(_ENABLE_ENV) != "1":
            raise EnforcementError(
                f"{_ENABLE_ENV}=1 is required to enable disposable enforcement"
            )
        if not _NAMESPACE_PATTERN.fullmatch(namespace):
            raise EnforcementError(
                "namespace must match mon-ci-* or mon-sandbox-*; host namespace is forbidden"
            )
        if timeout_seconds <= 0 or timeout_seconds > 30:
            raise ValueError("timeout_seconds must be greater than 0 and at most 30")

        self.namespace = namespace
        self.timeout_seconds = timeout_seconds
        self._runner = runner or _default_runner
        self.ip_binary = ip_binary or shutil.which("ip")
        self.nft_binary = nft_binary or shutil.which("nft")
        if self.ip_binary is None or self.nft_binary is None:
            raise EnforcementError("ip and nft executables are required")

    def _command(self, *nft_args: str) -> list[str]:
        return [
            self.ip_binary,
            "netns",
            "exec",
            self.namespace,
            self.nft_binary,
            *nft_args,
        ]

    async def _run(
        self,
        *nft_args: str,
        stdin_text: str | None = None,
    ) -> CommandResult:
        if stdin_text is None:
            return await self._runner(
                self._command(*nft_args),
                None,
                self.timeout_seconds,
            )

        script_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                prefix="mon-nft-",
                suffix=".nft",
                delete=False,
            ) as script:
                script.write(stdin_text)
                script_path = script.name
            return await self._runner(
                self._command(*(script_path if arg == "-" else arg for arg in nft_args)),
                None,
                self.timeout_seconds,
            )
        finally:
            if script_path is not None:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(script_path)

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
                f"failed to create disposable nftables table: {created.stderr[:500]}"
            )

    @staticmethod
    def _execution_comment(execution_id: str) -> str:
        if not _EXECUTION_PATTERN.fullmatch(execution_id):
            raise EnforcementError("execution_id contains unsupported characters")
        return f"mon:{execution_id}"

    @staticmethod
    def _address(plan: ResponsePlan) -> tuple[str, str]:
        if plan.request.action is not ActionType.BLOCK_IP:
            raise EnforcementError(
                "disposable nftables adapter currently supports BLOCK_IP only"
            )
        value = plan.request.target.ip_address
        if value is None:
            raise EnforcementError("BLOCK_IP requires an ip_address response target")
        address = ipaddress.ip_address(value)
        family = "ip" if address.version == 4 else "ip6"
        return family, str(address)

    async def _rules(self) -> CommandResult:
        return await self._run(
            "-a",
            "list",
            "chain",
            "inet",
            self.table_name,
            self.chain_name,
        )

    async def verify(
        self,
        plan: ResponsePlan,
        execution_id: str,
    ) -> EnforcementVerification:
        _, address = self._address(plan)
        comment = self._execution_comment(execution_id)
        rules = await self._rules()
        external_reference = (
            f"nft:inet/{self.table_name}/{self.chain_name}:{comment}"
        )
        if rules.returncode != 0:
            return EnforcementVerification(
                state=EnforcementVerificationState.UNKNOWN,
                message="unable to verify disposable nftables rule state",
                external_reference=external_reference,
                details={
                    "namespace": self.namespace,
                    "address": address,
                    "stderr": rules.stderr[:500],
                },
            )

        marker = f'comment "{comment}"'
        matching = [line for line in rules.stdout.splitlines() if marker in line]
        if not matching:
            return EnforcementVerification(
                state=EnforcementVerificationState.ABSENT,
                message="disposable nftables rule is absent",
                external_reference=external_reference,
                details={"namespace": self.namespace, "address": address},
            )
        if len(matching) == 1:
            return EnforcementVerification(
                state=EnforcementVerificationState.PRESENT,
                message="disposable nftables rule is present",
                external_reference=external_reference,
                details={"namespace": self.namespace, "address": address},
            )
        return EnforcementVerification(
            state=EnforcementVerificationState.UNKNOWN,
            message="multiple disposable nftables rules share the execution marker",
            external_reference=external_reference,
            details={
                "namespace": self.namespace,
                "address": address,
                "matching_rules": len(matching),
            },
        )

    async def execute(
        self,
        plan: ResponsePlan,
        execution_id: str,
    ) -> EnforcementResult:
        family, address = self._address(plan)
        comment = self._execution_comment(execution_id)
        await self._ensure_table()

        rules = await self._rules()
        if rules.returncode != 0:
            raise EnforcementError(
                f"failed to inspect disposable nftables chain: {rules.stderr[:500]}"
            )
        marker = f'comment "{comment}"'
        if marker in rules.stdout:
            return EnforcementResult(
                success=True,
                message="disposable nftables rule already present",
                external_reference=f"nft:inet/{self.table_name}/{self.chain_name}:{comment}",
                details={
                    "namespace": self.namespace,
                    "address": address,
                    "idempotent": True,
                },
            )

        script = (
            f"add rule inet {self.table_name} {self.chain_name} "
            f'{family} saddr {address} drop comment "{comment}"\n'
        )
        result = await self._run("-f", "-", stdin_text=script)
        if result.returncode != 0:
            return EnforcementResult(
                success=False,
                message=f"nftables rule application failed: {result.stderr[:500]}",
                details={"namespace": self.namespace, "address": address},
            )
        return EnforcementResult(
            success=True,
            message="disposable nftables source block applied",
            external_reference=f"nft:inet/{self.table_name}/{self.chain_name}:{comment}",
            details={"namespace": self.namespace, "address": address},
        )

    async def rollback(
        self,
        plan: ResponsePlan,
        execution_id: str,
    ) -> EnforcementResult:
        _, address = self._address(plan)
        comment = self._execution_comment(execution_id)
        rules = await self._rules()
        if rules.returncode != 0:
            return EnforcementResult(
                success=True,
                message="disposable nftables table is absent; rule already removed",
                details={
                    "namespace": self.namespace,
                    "address": address,
                    "idempotent": True,
                },
            )

        marker = f'comment "{comment}"'
        matching = [line for line in rules.stdout.splitlines() if marker in line]
        if not matching:
            return EnforcementResult(
                success=True,
                message="disposable nftables rule already removed",
                external_reference=f"nft:inet/{self.table_name}/{self.chain_name}:{comment}",
                details={
                    "namespace": self.namespace,
                    "address": address,
                    "idempotent": True,
                },
            )
        if len(matching) != 1:
            raise EnforcementError(
                "multiple nftables rules share the same execution marker"
            )

        handle_match = re.search(r"\bhandle\s+(\d+)\b", matching[0])
        if handle_match is None:
            raise EnforcementError("nftables rule handle was not present")
        handle = handle_match.group(1)
        script = (
            f"delete rule inet {self.table_name} {self.chain_name} handle {handle}\n"
        )
        result = await self._run("-f", "-", stdin_text=script)
        if result.returncode != 0:
            return EnforcementResult(
                success=False,
                message=f"nftables rollback failed: {result.stderr[:500]}",
                details={"namespace": self.namespace, "address": address},
            )
        return EnforcementResult(
            success=True,
            message="disposable nftables source block removed",
            external_reference=f"nft:inet/{self.table_name}/{self.chain_name}:{comment}",
            details={"namespace": self.namespace, "address": address},
        )
