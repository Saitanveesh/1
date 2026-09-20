from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from mon.domain import EnforcementVerificationState, ResponsePlan
from mon.enforcement import (
    EnforcementAdapterCapabilities,
    ReconcilableEnforcementAdapter,
    VerifiableEnforcementAdapter,
)


class AdapterCertificationError(AssertionError):
    """Raised when a certification step fails; carries the failing step name
    so a caller (or a failing pytest assertion) can tell which guarantee was
    violated without re-deriving it from a generic message.
    """

    def __init__(self, step: str, detail: str) -> None:
        super().__init__(f"[{step}] {detail}")
        self.step = step
        self.detail = detail


@dataclass(frozen=True, slots=True)
class AdapterCertificationReport:
    steps_passed: tuple[str, ...]


async def certify_enforcement_adapter(
    adapter: Any,
    capabilities: EnforcementAdapterCapabilities,
    plan: ResponsePlan,
    execution_id: str,
    *,
    invalid_target_plan: ResponsePlan | None = None,
    unsupported_action_plan: ResponsePlan | None = None,
    scope_mismatch_plan: ResponsePlan | None = None,
    assert_timeout: Callable[[], Awaitable[None]] | None = None,
    unrelated_state_snapshot: Callable[[], Awaitable[Any]] | None = None,
) -> AdapterCertificationReport:
    """Exercise the common guarantees any enforcement adapter should meet.

    This is intentionally small and practical rather than a general test
    framework: it drives one adapter through one realistic apply/verify/
    rollback/reconcile cycle plus a handful of pluggable negative cases, and
    raises `AdapterCertificationError` naming the first guarantee that broke.
    Callers (adapter-specific test suites) still own constructing a valid
    `plan`/`execution_id` and any negative-case plans/timeout trigger for
    their adapter; this harness only owns the sequence and the assertions.
    """
    passed: list[str] = []

    def step(name: str) -> None:
        passed.append(name)

    if capabilities.supports_verify != isinstance(adapter, VerifiableEnforcementAdapter):
        raise AdapterCertificationError(
            "capability_declaration",
            "capabilities.supports_verify does not match adapter.verify() presence",
        )
    if capabilities.supports_reconcile != isinstance(adapter, ReconcilableEnforcementAdapter):
        raise AdapterCertificationError(
            "capability_declaration",
            "capabilities.supports_reconcile does not match adapter.reconcile() presence",
        )
    if capabilities.supports_rollback and not (
        hasattr(adapter, "rollback") and callable(adapter.rollback)
    ):
        raise AdapterCertificationError(
            "capability_declaration",
            "capabilities.supports_rollback=True but the adapter has no rollback()",
        )
    step("capability_declaration_matches_behavior")

    baseline = await unrelated_state_snapshot() if unrelated_state_snapshot else None

    applied = await adapter.execute(plan, execution_id)
    if not applied.success:
        raise AdapterCertificationError("apply", f"initial apply failed: {applied.message}")
    step("apply")

    if capabilities.supports_verify:
        present = await adapter.verify(plan, execution_id)
        if present.state is not EnforcementVerificationState.PRESENT:
            raise AdapterCertificationError(
                "verify_present", f"expected PRESENT, observed {present.state.value}"
            )
        step("verify_present")

    repeat_apply = await adapter.execute(plan, execution_id)
    if not repeat_apply.success:
        raise AdapterCertificationError(
            "apply_idempotent", f"repeated apply failed: {repeat_apply.message}"
        )
    if capabilities.apply_idempotent and not repeat_apply.details.get("idempotent", False):
        raise AdapterCertificationError(
            "apply_idempotent",
            "capabilities.apply_idempotent=True but repeated apply did not report idempotent",
        )
    step("apply_idempotent")

    if capabilities.supports_reconcile:
        reconciled_present = await adapter.reconcile(
            plan, execution_id, expected_state=EnforcementVerificationState.PRESENT
        )
        if reconciled_present.observed_state is not EnforcementVerificationState.PRESENT:
            raise AdapterCertificationError(
                "reconcile_present",
                f"expected observed PRESENT, got {reconciled_present.observed_state.value}",
            )
        if reconciled_present.drifted:
            raise AdapterCertificationError(
                "reconcile_present", "reconcile reported drift when none was expected"
            )
        step("reconcile_present")

    if capabilities.supports_rollback:
        rolled_back = await adapter.rollback(plan, execution_id)
        if not rolled_back.success:
            raise AdapterCertificationError("rollback", f"rollback failed: {rolled_back.message}")
        step("rollback")

        if capabilities.supports_verify:
            absent = await adapter.verify(plan, execution_id)
            if absent.state is not EnforcementVerificationState.ABSENT:
                raise AdapterCertificationError(
                    "verify_absent", f"expected ABSENT, observed {absent.state.value}"
                )
            step("verify_absent")

        repeat_rollback = await adapter.rollback(plan, execution_id)
        if not repeat_rollback.success:
            raise AdapterCertificationError(
                "rollback_idempotent",
                f"repeated rollback failed: {repeat_rollback.message}",
            )
        if capabilities.rollback_idempotent and not repeat_rollback.details.get(
            "idempotent", False
        ):
            raise AdapterCertificationError(
                "rollback_idempotent",
                "capabilities.rollback_idempotent=True but repeated rollback did not "
                "report idempotent",
            )
        step("rollback_idempotent")

        if capabilities.supports_reconcile:
            reconciled_absent = await adapter.reconcile(
                plan, execution_id, expected_state=EnforcementVerificationState.ABSENT
            )
            if reconciled_absent.observed_state is not EnforcementVerificationState.ABSENT:
                raise AdapterCertificationError(
                    "reconcile_absent",
                    f"expected observed ABSENT, got {reconciled_absent.observed_state.value}",
                )
            if reconciled_absent.drifted:
                raise AdapterCertificationError(
                    "reconcile_absent", "reconcile reported drift when none was expected"
                )
            step("reconcile_absent")

    if assert_timeout is not None:
        try:
            await assert_timeout()
        except Exception:
            step("timeout_handling")
        else:
            raise AdapterCertificationError(
                "timeout_handling", "expected a timeout error but none was raised"
            )

    if invalid_target_plan is not None:
        try:
            await adapter.execute(invalid_target_plan, f"{execution_id}-invalid-target")
        except Exception:
            step("invalid_target_rejected")
        else:
            raise AdapterCertificationError(
                "invalid_target_rejected",
                "expected rejection of an invalid target but none occurred",
            )

    if unsupported_action_plan is not None:
        try:
            await adapter.execute(unsupported_action_plan, f"{execution_id}-unsupported-action")
        except Exception:
            step("unsupported_action_rejected")
        else:
            raise AdapterCertificationError(
                "unsupported_action_rejected",
                "expected rejection of an unsupported action but none occurred",
            )

    if scope_mismatch_plan is not None:
        try:
            await adapter.execute(scope_mismatch_plan, f"{execution_id}-scope-mismatch")
        except Exception:
            step("scope_mismatch_rejected")
        else:
            raise AdapterCertificationError(
                "scope_mismatch_rejected",
                "expected rejection of a scope-mismatched target but none occurred",
            )

    if unrelated_state_snapshot is not None:
        final = await unrelated_state_snapshot()
        if final != baseline:
            raise AdapterCertificationError(
                "no_unrelated_mutation",
                "unrelated state snapshot changed during certification",
            )
        step("no_unrelated_mutation")

    return AdapterCertificationReport(steps_passed=tuple(passed))
