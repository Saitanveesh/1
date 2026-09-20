from __future__ import annotations

import threading
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mon.domain import (
    ActionType,
    EnforcementKind,
    EnforcementPoint,
    EnforcementReconciliation,
    EnforcementResult,
    EnforcementVerification,
    EnforcementVerificationState,
    ResponsePlan,
)


class EnforcementError(RuntimeError):
    pass


class EnforcementExecutionPlane(StrEnum):
    SITE = "SITE"
    CONTROL_PLANE = "CONTROL_PLANE"


_CONTROL_PLANE_KINDS = {
    EnforcementKind.WAF,
    EnforcementKind.CLOUD,
    EnforcementKind.UPSTREAM,
}


def execution_plane(point: EnforcementPoint) -> EnforcementExecutionPlane:
    configured = point.attributes.get("execution_plane")
    if configured is not None:
        try:
            return EnforcementExecutionPlane(str(configured).strip().upper())
        except ValueError as exc:
            raise EnforcementError(
                "enforcement point execution_plane must be SITE or CONTROL_PLANE"
            ) from exc
    if point.kind in _CONTROL_PLANE_KINDS:
        return EnforcementExecutionPlane.CONTROL_PLANE
    return EnforcementExecutionPlane.SITE


class EnforcementAdapter(Protocol):
    async def execute(
        self,
        plan: ResponsePlan,
        execution_id: str,
    ) -> EnforcementResult: ...

    async def rollback(
        self,
        plan: ResponsePlan,
        execution_id: str,
    ) -> EnforcementResult: ...


@runtime_checkable
class VerifiableEnforcementAdapter(Protocol):
    async def verify(
        self,
        plan: ResponsePlan,
        execution_id: str,
    ) -> EnforcementVerification: ...


@runtime_checkable
class ReconcilableEnforcementAdapter(Protocol):
    async def reconcile(
        self,
        plan: ResponsePlan,
        execution_id: str,
        *,
        expected_state: EnforcementVerificationState,
    ) -> EnforcementReconciliation: ...


# --------------------------------------------------------------------------
# Adapter capability/certification contract (Part A)
# --------------------------------------------------------------------------


class CredentialRequirement(StrEnum):
    """Whether an adapter needs a secret to operate at all."""

    NONE = "NONE"
    REQUIRED = "REQUIRED"


class TargetType(StrEnum):
    IP_ADDRESS = "IP_ADDRESS"
    ASSET = "ASSET"


_MAX_EXTERNAL_TIMEOUT_SECONDS = 300.0


class EnforcementAdapterCapabilities(BaseModel):
    """Typed operational guarantees an enforcement adapter actually provides.

    This is distinct from `EnforcementPoint.capabilities` (the *configured*
    action set for one deployed enforcement point). This model describes what
    the adapter *implementation* itself supports, so the registry can reject
    an enforcement point whose configuration claims something the registered
    adapter code cannot actually do.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    supported_actions: set[ActionType] = Field(min_length=1)
    execution_plane: EnforcementExecutionPlane
    supports_verify: bool
    supports_rollback: bool
    supports_reconcile: bool
    apply_idempotent: bool
    rollback_idempotent: bool
    credential_requirement: CredentialRequirement
    supports_credential_ref: bool
    external_timeout_seconds: float = Field(gt=0, le=_MAX_EXTERNAL_TIMEOUT_SECONDS)
    remote_api: bool
    critical_asset_approval_recommended: bool
    supported_target_types: set[TargetType] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_combination(self) -> EnforcementAdapterCapabilities:
        if (
            self.credential_requirement is CredentialRequirement.REQUIRED
            and not self.supports_credential_ref
        ):
            raise ValueError(
                "an adapter that requires a credential must support credential_ref "
                "(inline credentials are forbidden)"
            )
        return self


def _legacy_inferred_capabilities(adapter: EnforcementAdapter) -> EnforcementAdapterCapabilities:
    """Best-effort capability inference for adapters registered without an
    explicit declaration (pre-existing call sites, test fakes). This is
    deliberately permissive on `supported_actions`/`supported_target_types`
    so registration-time mismatch checks only ever apply to adapters that
    opt in with an explicit `capabilities=` declaration.
    """

    return EnforcementAdapterCapabilities(
        supported_actions=set(ActionType),
        execution_plane=EnforcementExecutionPlane.SITE,
        supports_verify=isinstance(adapter, VerifiableEnforcementAdapter),
        supports_rollback=True,
        supports_reconcile=isinstance(adapter, ReconcilableEnforcementAdapter),
        apply_idempotent=False,
        rollback_idempotent=False,
        credential_requirement=CredentialRequirement.NONE,
        supports_credential_ref=True,
        external_timeout_seconds=30.0,
        remote_api=True,
        critical_asset_approval_recommended=False,
        supported_target_types={TargetType.IP_ADDRESS, TargetType.ASSET},
    )


def _validate_capabilities_against_adapter(
    adapter: EnforcementAdapter,
    capabilities: EnforcementAdapterCapabilities,
) -> None:
    if not (hasattr(adapter, "execute") and callable(adapter.execute)):
        raise EnforcementError("adapter must implement execute()")
    if capabilities.supports_rollback and not (
        hasattr(adapter, "rollback") and callable(adapter.rollback)
    ):
        raise EnforcementError(
            "adapter capabilities declare rollback support but the adapter has no rollback()"
        )
    if capabilities.supports_verify and not isinstance(adapter, VerifiableEnforcementAdapter):
        raise EnforcementError(
            "adapter capabilities declare verify support but the adapter does not "
            "implement verify()"
        )
    if capabilities.supports_reconcile and not isinstance(
        adapter, ReconcilableEnforcementAdapter
    ):
        raise EnforcementError(
            "adapter capabilities declare reconcile support but the adapter does not "
            "implement reconcile()"
        )


class EnforcementRegistry:
    def __init__(self) -> None:
        self._adapters: dict[tuple[EnforcementKind, str], EnforcementAdapter] = {}
        self._capabilities: dict[tuple[EnforcementKind, str], EnforcementAdapterCapabilities] = {}
        self._lock = threading.RLock()

    def register(
        self,
        kind: EnforcementKind,
        vendor: str,
        adapter: EnforcementAdapter,
        *,
        capabilities: EnforcementAdapterCapabilities | None = None,
    ) -> None:
        resolved = capabilities if capabilities is not None else _legacy_inferred_capabilities(
            adapter
        )
        _validate_capabilities_against_adapter(adapter, resolved)
        with self._lock:
            key = (kind, vendor.casefold())
            self._adapters[key] = adapter
            self._capabilities[key] = resolved

    def resolve(self, kind: EnforcementKind, vendor: str) -> EnforcementAdapter:
        with self._lock:
            exact = self._adapters.get((kind, vendor.casefold()))
            generic = self._adapters.get((kind, "*"))
            adapter = exact or generic
        if adapter is None:
            raise EnforcementError(f"no enforcement adapter for {kind.value}/{vendor}")
        return adapter

    def get_capabilities(
        self, kind: EnforcementKind, vendor: str
    ) -> EnforcementAdapterCapabilities | None:
        with self._lock:
            exact = self._capabilities.get((kind, vendor.casefold()))
            generic = self._capabilities.get((kind, "*"))
            return exact or generic
