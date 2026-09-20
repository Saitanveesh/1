from __future__ import annotations

import pytest

from mon.domain import (
    ActionType,
    Asset,
    EnforcementBinding,
    EnforcementKind,
    EnforcementPoint,
    EnforcementReconciliation,
    EnforcementResult,
    EnforcementVerification,
    EnforcementVerificationState,
    EvidenceClass,
    EvidenceRef,
    Incident,
    PolicyOutcome,
    ResponseRequest,
    ResponseTarget,
    Severity,
)
from mon.enforcement import (
    CredentialRequirement,
    EnforcementAdapterCapabilities,
    EnforcementError,
    EnforcementExecutionPlane,
    EnforcementRegistry,
    TargetType,
)
from mon.response import ResponseOrchestrator
from mon.store import InMemoryStore


def base_capabilities(**overrides: object) -> EnforcementAdapterCapabilities:
    fields: dict[str, object] = {
        "supported_actions": {ActionType.BLOCK_IP},
        "execution_plane": EnforcementExecutionPlane.SITE,
        "supports_verify": True,
        "supports_rollback": True,
        "supports_reconcile": True,
        "apply_idempotent": True,
        "rollback_idempotent": True,
        "credential_requirement": CredentialRequirement.NONE,
        "supports_credential_ref": True,
        "external_timeout_seconds": 5.0,
        "remote_api": False,
        "critical_asset_approval_recommended": True,
        "supported_target_types": {TargetType.IP_ADDRESS},
    }
    fields.update(overrides)
    return EnforcementAdapterCapabilities(**fields)


class FullAdapter:
    async def execute(self, plan, execution_id):
        return EnforcementResult(success=True, message="applied")

    async def rollback(self, plan, execution_id):
        return EnforcementResult(success=True, message="rolled back")

    async def verify(self, plan, execution_id):
        return EnforcementVerification(
            state=EnforcementVerificationState.PRESENT, message="present"
        )

    async def reconcile(self, plan, execution_id, *, expected_state):
        return EnforcementReconciliation(
            observed_state=expected_state,
            expected_state=expected_state,
            drifted=False,
            message="ok",
        )


class ExecuteOnlyAdapter:
    async def execute(self, plan, execution_id):
        return EnforcementResult(success=True, message="applied")

    async def rollback(self, plan, execution_id):
        return EnforcementResult(success=True, message="rolled back")


# --------------------------------------------------------------------------
# capability model validation
# --------------------------------------------------------------------------


def test_capabilities_require_at_least_one_supported_action() -> None:
    with pytest.raises(ValueError):
        base_capabilities(supported_actions=set())


def test_capabilities_require_at_least_one_target_type() -> None:
    with pytest.raises(ValueError):
        base_capabilities(supported_target_types=set())


def test_capabilities_reject_timeout_out_of_bounds() -> None:
    with pytest.raises(ValueError):
        base_capabilities(external_timeout_seconds=0)
    with pytest.raises(ValueError):
        base_capabilities(external_timeout_seconds=301)


def test_capabilities_reject_required_credential_without_ref_support() -> None:
    with pytest.raises(ValueError, match="credential_ref"):
        base_capabilities(
            credential_requirement=CredentialRequirement.REQUIRED,
            supports_credential_ref=False,
        )


def test_capabilities_allow_required_credential_with_ref_support() -> None:
    capabilities = base_capabilities(
        credential_requirement=CredentialRequirement.REQUIRED,
        supports_credential_ref=True,
    )
    assert capabilities.credential_requirement is CredentialRequirement.REQUIRED


# --------------------------------------------------------------------------
# registry capability lookup / registration validation
# --------------------------------------------------------------------------


def test_registry_returns_none_capabilities_when_nothing_registered() -> None:
    registry = EnforcementRegistry()
    assert registry.get_capabilities(EnforcementKind.FIREWALL, "acme") is None


def test_registry_capability_lookup_exact_then_generic() -> None:
    registry = EnforcementRegistry()
    generic_caps = base_capabilities()
    exact_caps = base_capabilities(supported_actions={ActionType.RATE_LIMIT})
    registry.register(EnforcementKind.FIREWALL, "*", FullAdapter(), capabilities=generic_caps)
    assert registry.get_capabilities(EnforcementKind.FIREWALL, "acme") == generic_caps

    registry.register(EnforcementKind.FIREWALL, "acme", FullAdapter(), capabilities=exact_caps)
    assert registry.get_capabilities(EnforcementKind.FIREWALL, "acme") == exact_caps
    assert registry.get_capabilities(EnforcementKind.FIREWALL, "other-vendor") == generic_caps


def test_registration_rejects_rollback_claim_without_rollback_method() -> None:
    class NoRollback:
        async def execute(self, plan, execution_id):
            return EnforcementResult(success=True, message="applied")

    registry = EnforcementRegistry()
    with pytest.raises(EnforcementError, match="rollback"):
        registry.register(
            EnforcementKind.FIREWALL,
            "broken",
            NoRollback(),
            capabilities=base_capabilities(supports_rollback=True),
        )


def test_registration_rejects_verify_claim_without_verify_method() -> None:
    registry = EnforcementRegistry()
    with pytest.raises(EnforcementError, match="verify"):
        registry.register(
            EnforcementKind.FIREWALL,
            "broken",
            ExecuteOnlyAdapter(),
            capabilities=base_capabilities(supports_verify=True, supports_reconcile=False),
        )


def test_registration_rejects_reconcile_claim_without_reconcile_method() -> None:
    registry = EnforcementRegistry()
    with pytest.raises(EnforcementError, match="reconcile"):
        registry.register(
            EnforcementKind.FIREWALL,
            "broken",
            ExecuteOnlyAdapter(),
            capabilities=base_capabilities(supports_verify=False, supports_reconcile=True),
        )


def test_registration_accepts_consistent_capability_declaration() -> None:
    registry = EnforcementRegistry()
    registry.register(
        EnforcementKind.FIREWALL,
        "consistent",
        FullAdapter(),
        capabilities=base_capabilities(),
    )
    assert registry.resolve(EnforcementKind.FIREWALL, "consistent") is not None


def test_registration_without_capabilities_infers_a_permissive_default() -> None:
    registry = EnforcementRegistry()
    registry.register(EnforcementKind.FIREWALL, "legacy", FullAdapter())
    inferred = registry.get_capabilities(EnforcementKind.FIREWALL, "legacy")
    assert inferred is not None
    assert ActionType.BLOCK_IP in inferred.supported_actions
    assert inferred.supports_verify is True
    assert inferred.supports_reconcile is True


# --------------------------------------------------------------------------
# configured-point vs adapter capability mismatch (response planning)
# --------------------------------------------------------------------------


def prepared_orchestrator(
    *, point_capabilities: set[ActionType], adapter_capabilities: EnforcementAdapterCapabilities
) -> tuple[ResponseOrchestrator, ResponseRequest]:
    store = InMemoryStore()
    store.add_asset(
        Asset(asset_id="host-1", tenant_id="t1", site_id="s1", display_name="Host")
    )
    store.add_incident(
        Incident(
            incident_id="inc-1",
            tenant_id="t1",
            site_id="s1",
            title="Incident",
            severity=Severity.HIGH,
            confidence=0.99,
            evidence=[
                EvidenceRef(
                    evidence_class=EvidenceClass.NETWORK_FLOW,
                    source="n",
                    summary="network",
                    confidence=0.9,
                ),
                EvidenceRef(
                    evidence_class=EvidenceClass.ENDPOINT,
                    source="e",
                    summary="endpoint",
                    confidence=0.9,
                ),
            ],
        )
    )
    store.add_enforcement_point(
        EnforcementPoint(
            enforcement_point_id="fw-1",
            tenant_id="t1",
            site_id="s1",
            kind=EnforcementKind.FIREWALL,
            vendor="capped",
            capabilities=point_capabilities,
        )
    )
    store.add_enforcement_binding(
        EnforcementBinding(
            tenant_id="t1",
            site_id="s1",
            asset_id="host-1",
            enforcement_point_id="fw-1",
            attributes={"blast_radius_estimate": "endpoint only"},
        )
    )
    registry = EnforcementRegistry()
    registry.register(
        EnforcementKind.FIREWALL, "capped", FullAdapter(), capabilities=adapter_capabilities
    )
    orchestrator = ResponseOrchestrator(store, registry)
    request = ResponseRequest(
        tenant_id="t1",
        site_id="s1",
        incident_id="inc-1",
        target=ResponseTarget(asset_id="host-1"),
        action=ActionType.RATE_LIMIT,
        ttl_seconds=300,
        reason="test",
    )
    return orchestrator, request


def test_plan_denies_when_point_claims_action_adapter_cannot_support() -> None:
    orchestrator, request = prepared_orchestrator(
        point_capabilities={ActionType.RATE_LIMIT},
        adapter_capabilities=base_capabilities(supported_actions={ActionType.BLOCK_IP}),
    )
    plan = orchestrator.plan(request)
    assert plan.decision.outcome is PolicyOutcome.DENY
    assert any("does not support" in reason for reason in plan.decision.reasons)


def test_plan_allows_when_point_and_adapter_capabilities_agree() -> None:
    orchestrator, request = prepared_orchestrator(
        point_capabilities={ActionType.RATE_LIMIT},
        adapter_capabilities=base_capabilities(supported_actions={ActionType.RATE_LIMIT}),
    )
    plan = orchestrator.plan(request)
    assert plan.decision.outcome is not PolicyOutcome.DENY


def test_reconciliation_model_reports_drift() -> None:
    reconciliation = EnforcementReconciliation(
        observed_state=EnforcementVerificationState.ABSENT,
        expected_state=EnforcementVerificationState.PRESENT,
        drifted=True,
        message="rule missing",
    )
    assert reconciliation.drifted is True
