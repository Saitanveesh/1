import datetime as dt
import os
import uuid

import pytest

from mon.database import DatabaseStore
from mon.domain import SecurityEvent
from mon.event_fabric import FabricReceiptStatus, security_event_envelope
from mon.fabric_ingress import ingest_fabric_envelope
from mon.pipeline import PipelinePersistenceMode, SecurityPipeline
from mon.sensor_fleet_models import (
    SensorEnrollmentTokenRecord,
    SensorFleetState,
    SensorHeartbeat,
    SensorIdentityRecord,
    SensorRecord,
)
from mon.site_identity_models import EnrollmentTokenRecord


@pytest.mark.skipif(
    not os.environ.get("MON_TEST_DATABASE_URL"),
    reason="PostgreSQL integration URL is not configured",
)
def test_postgres_store_survives_new_repository_instance() -> None:
    url = os.environ["MON_TEST_DATABASE_URL"]
    event_id = f"ci-{uuid.uuid4()}"
    event = SecurityEvent(
        event_id=event_id,
        tenant_id="ci-tenant",
        site_id="ci-site",
        sensor_id="ci-sensor",
        observed_at=dt.datetime.now(dt.UTC),
        category="integration.test",
    )

    first = DatabaseStore(url)
    first.add_event(event)
    first.close()

    second = DatabaseStore(url)
    assert second.event_exists("ci-tenant", "ci-site", event_id)
    assert not second.event_exists("other-tenant", "ci-site", event_id)
    second.close()



@pytest.mark.skipif(
    not os.environ.get("MON_TEST_DATABASE_URL"),
    reason="PostgreSQL integration URL is not configured",
)
def test_postgres_enrollment_token_is_consumed_once() -> None:
    url = os.environ["MON_TEST_DATABASE_URL"]
    token_hash = uuid.uuid4().hex + uuid.uuid4().hex
    now = dt.datetime.now(dt.UTC)
    store = DatabaseStore(url)
    store.add_enrollment_token(
        EnrollmentTokenRecord(
            token_hash=token_hash,
            tenant_id="ci-tenant",
            site_id="ci-site",
            created_by="ci",
            created_at=now,
            expires_at=now + dt.timedelta(minutes=5),
        )
    )

    first = store.consume_enrollment_token(token_hash, now)
    second = store.consume_enrollment_token(
        token_hash,
        now + dt.timedelta(seconds=1),
    )

    assert first is not None
    assert first.used_at is not None
    assert second is None
    store.close()


@pytest.mark.skipif(
    not os.environ.get("MON_TEST_DATABASE_URL"),
    reason="PostgreSQL integration URL is not configured",
)
def test_postgres_site_command_record_persists() -> None:
    from mon.domain import (
        ActionType,
        EnforcementKind,
        EnforcementPoint,
        PolicyDecision,
        PolicyOutcome,
        ResponsePlan,
        ResponseRequest,
        ResponseTarget,
    )
    from mon.site_command_models import SiteCommand, SiteCommandKind, SiteCommandRecord

    url = os.environ["MON_TEST_DATABASE_URL"]
    now = dt.datetime.now(dt.UTC)
    command_id = f"ci-command-{uuid.uuid4()}"
    request = ResponseRequest(
        request_id=f"ci-response-{uuid.uuid4()}",
        tenant_id="ci-tenant",
        site_id="ci-site",
        incident_id="ci-incident",
        target=ResponseTarget(ip_address="198.51.100.8"),
        action=ActionType.BLOCK_IP,
        enforcement_point_id="ci-fw",
        ttl_seconds=60,
        reason="ci",
    )
    point = EnforcementPoint(
        enforcement_point_id="ci-fw",
        tenant_id="ci-tenant",
        site_id="ci-site",
        kind=EnforcementKind.FIREWALL,
        vendor="ci",
        capabilities={ActionType.BLOCK_IP},
    )
    record = SiteCommandRecord(
        command=SiteCommand(
            command_id=command_id,
            tenant_id="ci-tenant",
            site_id="ci-site",
            kind=SiteCommandKind.APPLY_RESPONSE,
            created_at=now,
            not_after=now + dt.timedelta(minutes=5),
            response_plan=ResponsePlan(
                request=request,
                decision=PolicyDecision(
                    outcome=PolicyOutcome.ALLOW,
                    reasons=["ci"],
                ),
                enforcement_point=point,
            ),
        )
    )
    first = DatabaseStore(url)
    first.add_site_command(record)
    first.close()

    second = DatabaseStore(url)
    restored = second.get_site_command("ci-tenant", "ci-site", command_id)
    assert restored == record
    assert second.get_site_command("other", "ci-site", command_id) is None
    second.close()


@pytest.mark.skipif(
    not os.environ.get("MON_TEST_DATABASE_URL"),
    reason="PostgreSQL integration URL is not configured",
)
def test_postgres_sensor_fleet_lifecycle_persists_and_is_scoped() -> None:
    url = os.environ["MON_TEST_DATABASE_URL"]
    now = dt.datetime.now(dt.UTC)
    token_hash = uuid.uuid4().hex + uuid.uuid4().hex
    identity_id = str(uuid.uuid4())
    sensor_id = f"ci-sensor-{uuid.uuid4()}"
    token = SensorEnrollmentTokenRecord(
        token_hash=token_hash,
        tenant_id="ci-tenant",
        site_id="ci-site",
        sensor_id=sensor_id,
        created_by="ci",
        created_at=now,
        expires_at=now + dt.timedelta(minutes=5),
    )
    identity = SensorIdentityRecord(
        identity_id=identity_id,
        tenant_id="ci-tenant",
        site_id="ci-site",
        sensor_id=sensor_id,
        certificate_serial="12345",
        fingerprint_sha256=uuid.uuid4().hex + uuid.uuid4().hex,
        spiffe_uri=(
            f"spiffe://mon.local/tenant/ci-tenant/site/ci-site/"
            f"sensor/{sensor_id}"
        ),
        certificate_pem=(
            "-----BEGIN CERTIFICATE-----\n"
            + "A" * 80
            + "\n-----END CERTIFICATE-----\n"
        ),
        issued_at=now,
        expires_at=now + dt.timedelta(days=30),
    )
    sensor = SensorRecord(
        tenant_id="ci-tenant",
        site_id="ci-site",
        sensor_id=sensor_id,
        created_at=now,
        updated_at=now,
        current_identity_id=identity_id,
    )

    first = DatabaseStore(url)
    first.add_sensor_enrollment_token(token)
    assert first.complete_sensor_enrollment(
        token_hash,
        now,
        sensor,
        identity,
    )
    heartbeat = SensorHeartbeat(
        tenant_id="ci-tenant",
        site_id="ci-site",
        sensor_id=sensor_id,
        fingerprint_sha256=identity.fingerprint_sha256,
        observed_at=now + dt.timedelta(seconds=1),
        state=SensorFleetState.READY,
        collector_kind="CI",
    )
    assert first.record_sensor_heartbeat(
        heartbeat,
        now + dt.timedelta(seconds=2),
    ) is not None
    first.close()

    second = DatabaseStore(url)
    restored = second.get_sensor_record(
        "ci-tenant",
        "ci-site",
        sensor_id,
    )
    assert restored is not None
    assert restored.last_seen_at == now + dt.timedelta(seconds=2)
    assert (
        second.get_sensor_identity_by_fingerprint(
            "ci-tenant",
            "ci-site",
            identity.fingerprint_sha256,
        )
        is not None
    )
    assert (
        second.get_sensor_record("other-tenant", "ci-site", sensor_id)
        is None
    )
    revoked = second.revoke_sensor_lifecycle(
        "ci-tenant",
        "ci-site",
        sensor_id,
        actor_id="ci",
        reason="integration cleanup",
        now=now + dt.timedelta(seconds=3),
    )
    assert revoked is not None
    assert revoked.revoked_at is not None
    assert (
        second.record_sensor_heartbeat(
            heartbeat,
            now + dt.timedelta(seconds=4),
        )
        is None
    )
    second.close()


@pytest.mark.skipif(
    not os.environ.get("MON_TEST_DATABASE_URL"),
    reason="PostgreSQL integration URL is not configured",
)
def test_postgres_pipeline_commits_event_and_processing_receipt_atomically() -> None:
    url = os.environ["MON_TEST_DATABASE_URL"]
    event_id = f"ci-processed-{uuid.uuid4()}"
    item = SecurityEvent(
        event_id=event_id,
        tenant_id="ci-tenant",
        site_id="ci-site",
        sensor_id="ci-sensor",
        observed_at=dt.datetime.now(dt.UTC),
        category="integration.fabric",
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        protocol="tcp",
    )

    first = DatabaseStore(url)
    pipeline = SecurityPipeline(
        store=first,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )
    result = pipeline.process_event(item)
    assert result.duplicate is False
    assert first.event_processed("ci-tenant", "ci-site", event_id)
    first.close()

    second = DatabaseStore(url)
    try:
        assert second.get_event("ci-tenant", "ci-site", event_id) == item
        assert second.event_processed("ci-tenant", "ci-site", event_id)
        assert second.list_unprocessed_events("ci-tenant", "ci-site") == []
    finally:
        second.close()


@pytest.mark.skipif(
    not os.environ.get("MON_TEST_DATABASE_URL"),
    reason="PostgreSQL integration URL is not configured",
)
def test_postgres_fabric_receipt_survives_restart_and_deduplicates() -> None:
    url = os.environ["MON_TEST_DATABASE_URL"]
    event_id = f"ci-fabric-{uuid.uuid4()}"
    observed_at = dt.datetime.now(dt.UTC)
    item = SecurityEvent(
        event_id=event_id,
        tenant_id="ci-tenant",
        site_id="ci-site",
        sensor_id="ci-sensor",
        observed_at=observed_at,
        category="integration.fabric",
    )
    envelope = security_event_envelope(
        item,
        produced_at=observed_at + dt.timedelta(milliseconds=1),
    )

    first = DatabaseStore(url)
    pipeline = SecurityPipeline(
        store=first,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )
    ingested = ingest_fabric_envelope(first, pipeline, envelope)
    assert ingested.acknowledgement.duplicate is False
    first.close()

    second = DatabaseStore(url)
    second_pipeline = SecurityPipeline(
        store=second,
        persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
    )
    try:
        receipt = second.get_fabric_receipt(
            "ci-tenant",
            "ci-site",
            event_id,
        )
        assert receipt is not None
        assert receipt.status is FabricReceiptStatus.PROCESSED
        assert receipt.envelope_sha256 == envelope.canonical_sha256

        duplicate = ingest_fabric_envelope(
            second,
            second_pipeline,
            envelope,
        )
        assert duplicate.acknowledgement.duplicate is True
        assert duplicate.processing_result is None
    finally:
        second.close()
