import datetime as dt
import os
import uuid

import pytest

from mon.database import DatabaseStore
from mon.domain import SecurityEvent
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
