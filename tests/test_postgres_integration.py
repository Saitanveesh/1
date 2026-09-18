import datetime as dt
import os
import uuid

import pytest

from mon.database import DatabaseStore
from mon.domain import SecurityEvent


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
