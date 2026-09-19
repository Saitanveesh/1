import datetime as dt

import pytest

from mon.sensor_fleet_models import (
    SensorIdentityStatus,
    SensorTrustIdentity,
    SensorTrustSnapshot,
)
from mon.site_sensor_trust import SQLiteSensorTrustStore, SensorTrustStoreError


def snapshot(
    *,
    generated_at: dt.datetime,
    fingerprints: tuple[str, ...] = ("a" * 64,),
) -> SensorTrustSnapshot:
    return SensorTrustSnapshot(
        tenant_id="tenant-a",
        site_id="site-a",
        generated_at=generated_at,
        identities=[
            SensorTrustIdentity(
                sensor_id=f"sensor-{index}",
                identity_id=f"identity-{index}",
                fingerprint_sha256=fingerprint,
                status=SensorIdentityStatus.ACTIVE,
                expires_at=generated_at + dt.timedelta(days=30),
            )
            for index, fingerprint in enumerate(fingerprints, start=1)
        ],
    )


def test_sensor_trust_store_survives_restart_and_is_scope_bound(tmp_path) -> None:
    path = tmp_path / "sensor-trust.db"
    now = dt.datetime(2026, 9, 19, 5, 0, tzinfo=dt.UTC)
    first = SQLiteSensorTrustStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    first.replace(snapshot(generated_at=now), received_at=now)
    first.close()

    reopened = SQLiteSensorTrustStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        accepted = reopened.authorize(
            "sensor-1",
            "a" * 64,
            now=now + dt.timedelta(seconds=1),
        )
        assert accepted is not None
        assert reopened.diagnostics()["initialized"] is True
        assert reopened.diagnostics()["accepted_identities"] == 1
    finally:
        reopened.close()

    with pytest.raises(ValueError, match="site_id mismatch"):
        SQLiteSensorTrustStore(
            path,
            tenant_id="tenant-a",
            site_id="site-b",
        )


def test_sensor_trust_store_rejects_old_snapshot_and_revocation_replaces_allowset(
    tmp_path,
) -> None:
    path = tmp_path / "sensor-trust.db"
    now = dt.datetime(2026, 9, 19, 5, 0, tzinfo=dt.UTC)
    store = SQLiteSensorTrustStore(
        path,
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        store.replace(snapshot(generated_at=now))
        with pytest.raises(SensorTrustStoreError, match="older"):
            store.replace(
                snapshot(generated_at=now - dt.timedelta(seconds=1))
            )

        store.replace(
            SensorTrustSnapshot(
                tenant_id="tenant-a",
                site_id="site-a",
                generated_at=now + dt.timedelta(seconds=1),
                identities=[],
            )
        )
        assert (
            store.authorize(
                "sensor-1",
                "a" * 64,
                now=now + dt.timedelta(seconds=2),
            )
            is None
        )
    finally:
        store.close()


def test_retiring_identity_is_accepted_only_until_overlap_deadline(tmp_path) -> None:
    now = dt.datetime(2026, 9, 19, 5, 0, tzinfo=dt.UTC)
    store = SQLiteSensorTrustStore(
        tmp_path / "sensor-trust.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        store.replace(
            SensorTrustSnapshot(
                tenant_id="tenant-a",
                site_id="site-a",
                generated_at=now,
                identities=[
                    SensorTrustIdentity(
                        sensor_id="sensor-1",
                        identity_id="identity-old",
                        fingerprint_sha256="b" * 64,
                        status=SensorIdentityStatus.RETIRING,
                        expires_at=now + dt.timedelta(days=1),
                        accept_until=now + dt.timedelta(hours=1),
                    )
                ],
            )
        )
        assert (
            store.authorize(
                "sensor-1",
                "b" * 64,
                now=now + dt.timedelta(minutes=59),
            )
            is not None
        )
        assert (
            store.authorize(
                "sensor-1",
                "b" * 64,
                now=now + dt.timedelta(hours=1),
            )
            is None
        )
    finally:
        store.close()


def test_trust_snapshot_scope_mismatch_fails_closed(tmp_path) -> None:
    now = dt.datetime(2026, 9, 19, 5, 0, tzinfo=dt.UTC)
    store = SQLiteSensorTrustStore(
        tmp_path / "sensor-trust.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        with pytest.raises(SensorTrustStoreError, match="scope"):
            store.replace(
                SensorTrustSnapshot(
                    tenant_id="tenant-a",
                    site_id="site-b",
                    generated_at=now,
                    identities=[],
                )
            )
        assert store.snapshot() is None
    finally:
        store.close()
