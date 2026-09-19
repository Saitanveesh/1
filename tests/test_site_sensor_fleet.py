import datetime as dt

import pytest

from mon.sensor_fleet_models import (
    SensorEnrollmentResult,
    SensorFleetState,
    SensorHeartbeat,
    SensorIdentityStatus,
    SensorRenewalRequest,
    SensorRenewalResult,
    SensorTrustIdentity,
    SensorTrustSnapshot,
)
from mon.site_controller import SiteController, SiteScopeViolation, SQLiteEventSpool
from mon.site_sensor_trust import SQLiteSensorTrustStore


class FakeSensorFleetClient:
    def __init__(self, snapshot: SensorTrustSnapshot) -> None:
        self.snapshot = snapshot
        self.heartbeats: list[SensorHeartbeat] = []
        self.renewals: list[SensorRenewalRequest] = []

    async def fetch_trust_snapshot(
        self,
        tenant_id: str,
        site_id: str,
    ) -> SensorTrustSnapshot:
        assert tenant_id == self.snapshot.tenant_id
        assert site_id == self.snapshot.site_id
        return self.snapshot

    async def submit_heartbeat(self, heartbeat: SensorHeartbeat) -> None:
        self.heartbeats.append(heartbeat)

    async def renew_sensor(
        self,
        request: SensorRenewalRequest,
    ) -> SensorRenewalResult:
        self.renewals.append(request)
        next_snapshot = SensorTrustSnapshot(
            tenant_id=request.tenant_id,
            site_id=request.site_id,
            generated_at=self.snapshot.generated_at + dt.timedelta(seconds=1),
            identities=[
                *self.snapshot.identities,
                SensorTrustIdentity(
                    sensor_id=request.sensor_id,
                    identity_id="identity-new",
                    fingerprint_sha256="b" * 64,
                    status=SensorIdentityStatus.ACTIVE,
                    expires_at=self.snapshot.generated_at
                    + dt.timedelta(days=30),
                ),
            ],
        )
        return SensorRenewalResult(
            certificate=SensorEnrollmentResult(
                identity_id="identity-new",
                tenant_id=request.tenant_id,
                site_id=request.site_id,
                sensor_id=request.sensor_id,
                certificate_pem="certificate",
                ca_certificate_pem="ca",
                fingerprint_sha256="b" * 64,
                spiffe_uri=(
                    "spiffe://mon.local/tenant/tenant-a/"
                    "site/site-a/sensor/sensor-1"
                ),
                expires_at=self.snapshot.generated_at
                + dt.timedelta(days=30),
            ),
            trust_snapshot=next_snapshot,
        )


def trust_snapshot(now: dt.datetime) -> SensorTrustSnapshot:
    return SensorTrustSnapshot(
        tenant_id="tenant-a",
        site_id="site-a",
        generated_at=now,
        identities=[
            SensorTrustIdentity(
                sensor_id="sensor-1",
                identity_id="identity-old",
                fingerprint_sha256="a" * 64,
                status=SensorIdentityStatus.ACTIVE,
                expires_at=now + dt.timedelta(days=30),
            )
        ],
    )


@pytest.mark.asyncio
async def test_site_controller_syncs_and_persists_sensor_trust(tmp_path) -> None:
    now = dt.datetime.now(dt.UTC)
    spool = SQLiteEventSpool(
        tmp_path / "spool.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    trust = SQLiteSensorTrustStore(
        tmp_path / "trust.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    client = FakeSensorFleetClient(trust_snapshot(now))
    controller = SiteController(
        "tenant-a",
        "site-a",
        spool,
        sensor_fleet_client=client,
        sensor_trust_store=trust,
    )
    try:
        result = await controller.sync_sensor_trust()
        assert result["state"] == "SYNCED"
        assert result["accepted_identities"] == 1
        assert (
            controller.authorize_sensor_identity(
                "sensor-1",
                "a" * 64,
                now=now + dt.timedelta(seconds=1),
            )
            is not None
        )
    finally:
        trust.close()
        spool.close()

    reopened = SQLiteSensorTrustStore(
        tmp_path / "trust.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    try:
        assert (
            reopened.authorize(
                "sensor-1",
                "a" * 64,
                now=now + dt.timedelta(seconds=1),
            )
            is not None
        )
    finally:
        reopened.close()


@pytest.mark.asyncio
async def test_site_controller_rejects_untrusted_sensor_heartbeat(tmp_path) -> None:
    now = dt.datetime.now(dt.UTC)
    spool = SQLiteEventSpool(
        tmp_path / "spool.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    trust = SQLiteSensorTrustStore(
        tmp_path / "trust.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    client = FakeSensorFleetClient(trust_snapshot(now))
    controller = SiteController(
        "tenant-a",
        "site-a",
        spool,
        sensor_fleet_client=client,
        sensor_trust_store=trust,
    )
    try:
        await controller.sync_sensor_trust()
        heartbeat = SensorHeartbeat(
            tenant_id="tenant-a",
            site_id="site-a",
            sensor_id="sensor-1",
            fingerprint_sha256="c" * 64,
            observed_at=now,
            state=SensorFleetState.READY,
            collector_kind="ZEEK",
        )
        with pytest.raises(SiteScopeViolation, match="not accepted"):
            await controller.relay_sensor_heartbeat(heartbeat)
        assert client.heartbeats == []
    finally:
        trust.close()
        spool.close()


@pytest.mark.asyncio
async def test_site_controller_relays_heartbeat_and_applies_renewed_trust(
    tmp_path,
) -> None:
    now = dt.datetime.now(dt.UTC)
    spool = SQLiteEventSpool(
        tmp_path / "spool.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    trust = SQLiteSensorTrustStore(
        tmp_path / "trust.db",
        tenant_id="tenant-a",
        site_id="site-a",
    )
    client = FakeSensorFleetClient(trust_snapshot(now))
    controller = SiteController(
        "tenant-a",
        "site-a",
        spool,
        sensor_fleet_client=client,
        sensor_trust_store=trust,
    )
    try:
        await controller.sync_sensor_trust()
        heartbeat = SensorHeartbeat(
            tenant_id="tenant-a",
            site_id="site-a",
            sensor_id="sensor-1",
            fingerprint_sha256="a" * 64,
            observed_at=now,
            state=SensorFleetState.READY,
            collector_kind="ZEEK",
        )
        await controller.relay_sensor_heartbeat(heartbeat)
        assert client.heartbeats == [heartbeat]

        renewal = SensorRenewalRequest(
            tenant_id="tenant-a",
            site_id="site-a",
            sensor_id="sensor-1",
            current_fingerprint_sha256="a" * 64,
            csr_pem="-----BEGIN CERTIFICATE REQUEST-----"
            + "x" * 80
            + "-----END CERTIFICATE REQUEST-----",
        )
        result = await controller.relay_sensor_renewal(renewal)
        assert result.certificate.fingerprint_sha256 == "b" * 64
        assert (
            controller.authorize_sensor_identity(
                "sensor-1",
                "b" * 64,
                now=now + dt.timedelta(seconds=2),
            )
            is not None
        )
    finally:
        trust.close()
        spool.close()
