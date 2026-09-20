from __future__ import annotations

import datetime as dt
import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from mon.domain import (
    ActionType,
    AuditRecord,
    EnforcementKind,
    EnforcementPoint,
    EnforcementResult,
    PolicyDecision,
    PolicyOutcome,
    ResponseExecution,
    ResponseExecutionStatus,
    ResponsePlan,
    ResponseRequest,
    ResponseTarget,
    SecurityEvent,
)
from mon.sensor_fleet_models import SensorIdentityStatus, SensorTrustIdentity, SensorTrustSnapshot
from mon.site_command_models import SiteCommandResult
from mon.site_response_models import SiteResponseUpdate, SiteResponseUpdateKind
from mon.site_service import SiteServiceConfig, build_site_service_resources
from mon.site_state_snapshot import (
    DATABASE_FILENAMES,
    SiteStateSnapshotError,
    create_site_state_snapshot,
    restore_site_state_snapshot,
    verify_site_state_snapshot,
)

TENANT = "t1"
SITE = "s1"


def _response_plan(*, tenant_id: str = TENANT, site_id: str = SITE) -> ResponsePlan:
    request = ResponseRequest(
        request_id="exec-1",
        tenant_id=tenant_id,
        site_id=site_id,
        incident_id="inc-1",
        target=ResponseTarget(ip_address="198.51.100.9"),
        action=ActionType.BLOCK_IP,
        ttl_seconds=300,
        reason="snapshot test",
    )
    point = EnforcementPoint(
        enforcement_point_id="fw-1",
        tenant_id=tenant_id,
        site_id=site_id,
        kind=EnforcementKind.FIREWALL,
        vendor="test",
        capabilities={ActionType.BLOCK_IP},
    )
    return ResponsePlan(
        request=request,
        decision=PolicyDecision(outcome=PolicyOutcome.ALLOW, reasons=["test"]),
        enforcement_point=point,
    )


def _response_execution(*, tenant_id: str = TENANT, site_id: str = SITE) -> ResponseExecution:
    return ResponseExecution(
        execution_id="exec-1",
        tenant_id=tenant_id,
        site_id=site_id,
        plan=_response_plan(tenant_id=tenant_id, site_id=site_id),
        status=ResponseExecutionStatus.APPLIED,
        result=EnforcementResult(success=True, message="applied"),
        expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(seconds=300),
    )


def _verify_present_audit(*, tenant_id: str = TENANT, site_id: str = SITE) -> AuditRecord:
    return AuditRecord(
        tenant_id=tenant_id,
        site_id=site_id,
        actor_id="mon-site-reconciliation",
        category="RESPONSE",
        object_type="response_execution",
        object_id="exec-1",
        action="VERIFY",
        outcome="PRESENT",
    )


def seed_state_dir(
    root: Path, *, tenant_id: str = TENANT, site_id: str = SITE
) -> Path:
    """Build a real Site Controller state directory (all seven durable
    databases created through build_site_service_resources) with
    representative durable data in each, plus arbitrary/secret-looking
    files that a snapshot must never archive.
    """
    state_dir = root / "state"
    config = SiteServiceConfig(tenant_id=tenant_id, site_id=site_id, state_dir=state_dir)
    resources = build_site_service_resources(config)
    try:
        event = SecurityEvent(
            tenant_id=tenant_id,
            site_id=site_id,
            sensor_id="sensor-1",
            category="endpoint.process.start",
        )
        resources.event_spool.enqueue(event)
        resources.fabric_outbox.enqueue_security_event(event)
        resources.analysis_store.add_event(event)
        execution = _response_execution(tenant_id=tenant_id, site_id=site_id)
        resources.response_store.add_response_execution(execution)
        resources.response_store.add_audit_record(
            AuditRecord(
                tenant_id=tenant_id,
                site_id=site_id,
                actor_id="tester",
                category="RESPONSE",
                object_type="response_execution",
                object_id="exec-1",
                action="EXECUTE",
                outcome="APPLIED",
            )
        )
        resources.command_result_outbox.enqueue(
            SiteCommandResult(
                command_id="cmd-1",
                tenant_id=tenant_id,
                site_id=site_id,
                success=True,
                execution=execution,
            )
        )
        resources.response_update_outbox.enqueue(
            SiteResponseUpdate(
                update_id="upd-1",
                kind=SiteResponseUpdateKind.EXECUTION_RECONCILIATION,
                command_id="cmd-1",
                tenant_id=tenant_id,
                site_id=site_id,
                execution=execution,
                audit_records=[_verify_present_audit(tenant_id=tenant_id, site_id=site_id)],
            )
        )
        resources.sensor_trust_store.replace(
            SensorTrustSnapshot(
                tenant_id=tenant_id,
                site_id=site_id,
                generated_at=dt.datetime.now(dt.UTC),
                identities=[
                    SensorTrustIdentity(
                        sensor_id="sensor-1",
                        identity_id="identity-1",
                        fingerprint_sha256="a" * 64,
                        status=SensorIdentityStatus.ACTIVE,
                        expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=1),
                    )
                ],
            )
        )
    finally:
        resources.close()

    # Arbitrary and secret-looking files a snapshot must never archive.
    (state_dir / "notes.txt").write_text("operator scratch notes", encoding="utf-8")
    (state_dir / "private-key.pem").write_text("-----BEGIN PRIVATE KEY-----", encoding="utf-8")
    (state_dir / "bearer-token.txt").write_text("secret-bearer-token-value", encoding="utf-8")
    credentials_dir = state_dir / "credentials"
    credentials_dir.mkdir(parents=True, exist_ok=True)
    (credentials_dir / "vault.key").write_text("vault-key-material", encoding="utf-8")

    return state_dir


# --------------------------------------------------------------------------
# snapshot creation / seven-database scope
# --------------------------------------------------------------------------


def test_valid_snapshot_creates_archive_with_manifest(tmp_path) -> None:
    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    assert archive.is_file()
    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())
    assert names == {"manifest.json", *DATABASE_FILENAMES}


def test_snapshot_excludes_arbitrary_and_secret_looking_files(tmp_path) -> None:
    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())
    assert "notes.txt" not in names
    assert "private-key.pem" not in names
    assert "bearer-token.txt" not in names
    assert not any("credentials" in name or "vault" in name for name in names)

    raw = archive.read_bytes()
    assert b"secret-bearer-token-value" not in raw
    assert b"vault-key-material" not in raw
    assert b"BEGIN PRIVATE KEY" not in raw


def test_snapshot_manifest_lists_all_seven_expected_databases(tmp_path) -> None:
    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    manifest = verify_site_state_snapshot(archive)
    assert {entry.filename for entry in manifest.databases} == set(DATABASE_FILENAMES)
    assert len(manifest.databases) == 7
    for entry in manifest.databases:
        assert entry.size_bytes > 0
        assert len(entry.sha256) == 64


def test_snapshot_rejects_missing_database(tmp_path) -> None:
    state_dir = seed_state_dir(tmp_path)
    (state_dir / "sensor-trust.db").unlink()
    with pytest.raises(SiteStateSnapshotError, match="missing expected durable database"):
        create_site_state_snapshot(
            state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
        )


def test_partial_snapshot_failure_does_not_produce_valid_artifact(tmp_path, monkeypatch) -> None:
    state_dir = seed_state_dir(tmp_path)
    output = tmp_path / "snap.zip"

    import mon.site_state_snapshot as snapshot_module

    calls = {"count": 0}
    original = snapshot_module._backup_database

    def flaky_backup(source_path: Path, dest_path: Path) -> None:
        calls["count"] += 1
        if calls["count"] >= 3:
            raise RuntimeError("simulated backup failure")
        original(source_path, dest_path)

    monkeypatch.setattr(snapshot_module, "_backup_database", flaky_backup)
    with pytest.raises(RuntimeError, match="simulated backup failure"):
        create_site_state_snapshot(state_dir, output, tenant_id=TENANT, site_id=SITE)

    assert not output.exists()
    leftovers = list(tmp_path.glob(".snap.zip.part-*"))
    assert leftovers == []
    work_dirs = list(tmp_path.glob(".mon-site-snapshot-*"))
    assert work_dirs == []


# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------


def test_verify_valid_snapshot_succeeds(tmp_path) -> None:
    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    manifest = verify_site_state_snapshot(
        archive, expected_tenant_id=TENANT, expected_site_id=SITE
    )
    assert manifest.tenant_id == TENANT
    assert manifest.site_id == SITE


def test_verify_zip_extraction_success_alone_is_not_sufficient(tmp_path) -> None:
    """A structurally valid zip whose manifest disagrees with database
    content must still fail -- opening it successfully is not verification.
    """
    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    _corrupt_member_bytes(archive, "sensor-trust.db", lambda data: data + b"\x00" * 16)
    with pytest.raises(SiteStateSnapshotError):
        verify_site_state_snapshot(archive)


def test_verify_rejects_unexpected_archive_member(tmp_path) -> None:
    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(archive) as src, zipfile.ZipFile(
        tampered, "w", zipfile.ZIP_DEFLATED
    ) as dst:
        for name in src.namelist():
            dst.writestr(name, src.read(name))
        dst.writestr("extra-file.txt", "not part of the contract")
    with pytest.raises(SiteStateSnapshotError, match="unexpected member"):
        verify_site_state_snapshot(tampered)


def test_verify_rejects_checksum_corruption(tmp_path) -> None:
    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    _corrupt_member_bytes(archive, "response-state.db", lambda data: data[:-8] + b"\xff" * 8)
    with pytest.raises(SiteStateSnapshotError, match="checksum mismatch|size mismatch"):
        verify_site_state_snapshot(archive)


def test_verify_rejects_corrupt_sqlite_even_with_matching_checksum(tmp_path) -> None:
    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    corrupted = b"not a sqlite database at all, just garbage bytes" * 4
    _replace_member_and_manifest(archive, "command-results.db", corrupted)
    with pytest.raises(SiteStateSnapshotError, match="integrity check|not a database"):
        verify_site_state_snapshot(archive)


def _corrupt_member_bytes(archive: Path, member: str, mutate) -> None:
    with zipfile.ZipFile(archive) as zf:
        original = zf.read(member)
    mutated = mutate(original)
    _rewrite_member(archive, member, mutated)


def _replace_member_and_manifest(archive: Path, member: str, new_bytes: bytes) -> None:
    """Replace one database member's bytes and update its manifest entry to
    match (correct sha256/size), so a subsequent failure is attributable to
    something other than a checksum mismatch (e.g. corrupt SQLite content).
    """
    with zipfile.ZipFile(archive) as zf:
        manifest_payload = json.loads(zf.read("manifest.json").decode("utf-8"))

    for entry in manifest_payload["databases"]:
        if entry["filename"] == member:
            entry["sha256"] = hashlib.sha256(new_bytes).hexdigest()
            entry["size_bytes"] = len(new_bytes)

    tmp_archive = archive.with_suffix(".rewrite.zip")
    with zipfile.ZipFile(archive) as src, zipfile.ZipFile(
        tmp_archive, "w", zipfile.ZIP_DEFLATED
    ) as dst:
        for name in src.namelist():
            if name == member:
                dst.writestr(name, new_bytes)
            elif name == "manifest.json":
                dst.writestr(name, json.dumps(manifest_payload))
            else:
                dst.writestr(name, src.read(name))
    tmp_archive.replace(archive)


def _rewrite_member(archive: Path, member: str, new_bytes: bytes) -> None:
    tmp_archive = archive.with_suffix(".rewrite.zip")
    with zipfile.ZipFile(archive) as src, zipfile.ZipFile(
        tmp_archive, "w", zipfile.ZIP_DEFLATED
    ) as dst:
        for name in src.namelist():
            payload = new_bytes if name == member else src.read(name)
            dst.writestr(name, payload)
    tmp_archive.replace(archive)


# --------------------------------------------------------------------------
# restore
# --------------------------------------------------------------------------


def test_restore_to_new_destination_and_durable_state_survives(tmp_path) -> None:
    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    destination = tmp_path / "restored"
    manifest, diagnostics = restore_site_state_snapshot(
        archive, destination, tenant_id=TENANT, site_id=SITE
    )
    assert manifest.tenant_id == TENANT
    for name in DATABASE_FILENAMES:
        assert (destination / name).is_file()
        assert name in diagnostics


def test_restored_event_spool_and_fabric_outbox_records_survive(tmp_path) -> None:
    from mon.event_fabric_outbox import DurableFabricOutbox
    from mon.site_controller import SQLiteEventSpool

    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    destination = tmp_path / "restored"
    restore_site_state_snapshot(archive, destination, tenant_id=TENANT, site_id=SITE)

    spool = SQLiteEventSpool(
        destination / "event-spool.db", tenant_id=TENANT, site_id=SITE
    )
    try:
        assert spool.count() == 1
    finally:
        spool.close()

    outbox = DurableFabricOutbox(
        destination / "fabric-outbox.db", tenant_id=TENANT, site_id=SITE
    )
    try:
        assert outbox.diagnostics()["total"] == 1
    finally:
        outbox.close()


def test_restored_analysis_state_survives(tmp_path) -> None:
    from mon.site_analysis_store import SQLiteSiteAnalysisStore

    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    destination = tmp_path / "restored"
    restore_site_state_snapshot(archive, destination, tenant_id=TENANT, site_id=SITE)

    store = SQLiteSiteAnalysisStore(
        destination / "analysis-state.db", tenant_id=TENANT, site_id=SITE
    )
    try:
        events = store.list_events(TENANT, SITE)
        assert len(events) == 1
    finally:
        store.close()


def test_restored_response_state_survives(tmp_path) -> None:
    from mon.site_response_store import SQLiteSiteResponseStore

    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    destination = tmp_path / "restored"
    restore_site_state_snapshot(archive, destination, tenant_id=TENANT, site_id=SITE)

    store = SQLiteSiteResponseStore(
        destination / "response-state.db", tenant_id=TENANT, site_id=SITE
    )
    try:
        executions = store.list_response_executions(TENANT, SITE)
        assert len(executions) == 1
        assert executions[0].execution_id == "exec-1"
        audit = store.list_audit_records(TENANT, SITE)
        assert len(audit) == 1
    finally:
        store.close()


def test_restored_command_and_response_update_outbox_records_survive(tmp_path) -> None:
    from mon.site_command_outbox import SQLiteCommandResultOutbox
    from mon.site_response_outbox import SQLiteResponseUpdateOutbox

    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    destination = tmp_path / "restored"
    restore_site_state_snapshot(archive, destination, tenant_id=TENANT, site_id=SITE)

    command_outbox = SQLiteCommandResultOutbox(
        destination / "command-results.db", tenant_id=TENANT, site_id=SITE
    )
    try:
        assert command_outbox.get("cmd-1") is not None
    finally:
        command_outbox.close()

    response_outbox = SQLiteResponseUpdateOutbox(
        destination / "response-updates.db", tenant_id=TENANT, site_id=SITE
    )
    try:
        assert response_outbox.get("upd-1") is not None
    finally:
        response_outbox.close()


def test_restored_sensor_trust_state_survives(tmp_path) -> None:
    from mon.site_sensor_trust import SQLiteSensorTrustStore

    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    destination = tmp_path / "restored"
    restore_site_state_snapshot(archive, destination, tenant_id=TENANT, site_id=SITE)

    store = SQLiteSensorTrustStore(
        destination / "sensor-trust.db", tenant_id=TENANT, site_id=SITE
    )
    try:
        snapshot = store.snapshot()
        assert snapshot is not None
        assert len(snapshot.identities) == 1
        assert snapshot.identities[0].sensor_id == "sensor-1"
    finally:
        store.close()


def test_restore_rejects_tenant_mismatch(tmp_path) -> None:
    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    with pytest.raises(SiteStateSnapshotError, match="tenant_id"):
        restore_site_state_snapshot(
            archive, tmp_path / "restored", tenant_id="other-tenant", site_id=SITE
        )


def test_restore_rejects_site_mismatch(tmp_path) -> None:
    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    with pytest.raises(SiteStateSnapshotError, match="site_id"):
        restore_site_state_snapshot(
            archive, tmp_path / "restored", tenant_id=TENANT, site_id="other-site"
        )


def test_restore_rejects_existing_nonempty_destination(tmp_path) -> None:
    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    destination = tmp_path / "restored"
    destination.mkdir()
    (destination / "pre-existing.txt").write_text("do not overwrite me", encoding="utf-8")
    with pytest.raises(SiteStateSnapshotError, match="not empty"):
        restore_site_state_snapshot(archive, destination, tenant_id=TENANT, site_id=SITE)
    assert (destination / "pre-existing.txt").is_file()


def test_restore_allows_empty_existing_destination(tmp_path) -> None:
    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    destination = tmp_path / "restored"
    destination.mkdir()
    manifest, _diagnostics = restore_site_state_snapshot(
        archive, destination, tenant_id=TENANT, site_id=SITE
    )
    assert manifest.tenant_id == TENANT


def test_restore_rejects_missing_database_in_archive(tmp_path) -> None:
    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(archive) as src, zipfile.ZipFile(
        tampered, "w", zipfile.ZIP_DEFLATED
    ) as dst:
        for name in src.namelist():
            if name == "sensor-trust.db":
                continue
            dst.writestr(name, src.read(name))
    with pytest.raises(SiteStateSnapshotError, match="missing expected member"):
        restore_site_state_snapshot(
            tampered, tmp_path / "restored", tenant_id=TENANT, site_id=SITE
        )
    assert not (tmp_path / "restored").exists()


def test_restore_rejects_corrupt_sqlite(tmp_path) -> None:
    state_dir = seed_state_dir(tmp_path)
    archive = create_site_state_snapshot(
        state_dir, tmp_path / "snap.zip", tenant_id=TENANT, site_id=SITE
    )
    _replace_member_and_manifest(archive, "event-spool.db", b"garbage, not a database" * 8)
    with pytest.raises(SiteStateSnapshotError):
        restore_site_state_snapshot(
            archive, tmp_path / "restored", tenant_id=TENANT, site_id=SITE
        )
    assert not (tmp_path / "restored").exists()


# --------------------------------------------------------------------------
# archive/path safety
# --------------------------------------------------------------------------


def test_verify_rejects_path_traversal_member(tmp_path) -> None:
    archive = tmp_path / "malicious.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../evil.db", "not a real database")
        zf.writestr("manifest.json", "{}")
    with pytest.raises(SiteStateSnapshotError):
        verify_site_state_snapshot(archive)


def test_verify_rejects_duplicate_member_names(tmp_path) -> None:
    archive = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("manifest.json", "{}")
        zf.writestr("manifest.json", "{}")
    with pytest.raises(SiteStateSnapshotError, match="duplicate"):
        verify_site_state_snapshot(archive)


def test_verify_rejects_non_zip_file(tmp_path) -> None:
    fake = tmp_path / "not-a-zip.zip"
    fake.write_bytes(b"this is not a zip archive")
    with pytest.raises(SiteStateSnapshotError, match="not a valid zip"):
        verify_site_state_snapshot(fake)


def test_verify_rejects_missing_manifest(tmp_path) -> None:
    archive = tmp_path / "no-manifest.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("event-spool.db", "placeholder")
    with pytest.raises(SiteStateSnapshotError, match="manifest"):
        verify_site_state_snapshot(archive)
