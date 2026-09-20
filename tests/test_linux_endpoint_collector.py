from __future__ import annotations

import asyncio
import datetime as dt

import pytest

from mon.domain import SecurityEvent
from mon.endpoint import normalize_endpoint_event
from mon.linux_endpoint_collector import (
    AuditProcessSource,
    InMemoryAuditLogReader,
    InMemoryJournalReader,
    JournalAuthSource,
    LinuxCollectorCheckpointError,
    LinuxCollectorCheckpointStore,
    LinuxCollectorState,
    LinuxEndpointCollector,
    LinuxEndpointCollectorError,
    LinuxSourceKind,
    LinuxSourcePermissionDenied,
    LinuxSourceUnavailable,
    SQLiteLinuxEventBuffer,
    deterministic_audit_event_id,
    deterministic_journal_event_id,
    group_audit_lines,
    normalize_linux_audit_execve,
    normalize_linux_journal_event,
    parse_audit_line,
    parse_journal_entry,
)

TENANT = "tenant-a"
SITE = "site-a"
SENSOR = "linux-sensor-1"
HOSTNAME = "web-01"


def journal_entry(
    *,
    cursor: str = "s=abc123;i=1;b=boot1;m=100;t=200;x=1",
    realtime_us: int = 1_790_000_000_000_000,
    syslog_identifier: str = "sshd",
    message: str,
    pid: str = "4242",
    hostname: str = HOSTNAME,
    boot_id: str = "boot-1",
) -> dict[str, str]:
    return {
        "__CURSOR": cursor,
        "__REALTIME_TIMESTAMP": str(realtime_us),
        "_BOOT_ID": boot_id,
        "_HOSTNAME": hostname,
        "_PID": pid,
        "SYSLOG_IDENTIFIER": syslog_identifier,
        "MESSAGE": message,
    }


def audit_group(
    *,
    timestamp: str = "1700000000.123",
    serial: str = "500",
    pid: str = "1234",
    ppid: str = "1",
    auid: str = "1000",
    uid: str = "0",
    comm: str = "bash",
    exe: str = "/usr/bin/bash",
    success: str = "yes",
    argv: list[str] | None = None,
    include_execve: bool = True,
) -> list[str]:
    header = f"msg=audit({timestamp}:{serial}):"
    syscall = (
        f'type=SYSCALL {header} arch=c000003e syscall=59 success={success} exit=0 '
        f'a0=1 a1=2 a2=3 a3=4 items=1 ppid={ppid} pid={pid} auid={auid} uid={uid} '
        f'gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 '
        f'comm="{comm}" exe="{exe}" subj=unconfined key=(null)'
    )
    lines = [syscall]
    if include_execve:
        argv = argv if argv is not None else ["ls", "-la"]
        argv_fields = " ".join(f'a{i}="{value}"' for i, value in enumerate(argv))
        lines.append(f'type=EXECVE {header} argc={len(argv)} {argv_fields}')
    lines.append(f"type=EOE {header}")
    return lines


class FakeSender:
    def __init__(self) -> None:
        self.sent: list[SecurityEvent] = []
        self.fail = False

    async def send(self, event: SecurityEvent) -> None:
        if self.fail:
            raise RuntimeError("sender unavailable")
        self.sent.append(event)


# --------------------------------------------------------------------------
# journal / auth normalization
# --------------------------------------------------------------------------


def test_auth_success_normalization_from_sshd_journal_message() -> None:
    record = parse_journal_entry(
        journal_entry(message="Accepted password for alice from 10.0.0.5 port 22 ssh2")
    )
    item = normalize_linux_journal_event(
        record, tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    assert item is not None
    assert item.kind.value == "AUTH_SUCCESS"
    assert item.user_name == "alice"
    assert item.src_ip == "10.0.0.5"
    assert item.outcome == "success"
    assert item.event_id.startswith("linux-endpoint:")

    event = normalize_endpoint_event(item)
    assert event.attributes["identity_source"] == "username"
    assert event.attributes["identity_confidence"] == "WEAK"


def test_auth_failure_normalization_from_sshd_journal_message() -> None:
    record = parse_journal_entry(
        journal_entry(
            message="Failed password for invalid user bob from 10.0.0.6 port 23 ssh2"
        )
    )
    item = normalize_linux_journal_event(
        record, tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    assert item is not None
    assert item.kind.value == "AUTH_FAILURE"
    assert item.user_name == "bob"
    assert item.outcome == "failure"


def test_non_sshd_and_unmatched_journal_messages_are_ignored() -> None:
    other_unit = parse_journal_entry(
        journal_entry(
            syslog_identifier="cron",
            message="Accepted password for alice from 1.2.3.4 port 22 ssh2",
        )
    )
    assert normalize_linux_journal_event(
        other_unit, tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    ) is None

    unmatched = parse_journal_entry(journal_entry(message="Server listening on 0.0.0.0 port 22."))
    assert normalize_linux_journal_event(
        unmatched, tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    ) is None


def test_deterministic_journal_event_id_replay() -> None:
    message = "Accepted password for alice from 10.0.0.5 port 22 ssh2"
    first = parse_journal_entry(journal_entry(message=message))
    second = parse_journal_entry(journal_entry(message=message))
    assert deterministic_journal_event_id(
        tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR, cursor=first.cursor
    ) == deterministic_journal_event_id(
        tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR, cursor=second.cursor
    )


def test_journal_entry_missing_required_fields_is_rejected() -> None:
    with pytest.raises(ValueError):
        parse_journal_entry({"__CURSOR": "abc"})


def test_journal_entry_oversized_is_rejected() -> None:
    huge = journal_entry(message="Accepted password for alice from 10.0.0.5 port 22 ssh2")
    huge["MESSAGE"] = "x" * 40_000
    with pytest.raises(ValueError):
        parse_journal_entry(huge)


def test_journal_event_rejects_forbidden_credential_fields() -> None:
    record = parse_journal_entry(
        journal_entry(message="Accepted password for alice from 10.0.0.5 port 22 ssh2")
    )
    item = normalize_linux_journal_event(record, tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR)
    assert item is not None
    dumped = str(item.model_dump()).casefold()
    for forbidden in ("password", "secret", "private_key", "kerberos_ticket", "ssh private key"):
        assert forbidden not in dumped


# --------------------------------------------------------------------------
# audit / process execution normalization
# --------------------------------------------------------------------------


def test_process_execution_normalization_with_uid_and_namespace() -> None:
    complete, pending, rejected = group_audit_lines(audit_group())
    assert not pending
    assert rejected == 0
    assert len(complete) == 1
    item = normalize_linux_audit_execve(
        complete[0], tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR, hostname=HOSTNAME
    )
    assert item is not None
    assert item.kind.value == "PROCESS_START"
    assert item.process_pid == 1234
    assert item.parent_process_pid == 1
    assert item.user_uid == "1000"
    assert item.identity_namespace == HOSTNAME
    assert item.command_line == "ls -la"
    assert item.image == "/usr/bin/bash"
    assert item.outcome == "success"

    event = normalize_endpoint_event(item)
    assert event.attributes["identity_source"] == "linux_uid"
    assert event.attributes["identity_confidence"] == "STRONG"
    assert event.attributes["identity_domain"] == HOSTNAME


def test_process_execution_prefers_auid_over_uid_when_both_present() -> None:
    complete, _pending, _rejected = group_audit_lines(audit_group(auid="1000", uid="0"))
    item = normalize_linux_audit_execve(
        complete[0], tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR, hostname=HOSTNAME
    )
    assert item is not None
    assert item.user_uid == "1000"


def test_unset_auid_sentinel_falls_back_to_uid() -> None:
    complete, _pending, _rejected = group_audit_lines(
        audit_group(auid="4294967295", uid="33")
    )
    item = normalize_linux_audit_execve(
        complete[0], tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR, hostname=HOSTNAME
    )
    assert item is not None
    assert item.user_uid == "33"


def test_uid_without_hostname_namespace_is_not_treated_as_globally_unique() -> None:
    complete, _pending, _rejected = group_audit_lines(audit_group())
    item = normalize_linux_audit_execve(
        complete[0], tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR, hostname=None
    )
    assert item is not None
    # A UID is still preserved, but with no namespace/host context to scope it.
    assert item.user_uid == "1000"
    assert item.identity_namespace is None


def test_syscall_without_execve_is_not_classified_as_process_start() -> None:
    lines = [
        line
        for line in audit_group(include_execve=False)
        if not line.startswith("type=EXECVE")
    ]
    complete, _pending, _rejected = group_audit_lines(lines)
    assert len(complete) == 1
    assert normalize_linux_audit_execve(
        complete[0], tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR, hostname=HOSTNAME
    ) is None


def test_absent_command_line_when_execve_has_no_args() -> None:
    lines = audit_group(argv=[])
    complete, _pending, _rejected = group_audit_lines(lines)
    item = normalize_linux_audit_execve(
        complete[0], tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR, hostname=HOSTNAME
    )
    assert item is not None
    assert item.command_line is None


def test_incomplete_audit_group_without_eoe_is_pending_not_lost() -> None:
    lines = [line for line in audit_group() if not line.startswith("type=EOE")]
    complete, pending, rejected = group_audit_lines(lines)
    assert complete == []
    assert rejected == 0
    assert len(pending) == len(lines)


def test_malformed_audit_line_is_rejected_not_raised() -> None:
    lines = audit_group() + ["this is not a valid audit line"]
    complete, _pending, rejected = group_audit_lines(lines)
    assert rejected == 1
    assert len(complete) == 1


def test_parse_audit_line_rejects_malformed_input() -> None:
    with pytest.raises(ValueError):
        parse_audit_line("not an audit line at all")


def test_parse_audit_line_rejects_oversized_input() -> None:
    with pytest.raises(ValueError):
        parse_audit_line("type=SYSCALL msg=audit(1700000000.123:1): " + "a" * 20_000)


def test_deterministic_audit_event_id_replay() -> None:
    complete_a, _p, _r = group_audit_lines(audit_group())
    complete_b, _p2, _r2 = group_audit_lines(audit_group())
    id_a = deterministic_audit_event_id(
        tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR, audit_id=complete_a[0].audit_id
    )
    id_b = deterministic_audit_event_id(
        tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR, audit_id=complete_b[0].audit_id
    )
    assert id_a == id_b


def test_audit_event_rejects_forbidden_credential_fields() -> None:
    complete, _p, _r = group_audit_lines(audit_group())
    item = normalize_linux_audit_execve(
        complete[0], tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR, hostname=HOSTNAME
    )
    assert item is not None
    dumped = str(item.model_dump()).casefold()
    for forbidden in ("password", "secret", "private_key", "kerberos_ticket"):
        assert forbidden not in dumped


def test_tenant_scope_is_required_for_normalization() -> None:
    complete, _p, _r = group_audit_lines(audit_group())
    with pytest.raises(ValueError):
        normalize_linux_audit_execve(
            complete[0], tenant_id="", site_id=SITE, sensor_id=SENSOR, hostname=HOSTNAME
        )
    record = parse_journal_entry(
        journal_entry(message="Accepted password for alice from 10.0.0.5 port 22 ssh2")
    )
    with pytest.raises(ValueError):
        normalize_linux_journal_event(record, tenant_id=TENANT, site_id="", sensor_id=SENSOR)


# --------------------------------------------------------------------------
# checkpoint store
# --------------------------------------------------------------------------


def test_checkpoint_save_and_load_roundtrip(tmp_path) -> None:
    store = LinuxCollectorCheckpointStore(
        tmp_path / "checkpoints", tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    assert store.load("journal:sshd", LinuxSourceKind.JOURNAL) is None
    store.save("journal:sshd", LinuxSourceKind.JOURNAL, "cursor-1")
    loaded = store.load("journal:sshd", LinuxSourceKind.JOURNAL)
    assert loaded is not None
    assert loaded.checkpoint_token == "cursor-1"
    assert loaded.tenant_id == TENANT


def test_checkpoint_restart_semantics_persist_across_new_store_instance(tmp_path) -> None:
    directory = tmp_path / "checkpoints"
    first_store = LinuxCollectorCheckpointStore(
        directory, tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    first_store.save("audit:execve", LinuxSourceKind.AUDIT, "1700000000.123:500")

    second_store = LinuxCollectorCheckpointStore(
        directory, tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    loaded = second_store.load("audit:execve", LinuxSourceKind.AUDIT)
    assert loaded is not None
    assert loaded.checkpoint_token == "1700000000.123:500"


def test_different_source_kinds_get_independent_checkpoints(tmp_path) -> None:
    store = LinuxCollectorCheckpointStore(
        tmp_path / "checkpoints", tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    store.save("shared-id", LinuxSourceKind.JOURNAL, "cursor-a")
    with pytest.raises(LinuxCollectorCheckpointError):
        store.load("shared-id", LinuxSourceKind.AUDIT)


def test_corrupt_checkpoint_fails_visibly(tmp_path) -> None:
    directory = tmp_path / "checkpoints"
    store = LinuxCollectorCheckpointStore(
        directory, tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    store.save("journal:sshd", LinuxSourceKind.JOURNAL, "cursor-1")
    path = store._path("journal:sshd")
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(LinuxCollectorCheckpointError):
        store.load("journal:sshd", LinuxSourceKind.JOURNAL)


def test_checkpoint_scope_mismatch_fails_visibly(tmp_path) -> None:
    directory = tmp_path / "checkpoints"
    store_a = LinuxCollectorCheckpointStore(
        directory, tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    store_a.save("journal:sshd", LinuxSourceKind.JOURNAL, "cursor-1")
    store_b = LinuxCollectorCheckpointStore(
        directory, tenant_id="other-tenant", site_id=SITE, sensor_id=SENSOR
    )
    with pytest.raises(LinuxCollectorCheckpointError):
        store_b.load("journal:sshd", LinuxSourceKind.JOURNAL)


# --------------------------------------------------------------------------
# buffer
# --------------------------------------------------------------------------


def make_event(event_id: str = "evt-1") -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        tenant_id=TENANT,
        site_id=SITE,
        sensor_id=SENSOR,
        category="endpoint.process.start",
        observed_at=dt.datetime.now(dt.UTC),
    )


def test_buffer_enforces_tenant_site_sensor_scope(tmp_path) -> None:
    buffer = SQLiteLinuxEventBuffer(
        tmp_path / "buffer.db", tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    wrong_scope = SecurityEvent(
        event_id="evt-x",
        tenant_id="other-tenant",
        site_id=SITE,
        sensor_id=SENSOR,
        category="endpoint.process.start",
    )
    with pytest.raises(ValueError):
        buffer.enqueue(wrong_scope)
    buffer.close()


def test_buffer_deduplicates_identical_event_ids(tmp_path) -> None:
    buffer = SQLiteLinuxEventBuffer(
        tmp_path / "buffer.db", tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    first = buffer.enqueue(make_event("evt-1"))
    second = buffer.enqueue(make_event("evt-1"))
    assert first is True
    assert second is False
    assert buffer.count() == 1
    buffer.close()


def test_buffer_is_bounded_and_rejects_overflow(tmp_path) -> None:
    buffer = SQLiteLinuxEventBuffer(
        tmp_path / "buffer.db",
        tenant_id=TENANT,
        site_id=SITE,
        sensor_id=SENSOR,
        max_events=2,
    )
    buffer.enqueue(make_event("evt-1"))
    buffer.enqueue(make_event("evt-2"))
    with pytest.raises(LinuxEndpointCollectorError):
        buffer.enqueue(make_event("evt-3"))
    buffer.close()


# --------------------------------------------------------------------------
# collector health / end-to-end
# --------------------------------------------------------------------------


def build_collector(tmp_path, *, sources, sender=None):
    checkpoint_store = LinuxCollectorCheckpointStore(
        tmp_path / "checkpoints", tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    buffer = SQLiteLinuxEventBuffer(
        tmp_path / "buffer.db", tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    sender = sender or FakeSender()
    collector = LinuxEndpointCollector(
        tenant_id=TENANT,
        site_id=SITE,
        sensor_id=SENSOR,
        sources=sources,
        checkpoint_store=checkpoint_store,
        buffer=buffer,
        sender=sender,
    )
    return collector, buffer, sender


def test_health_is_synced_after_successful_collection_and_flush(tmp_path) -> None:
    journal_reader = InMemoryJournalReader(
        [journal_entry(message="Accepted password for alice from 10.0.0.5 port 22 ssh2")]
    )
    source = JournalAuthSource(
        "journal:sshd", journal_reader, tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    collector, buffer, sender = build_collector(tmp_path, sources=[source])
    health = asyncio.run(collector.collect_once())
    assert health.state is LinuxCollectorState.SYNCED
    assert health.buffered_events == 0
    assert len(sender.sent) == 1
    buffer.close()


def test_health_reports_buffering_when_transport_has_not_flushed_yet(tmp_path) -> None:
    journal_reader = InMemoryJournalReader(
        [journal_entry(message="Accepted password for alice from 10.0.0.5 port 22 ssh2")]
    )
    source = JournalAuthSource(
        "journal:sshd", journal_reader, tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    sender = FakeSender()
    sender.fail = True
    collector, buffer, _sender = build_collector(tmp_path, sources=[source], sender=sender)
    health = asyncio.run(collector.collect_once())
    assert health.state is LinuxCollectorState.TRANSPORT_UNAVAILABLE
    assert health.buffered_events == 1
    buffer.close()


def test_health_reports_source_unavailable_and_permission_denied() -> None:
    class UnavailableSource:
        source_id = "audit:execve"
        source_kind = LinuxSourceKind.AUDIT

        def read_after(self, checkpoint_token, *, limit):
            raise LinuxSourceUnavailable("audit log is missing")

    class DeniedSource:
        source_id = "journal:sshd"
        source_kind = LinuxSourceKind.JOURNAL

        def read_after(self, checkpoint_token, *, limit):
            raise LinuxSourcePermissionDenied("cannot read journal")

    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        collector, buffer, _sender = build_collector(
            tmp_path, sources=[UnavailableSource(), DeniedSource()]
        )
        health = asyncio.run(collector.collect_once())
        assert health.state is LinuxCollectorState.PERMISSION_DENIED
        states = {item.source_id: item.state for item in health.sources}
        assert states["audit:execve"] is LinuxCollectorState.SOURCE_UNAVAILABLE
        assert states["journal:sshd"] is LinuxCollectorState.PERMISSION_DENIED
        buffer.close()


def test_health_is_degraded_when_records_are_rejected(tmp_path) -> None:
    journal_reader = InMemoryJournalReader([{"__CURSOR": "c1"}])
    source = JournalAuthSource(
        "journal:sshd", journal_reader, tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    collector, buffer, _sender = build_collector(tmp_path, sources=[source])
    health = asyncio.run(collector.collect_once())
    assert health.state is LinuxCollectorState.DEGRADED
    buffer.close()


def test_collect_once_does_not_reprocess_after_checkpoint_advance(tmp_path) -> None:
    entries = [
        journal_entry(
            cursor="cursor-1",
            message="Accepted password for alice from 10.0.0.5 port 22 ssh2",
        ),
        journal_entry(
            cursor="cursor-2",
            message="Failed password for bob from 10.0.0.6 port 23 ssh2",
        ),
    ]
    journal_reader = InMemoryJournalReader(entries)
    source = JournalAuthSource(
        "journal:sshd", journal_reader, tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    collector, buffer, sender = build_collector(tmp_path, sources=[source])
    asyncio.run(collector.collect_once())
    assert len(sender.sent) == 2

    # A second pass with the same reader (and its now-advanced checkpoint)
    # must not resend already-processed evidence.
    asyncio.run(collector.collect_once())
    assert len(sender.sent) == 2
    buffer.close()


def test_end_to_end_audit_process_execution_reaches_sender(tmp_path) -> None:
    reader = InMemoryAuditLogReader([audit_group()])
    source = AuditProcessSource(
        "audit:execve",
        reader,
        tenant_id=TENANT,
        site_id=SITE,
        sensor_id=SENSOR,
        hostname=HOSTNAME,
    )
    collector, buffer, sender = build_collector(tmp_path, sources=[source])
    health = asyncio.run(collector.collect_once())
    assert health.state is LinuxCollectorState.SYNCED
    assert len(sender.sent) == 1
    assert sender.sent[0].category == "endpoint.process.start"
    buffer.close()
