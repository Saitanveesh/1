from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from mon.linux_endpoint_collector import (
    FileAuditLogReader,
    LinuxCollectorCheckpointError,
    LinuxCollectorHealth,
    LinuxCollectorServiceRuntime,
    LinuxCollectorServiceState,
    LinuxCollectorState,
    LinuxEndpointCollectorError,
    LinuxSourceHealth,
    LinuxSourceKind,
    LinuxSourcePermissionDenied,
    LinuxSourceUnavailable,
    SystemdJournalReader,
    _build_audit_source,
    _build_journal_source,
    async_main,
    build_arg_parser,
    build_collector_from_args,
    validate_poll_interval,
)

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "tools" / "systemd" / "mon-linux-endpoint-collector.service"


def health(
    state: LinuxCollectorState, sources: list[LinuxSourceHealth] | None = None
) -> LinuxCollectorHealth:
    return LinuxCollectorHealth(state=state, buffered_events=0, sources=sources or [])


# --------------------------------------------------------------------------
# CLI / config validation
# --------------------------------------------------------------------------


def test_cli_requires_tenant_site_sensor_and_state_dir() -> None:
    parser = build_arg_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--tenant-id", "t"])


def test_cli_help_exits_zero() -> None:
    parser = build_arg_parser()
    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(["--help"])
    assert excinfo.value.code == 0


def test_cli_defaults_are_bounded_and_loopback_only(tmp_path) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(
        [
            "--tenant-id",
            "tenant-a",
            "--site-id",
            "site-a",
            "--sensor-id",
            "sensor-a",
            "--state-dir",
            str(tmp_path),
        ]
    )
    assert args.site_url == "http://127.0.0.1:8090"
    assert 0 < args.poll_interval_seconds <= 3600
    assert args.batch_size == 100
    assert args.max_buffered_events == 10_000


def test_build_collector_from_args_never_crashes_when_sources_are_unavailable(tmp_path) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(
        [
            "--tenant-id",
            "tenant-a",
            "--site-id",
            "site-a",
            "--sensor-id",
            "sensor-a",
            "--state-dir",
            str(tmp_path),
            "--site-url",
            "http://127.0.0.1:9",
            "--audit-log-file",
            str(tmp_path / "does-not-exist.log"),
        ]
    )
    collector, resources = build_collector_from_args(args)
    try:
        health = asyncio.run(collector.collect_once())
        assert health.state is LinuxCollectorState.SOURCE_UNAVAILABLE
        assert not any("password" in (item.last_error or "") for item in health.sources)
    finally:
        for resource in resources:
            resource.close()


def test_build_collector_from_args_rejects_non_loopback_site_url(tmp_path) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(
        [
            "--tenant-id",
            "tenant-a",
            "--site-id",
            "site-a",
            "--sensor-id",
            "sensor-a",
            "--state-dir",
            str(tmp_path),
            "--site-url",
            "http://evil.example.com",
        ]
    )
    with pytest.raises(ValueError, match="loopback"):
        build_collector_from_args(args)


def test_one_shot_cli_reports_source_unavailable_without_fabricating_events(
    tmp_path, capsys
) -> None:
    exit_code = asyncio.run(
        async_main(
            [
                "--tenant-id",
                "tenant-a",
                "--site-id",
                "site-a",
                "--sensor-id",
                "sensor-a",
                "--state-dir",
                str(tmp_path),
                "--site-url",
                "http://127.0.0.1:9",
                "--audit-log-file",
                str(tmp_path / "missing.log"),
            ]
        )
    )
    assert exit_code == 2
    printed = capsys.readouterr().out
    assert "SOURCE_UNAVAILABLE" in printed


# --------------------------------------------------------------------------
# runtime stop / cancellation / resource cleanup
# --------------------------------------------------------------------------


def test_poll_interval_validation() -> None:
    assert validate_poll_interval(0.01) == 0.01
    assert validate_poll_interval(3600) == 3600
    with pytest.raises(ValueError, match="poll interval"):
        validate_poll_interval(0.0)
    with pytest.raises(ValueError, match="poll interval"):
        validate_poll_interval(3600.1)


def test_service_runtime_stops_on_request_and_closes_resources() -> None:
    class Collector:
        def __init__(self) -> None:
            self.calls = 0

        async def collect_once(self) -> LinuxCollectorHealth:
            self.calls += 1
            return health(LinuxCollectorState.SYNCED)

    class Resource:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    async def scenario() -> None:
        collector = Collector()
        resource = Resource()
        runtime = LinuxCollectorServiceRuntime(
            collector=collector,
            poll_interval_seconds=60,
            resources=(resource,),
        )
        task = asyncio.create_task(runtime.run_forever())
        await asyncio.sleep(0)
        assert runtime.status.service_state is LinuxCollectorServiceState.RUNNING
        runtime.request_stop()
        status = await asyncio.wait_for(task, timeout=1)

        assert status.service_state is LinuxCollectorServiceState.STOPPED
        assert collector.calls == 1
        assert resource.closed is True

    asyncio.run(scenario())


def test_service_runtime_fatal_checkpoint_error_is_visible_and_still_closes_resources() -> None:
    class Collector:
        async def collect_once(self) -> LinuxCollectorHealth:
            raise LinuxCollectorCheckpointError("checkpoint corrupt")

    class Resource:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    async def scenario() -> None:
        resource = Resource()
        runtime = LinuxCollectorServiceRuntime(
            collector=Collector(),
            poll_interval_seconds=1,
            resources=(resource,),
        )
        with pytest.raises(LinuxCollectorCheckpointError):
            await runtime.run_forever()
        assert runtime.status.service_state is LinuxCollectorServiceState.FAILED
        assert runtime.status.fatal_error == "checkpoint corrupt"
        assert resource.closed is True

    asyncio.run(scenario())


def test_service_runtime_surfaces_transport_unavailable_without_crashing() -> None:
    class Collector:
        def __init__(self) -> None:
            self.calls = 0

        async def collect_once(self) -> LinuxCollectorHealth:
            self.calls += 1
            state = (
                LinuxCollectorState.TRANSPORT_UNAVAILABLE
                if self.calls == 1
                else LinuxCollectorState.SYNCED
            )
            return health(state)

    async def scenario() -> None:
        collector = Collector()
        runtime = LinuxCollectorServiceRuntime(collector=collector, poll_interval_seconds=0.01)
        task = asyncio.create_task(runtime.run_forever())
        while collector.calls < 2:
            await asyncio.sleep(0.01)
        runtime.request_stop()
        status = await asyncio.wait_for(task, timeout=1)

        assert status.service_state is LinuxCollectorServiceState.STOPPED
        assert status.collector_health is not None
        assert status.collector_health.state is LinuxCollectorState.SYNCED

    asyncio.run(scenario())


# --------------------------------------------------------------------------
# journal adapter boundary
# --------------------------------------------------------------------------


def test_systemd_journal_reader_reports_unavailable_off_linux() -> None:
    if sys.platform == "linux":
        pytest.skip("this asserts the non-Linux guard path")
    with pytest.raises(LinuxSourceUnavailable, match="requires Linux"):
        SystemdJournalReader()


def test_build_journal_source_degrades_to_static_failure_when_unavailable(tmp_path) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(
        [
            "--tenant-id",
            "tenant-a",
            "--site-id",
            "site-a",
            "--sensor-id",
            "sensor-a",
            "--state-dir",
            str(tmp_path),
            "--ssh-unit",
            "sshd",
        ]
    )
    source = _build_journal_source(args)
    assert source.source_kind is LinuxSourceKind.JOURNAL
    with pytest.raises((LinuxSourceUnavailable, LinuxSourcePermissionDenied)):
        source.read_after(None, limit=10)


# --------------------------------------------------------------------------
# audit adapter boundary
# --------------------------------------------------------------------------


def test_file_audit_log_reader_reports_unavailable_when_file_missing(tmp_path) -> None:
    reader = FileAuditLogReader(tmp_path / "does-not-exist.log")
    with pytest.raises(LinuxSourceUnavailable):
        reader.read_after(None, limit=10)


def test_file_audit_log_reader_holds_back_incomplete_trailing_event(tmp_path) -> None:
    log_path = tmp_path / "audit.log"
    header = "msg=audit(1700000000.100:1):"
    complete = (
        f'type=SYSCALL {header} pid=100 ppid=1 auid=1000 uid=0 comm="bash" '
        f'exe="/usr/bin/bash" success=yes\n'
        f'type=EXECVE {header} argc=1 a0="ls"\n'
        f"type=EOE {header}\n"
    )
    incomplete = 'type=SYSCALL msg=audit(1700000000.200:2): pid=101 ppid=1 auid=1000 uid=0\n'
    log_path.write_text(complete + incomplete, encoding="utf-8")

    reader = FileAuditLogReader(log_path)
    groups, token = reader.read_after(None, limit=10)

    assert len(groups) == 1
    assert token is not None
    # The offset only advances through the complete event; the trailing
    # incomplete SYSCALL line is not consumed by the checkpoint.
    assert int(token) == len(complete.encode("utf-8"))

    # A second read from the same token returns nothing new until an EOE for
    # the pending event is appended.
    groups_again, token_again = reader.read_after(token, limit=10)
    assert groups_again == []
    assert token_again == token

    with log_path.open("a", encoding="utf-8") as handle:
        handle.write("type=EOE msg=audit(1700000000.200:2):\n")
    groups_final, token_final = reader.read_after(token, limit=10)
    assert len(groups_final) == 1
    assert token_final is not None
    assert int(token_final) > int(token)


def test_file_audit_log_reader_rejects_invalid_checkpoint_token(tmp_path) -> None:
    log_path = tmp_path / "audit.log"
    log_path.write_text("type=EOE msg=audit(1700000000.100:1):\n", encoding="utf-8")
    reader = FileAuditLogReader(log_path)
    with pytest.raises(LinuxEndpointCollectorError):
        reader.read_after("not-a-byte-offset", limit=10)


def test_build_audit_source_construction_never_touches_the_filesystem(tmp_path) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(
        [
            "--tenant-id",
            "tenant-a",
            "--site-id",
            "site-a",
            "--sensor-id",
            "sensor-a",
            "--state-dir",
            str(tmp_path),
            "--audit-log-file",
            str(tmp_path / "nonexistent" / "audit.log"),
        ]
    )
    source = _build_audit_source(args, "host-1")
    assert source.source_kind is LinuxSourceKind.AUDIT
    with pytest.raises(LinuxSourceUnavailable):
        source.read_after(None, limit=10)


# --------------------------------------------------------------------------
# systemd unit configuration expectations
# --------------------------------------------------------------------------


def test_systemd_unit_file_exists_and_is_repo_owned() -> None:
    assert UNIT.is_file()


def test_systemd_unit_uses_dedicated_runtime_command() -> None:
    unit = UNIT.read_text(encoding="utf-8")
    assert "ExecStart=/usr/local/bin/mon-linux-endpoint-collector foreground" in unit


def test_systemd_unit_has_bounded_restart_policy() -> None:
    unit = UNIT.read_text(encoding="utf-8")
    assert "Restart=on-failure" in unit
    assert "RestartSec=" in unit
    assert "StartLimitBurst=" in unit
    assert "StartLimitIntervalSec=" in unit


def test_systemd_unit_declares_explicit_state_directory() -> None:
    unit = UNIT.read_text(encoding="utf-8")
    assert "StateDirectory=mon-linux-endpoint-collector" in unit
    assert "--state-dir /var/lib/mon-linux-endpoint-collector" in unit


def test_systemd_unit_does_not_assume_root() -> None:
    unit = UNIT.read_text(encoding="utf-8")
    assert "User=mon-collector" in unit
    assert "User=root" not in unit


def test_systemd_unit_does_not_embed_secrets() -> None:
    directives = "\n".join(
        line
        for line in UNIT.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ).casefold()
    for forbidden in ("password", "secret", "private_key", "api_key", "token="):
        assert forbidden not in directives


def test_ci_workflow_runs_linux_endpoint_collector_job() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "linux-endpoint-collector:" in workflow
    assert "mon-linux-endpoint-collector --help" in workflow
    assert "kill -TERM" in workflow
