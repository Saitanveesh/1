"""Windows service lifecycle certification.

Static tests run anywhere. The lifecycle test registers a real SCM service and
therefore runs ONLY on a disposable Windows CI runner: it requires
MON_WINDOWS_CERT=1 (set by .github/workflows/windows-service-certification.yml)
plus MON_CERT_EXE / MON_CERT_EXE_B pointing at built MONWindows.exe candidates.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mon.domain import SecurityEvent
from mon.endpoint import normalize_endpoint_event
from mon.windows_endpoint_collector import (
    SQLiteWindowsEventBuffer,
    WindowsEventCheckpointStore,
    normalize_windows_event,
    parse_windows_event_xml,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "windows" / "mon-windows-service.ps1"
REPORT_PATH = Path("windows-service-certification-report.json")

TENANT, SITE, SENSOR = "cert-tenant", "cert-site", "cert-sensor"

_ENABLED = (
    sys.platform == "win32"
    and os.environ.get("MON_WINDOWS_CERT") == "1"
    and bool(os.environ.get("MON_CERT_EXE"))
    and bool(os.environ.get("MON_CERT_EXE_B"))
)


# --------------------------------------------------------------------------
# Static checks (run everywhere)
# --------------------------------------------------------------------------


def test_script_quotes_executable_and_state_dir_and_has_no_credentials() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    assert '$binPath = "`"$resolvedExe`" service-run' in script
    assert '--state-dir `"$resolvedStateDir`"' in script
    assert 'start=", "demand"' in script
    lowered = script.lower()
    for word in ("password", "token", "secret", "certificate", "apikey"):
        assert word not in lowered


def test_fault_injection_hook_is_inert_without_env_and_prefix() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    assert 'MON_TEST_FAIL_AFTER_SCM_CREATE -eq "1"' in script
    assert '$ServiceName -like "mon-cert-*"' in script
    # Hook must sit after registration and inside the rollback-protected try block.
    assert script.index("$created = $true") < script.index("MON_TEST_FAIL_AFTER_SCM_CREATE")
    assert script.index("MON_TEST_FAIL_AFTER_SCM_CREATE") < script.index("catch {")


def test_workflow_is_dedicated_bounded_and_always_cleans_up() -> None:
    workflow = (ROOT / ".github/workflows/windows-service-certification.yml").read_text(
        encoding="utf-8"
    )
    assert "windows-latest" in workflow
    assert "timeout-minutes" in workflow
    assert "if: always()" in workflow
    assert "windows-service-certification-report.json" in workflow


# --------------------------------------------------------------------------
# Real lifecycle (disposable Windows runner only)
# --------------------------------------------------------------------------


def _run(cmd: list[str], timeout: float = 120, env: dict[str, str] | None = None):
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False, env=env
    )


def _script(action: str, name: str, *extra: str, env: dict[str, str] | None = None):
    return _run(
        [
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(SCRIPT), "-Action", action, "-ServiceName", name,
            "-TimeoutSeconds", "30", *extra,
        ],
        timeout=120,
        env=env,
    )  # fmt: skip


def _install(name: str, exe: Path, state: Path, env: dict[str, str] | None = None):
    return _script(
        "install", name,
        "-ExecutablePath", str(exe), "-StateDir", str(state),
        "-TenantId", TENANT, "-SiteId", SITE, "-SensorId", SENSOR,
        "-SiteUrl", "http://127.0.0.1:9", "-PollIntervalSeconds", "1",
        env=env,
    )  # fmt: skip


def _status(name: str) -> str:
    result = _script("status", name)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip().splitlines()[-1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sc(*args: str) -> subprocess.CompletedProcess:
    return _run(["sc.exe", *args], timeout=30)


def _scm_absent(name: str) -> bool:
    # 1060 = ERROR_SERVICE_DOES_NOT_EXIST
    return _sc("query", name).returncode == 1060


def _queryex(name: str) -> dict[str, object]:
    out = _sc("queryex", name).stdout
    state = re.search(r"STATE\s*:\s*\d+\s+(\w+)", out)
    pid = re.search(r"PID\s*:\s*(\d+)", out)
    win32 = re.search(r"WIN32_EXIT_CODE\s*:\s*(\d+)", out)
    return {
        "state": state.group(1) if state else None,
        "pid": int(pid.group(1)) if pid else 0,
        "win32_exit_code": int(win32.group(1)) if win32 else None,
    }


def _qc(name: str) -> dict[str, str]:
    out = _sc("qc", name).stdout
    binary = re.search(r"BINARY_PATH_NAME\s*:\s*(.+)", out)
    start = re.search(r"START_TYPE\s*:\s*\d+\s+(\w+)", out)
    return {
        "binary_path": binary.group(1).strip() if binary else "",
        "start_type": start.group(1) if start else "",
    }


def _wait_state(name: str, wanted: set[str], seconds: float = 30) -> str | None:
    deadline = time.monotonic() + seconds
    state = None
    while time.monotonic() < deadline:
        state = _queryex(name)["state"]
        if state in wanted:
            return state
        time.sleep(0.5)
    return state


def _processes_under(root: Path) -> list[dict[str, object]]:
    ps = (
        "Get-CimInstance Win32_Process -Filter \"Name='MONWindows.exe'\" | "
        "Select-Object ProcessId,ParentProcessId,ExecutablePath | ConvertTo-Json -Compress"
    )
    out = _ps5(ps).stdout.strip()
    if not out:
        return []
    data = json.loads(out)
    rows = data if isinstance(data, list) else [data]
    prefix = str(root).lower()
    return [r for r in rows if str(r.get("ExecutablePath") or "").lower().startswith(prefix)]


def _ps5(command: str) -> subprocess.CompletedProcess:
    # The runner's pwsh 7 PSModulePath breaks Windows PowerShell 5.1 module autoload.
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    return _run(["powershell.exe", "-NoProfile", "-Command", command], timeout=60, env=env)


def _authenticode(path: Path) -> str:
    ps = (
        "$ErrorActionPreference = 'Stop'; "
        f"(Get-AuthenticodeSignature -LiteralPath '{path}').Status.ToString()"
    )
    result = _ps5(ps)
    return result.stdout.strip() or f"error: {result.stderr.strip()[:300]}"


def _replace_binary(src: Path, dst: Path, seconds: float = 30) -> int:
    """Replace a stopped service's executable; bounded retry for post-exit handle release."""
    deadline = time.monotonic() + seconds
    attempts = 0
    while True:
        attempts += 1
        try:
            shutil.copy2(src, dst)
            return attempts
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)


def _seed_state(state: Path) -> str:
    """Seed durable state via existing MON classes (synthetic, not telemetry)."""
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        '<Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4625</EventID>'
        '<TimeCreated SystemTime="2026-09-20T00:00:00.000000Z" />'
        "<EventRecordID>4242</EventRecordID><Channel>Security</Channel>"
        "<Computer>CERT-FIXTURE</Computer></System><EventData>"
        '<Data Name="TargetUserSid">S-1-5-21-1000</Data>'
        '<Data Name="TargetUserName">fixture</Data>'
        '<Data Name="TargetDomainName">CERT</Data>'
        '<Data Name="TargetLogonId">0x1</Data>'
        '<Data Name="IpAddress">198.51.100.9</Data>'
        "</EventData></Event>"
    )
    endpoint = normalize_windows_event(
        parse_windows_event_xml(xml), tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    assert endpoint is not None
    event = SecurityEvent.model_validate(normalize_endpoint_event(endpoint))
    buffer = SQLiteWindowsEventBuffer(
        state / "windows-endpoint-buffer.db", tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    try:
        buffer.enqueue(event)
    finally:
        buffer.close()
    WindowsEventCheckpointStore(state / "security-checkpoint.json", channel="Security").save(
        last_record_id=4242
    )
    return event.event_id


def _state_readable(state: Path, event_id: str) -> dict[str, object]:
    buffer = SQLiteWindowsEventBuffer(
        state / "windows-endpoint-buffer.db", tenant_id=TENANT, site_id=SITE, sensor_id=SENSOR
    )
    try:
        has = buffer.has_event(event_id)
        count = buffer.count()
    finally:
        buffer.close()
    checkpoint = WindowsEventCheckpointStore(
        state / "security-checkpoint.json", channel="Security"
    ).load()
    return {
        "seed_event_present": has,
        "buffer_count": count,
        "checkpoint_last_record_id": checkpoint.last_record_id if checkpoint else None,
    }


class _Report:
    def __init__(self) -> None:
        self.data: dict[str, object] = {
            "schema": "mon.windows-service-certification.v1",
            "generated_at": dt.datetime.now(dt.UTC).isoformat(),
            "stages": {},
            "not_proven": [],
        }

    def stage(self, name: str, **facts: object) -> None:
        self.data["stages"][name] = {"status": "PROVEN", **facts}  # type: ignore[index]

    def not_proven(self, item: str) -> None:
        self.data["not_proven"].append(item)  # type: ignore[union-attr]

    def write(self) -> None:
        REPORT_PATH.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")


@pytest.mark.skipif(
    not _ENABLED, reason="requires a disposable Windows CI runner (MON_WINDOWS_CERT=1)"
)
def test_windows_service_lifecycle_certification(tmp_path: Path) -> None:
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "0")
    name = f"mon-cert-{run_id}-{attempt}"
    partial_name = f"mon-cert-partial-{run_id}-{attempt}"
    work = tmp_path / "MON Cert"  # spaces exercise the quoting contract
    install_dir, state, cand_a, cand_b = (
        work / "install dir", work / "state dir", work / "candidate-a", work / "candidate-b",
    )  # fmt: skip
    for directory in (install_dir, state, cand_a, cand_b):
        directory.mkdir(parents=True)
    exe_a, exe_b = cand_a / "MONWindows.exe", cand_b / "MONWindows.exe"
    shutil.copy2(os.environ["MON_CERT_EXE"], exe_a)
    shutil.copy2(os.environ["MON_CERT_EXE_B"], exe_b)
    installed = install_dir / "MONWindows.exe"

    report = _Report()
    report.data["runner"] = {
        "platform": platform.platform(),
        "windows_version": platform.version(),
        "image_version": os.environ.get("IMAGEVERSION", "unknown")  # noqa: SIM112,
    }
    report.data["service_name"] = name
    cleanup_names = [name, partial_name]

    try:
        # 1-2: build outputs and digests
        sha_a, sha_b = _sha256(exe_a), _sha256(exe_b)
        assert sha_a != sha_b, "candidate B must be byte-distinct"
        expected = os.environ.get("MON_CERT_EXE_SHA256", "").strip().lower()
        if expected:
            assert sha_a == expected, "candidate A digest differs from the recorded build digest"
        shutil.copy2(exe_a, installed)
        assert _sha256(installed) == sha_a
        report.stage("build_and_digest", sha256_a=sha_a, sha256_b=sha_b,
                     matches_recorded_build_digest=bool(expected))  # fmt: skip

        # Signing readiness (never faked)
        signature = _authenticode(installed)
        assert signature == "NotSigned", f"unexpected Authenticode state: {signature}"
        report.stage("authenticode_state", state=signature)
        report.not_proven("production Authenticode signing")

        # Partial install rollback (fault injected after SCM registration)
        partial_state = work / "partial-state"
        partial_state.mkdir()
        (partial_state / "keep.marker").write_text("caller-owned", encoding="utf-8")
        env = {**os.environ, "MON_TEST_FAIL_AFTER_SCM_CREATE": "1"}
        failed = _install(partial_name, installed, partial_state, env=env)
        assert failed.returncode != 0
        assert _scm_absent(partial_name), "partial install left an orphan SCM entry"
        assert (partial_state / "keep.marker").read_text(encoding="utf-8") == "caller-owned"
        report.stage("partial_install_rollback", install_returncode=failed.returncode,
                     scm_entry_removed=True, caller_state_preserved=True)  # fmt: skip

        # 3-4: install + SCM configuration
        result = _install(name, installed, state)
        assert result.returncode == 0, result.stdout + result.stderr
        config = _qc(name)
        binary = config["binary_path"]
        assert binary.startswith(f'"{installed}" service-run'), binary
        assert f'--state-dir "{state}"' in binary, binary
        assert f"--service-name {name}" in binary
        assert config["start_type"] == "DEMAND_START", config
        for word in ("password", "token", "secret", "apikey"):
            assert word not in binary.lower()
        failure = _sc("qfailure", name).stdout
        recovery_configured = "RESTART" in failure.upper()
        report.stage("install_and_scm_config", install_result=result.stdout.strip(),
                     binary_path_quoted=True, state_dir_quoted=True,
                     start_type=config["start_type"], points_at_candidate_a=True,
                     credentials_in_binary_path=False,
                     recovery_policy_configured=recovery_configured)  # fmt: skip

        # 5-8: start, RUNNING, real process, state dir exercised
        started = _script("start", name)
        assert started.returncode == 0, started.stdout + started.stderr
        assert _status(name) == f"running {name}"
        info = _queryex(name)
        assert info["state"] == "RUNNING" and info["pid"] > 0
        procs = _processes_under(install_dir)
        assert any(p["ProcessId"] == info["pid"] for p in procs), procs
        assert all(str(p["ExecutablePath"]).lower() == str(installed).lower() for p in procs)
        buffer_db = state / "windows-endpoint-buffer.db"
        deadline = time.monotonic() + 30
        while not buffer_db.exists() and time.monotonic() < deadline:
            time.sleep(0.5)
        assert buffer_db.exists(), "running service did not open its state directory"
        report.stage("start_running_process_identity", service_pid=info["pid"],
                     process_count=len(procs), executable_matches=True,
                     state_db_created_by_service=True)  # fmt: skip

        # 9: stop -> seed durable state -> 10: restart
        stopped = _script("stop", name)
        assert stopped.returncode == 0, stopped.stdout + stopped.stderr
        assert _status(name) == f"stopped {name}"
        leftovers = _processes_under(install_dir)
        assert leftovers == [], f"process left after stop: {leftovers}"
        seed_id = _seed_state(state)
        assert _state_readable(state, seed_id)["seed_event_present"] is True
        assert _script("start", name).returncode == 0
        assert _status(name) == f"running {name}"
        restart_pid = _queryex(name)["pid"]
        report.stage("stop_and_restart", stop_result="stopped", no_process_after_stop=True,
                     restart_result="running", restart_pid=restart_pid)  # fmt: skip

        # 11: crash observation (kill exactly the service PID)
        crash_pid = _queryex(name)["pid"]
        before = _processes_under(install_dir)
        killed = _run(["taskkill.exe", "/F", "/PID", str(crash_pid)], timeout=30)
        assert killed.returncode == 0, killed.stdout + killed.stderr
        after_state = _wait_state(name, {"STOPPED"}, 30)
        assert after_state != "RUNNING", "service did not leave RUNNING after its process died"
        time.sleep(10)  # give any (unexpected) recovery policy time to act
        settled = _queryex(name)
        leaked = _processes_under(install_dir)
        report.stage("crash_observation", killed_pid=crash_pid,
                     processes_before=len(before), state_after_kill=after_state,
                     state_after_10s=settled["state"],
                     win32_exit_code=settled["win32_exit_code"],
                     recovery_policy_configured=recovery_configured,
                     automatic_recovery_observed=settled["state"] == "RUNNING",
                     orphan_processes_after_crash=len(leaked))  # fmt: skip
        assert settled["state"] == ("RUNNING" if recovery_configured else "STOPPED")
        assert leaked == [], f"child-process leak after crash: {leaked}"
        assert _script("start", name).returncode == 0  # manual start works after crash
        assert _status(name) == f"running {name}"
        assert _script("stop", name).returncode == 0

        # State preservation across stop
        assert _state_readable(state, seed_id)["seed_event_present"] is True

        # 12-14: uninstall, SCM deleted, state preserved
        uninstalled = _script("uninstall", name)
        assert uninstalled.returncode == 0, uninstalled.stdout + uninstalled.stderr
        assert _scm_absent(name)
        assert _status(name) == f"absent {name}"
        assert _processes_under(install_dir) == []
        preserved = _state_readable(state, seed_id)
        assert preserved["seed_event_present"] is True
        # The running service legitimately advances the checkpoint by reading the real
        # Security log; durable state must never regress below the seeded value.
        assert preserved["checkpoint_last_record_id"] >= 4242
        report.stage("uninstall_and_state_preservation", uninstall_result="uninstalled",
                     scm_entry_deleted=True, status_after_uninstall="absent",
                     state_after_uninstall=preserved)  # fmt: skip

        # Reinstall pointing at the same state directory
        assert _install(name, installed, state).returncode == 0
        assert _script("start", name).returncode == 0
        assert _status(name) == f"running {name}"
        assert _script("stop", name).returncode == 0
        reinstalled = _state_readable(state, seed_id)
        assert reinstalled["seed_event_present"] is True
        report.stage("reinstall_same_state", state_after_reinstall=reinstalled)

        # Upgrade / rollback (binary replacement only; never replace a running exe)
        assert _status(name) == f"stopped {name}"
        upgrade_attempts = _replace_binary(exe_b, installed)
        assert _sha256(installed) == sha_b != sha_a
        assert _script("start", name).returncode == 0
        assert _status(name) == f"running {name}"
        assert _qc(name)["binary_path"].startswith(f'"{installed}" service-run')
        assert _script("stop", name).returncode == 0
        upgraded_state = _state_readable(state, seed_id)
        assert upgraded_state["seed_event_present"] is True
        rollback_attempts = _replace_binary(exe_a, installed)
        assert _sha256(installed) == sha_a
        assert _script("start", name).returncode == 0
        assert _status(name) == f"running {name}"
        assert _script("stop", name).returncode == 0
        rolled_back_state = _state_readable(state, seed_id)
        assert rolled_back_state["seed_event_present"] is True
        report.stage("upgrade_and_rollback", upgraded_sha256=sha_b, rolled_back_sha256=sha_a,
                     upgrade_start="running", rollback_start="running",
                     replace_attempts={"upgrade": upgrade_attempts, "rollback": rollback_attempts},
                     state_after_upgrade=upgraded_state,
                     state_after_rollback=rolled_back_state)  # fmt: skip
        assert _script("uninstall", name).returncode == 0
        assert _scm_absent(name)

        # Event source read (one-shot pass, separate state dir; honest, non-gating)
        source_state = work / "source-state"
        probe = _run(
            [str(installed), "--tenant-id", TENANT, "--site-id", SITE, "--sensor-id", SENSOR,
             "--state-dir", str(source_state), "--site-url", "http://127.0.0.1:9"],
            timeout=90,
        )  # fmt: skip
        health: dict[str, object] = {}
        with contextlib.suppress(ValueError, IndexError):
            health = json.loads(probe.stdout.strip().splitlines()[-1])
        opened = bool(health.get("source_available")) and bool(health.get("permissions_sufficient"))
        report.data["event_source_read"] = {
            "returncode": probe.returncode,
            "collector_state": health.get("state"),
            "source_available": health.get("source_available"),
            "permissions_sufficient": health.get("permissions_sufficient"),
            "status": "PROVEN" if opened else "NOT_PROVEN",
        }
        if not opened:
            report.not_proven("Windows Security event source read on the runner")
        report.data["overall"] = "PASS"
    except BaseException:
        report.data["overall"] = "FAIL"
        raise
    finally:
        cleanup: dict[str, object] = {}
        for svc in cleanup_names:
            with contextlib.suppress(Exception):
                _script("uninstall", svc)
            if not _scm_absent(svc):
                _sc("stop", svc)
                _sc("delete", svc)
                time.sleep(2)
        for proc in _processes_under(work):
            _run(["taskkill.exe", "/F", "/T", "/PID", str(proc["ProcessId"])], timeout=30)
        time.sleep(1)
        cleanup["services_absent"] = all(_scm_absent(s) for s in cleanup_names)
        cleanup["collector_processes_remaining"] = len(_processes_under(work))
        shutil.rmtree(work, ignore_errors=True)
        cleanup["test_owned_temp_removed"] = not work.exists()
        report.data["cleanup"] = cleanup
        for item in (
            "MSI packaging", "enterprise deployment tooling", "production upgrade orchestrator",
            "tamper protection", "Windows version matrix beyond the runner image",
            "user's physical laptop",
        ):  # fmt: skip
            report.not_proven(item)
        report.write()
    assert cleanup["services_absent"] and cleanup["collector_processes_remaining"] == 0


def test_invoke_sc_builds_native_command_line_explicitly() -> None:
    """Regression: PS 5.1 stripped the quotes in binPath, breaking paths with spaces."""
    script = SCRIPT.read_text(encoding="utf-8")
    assert "function ConvertTo-NativeArg" in script
    assert "System.Diagnostics.ProcessStartInfo" in script
    assert "$startInfo.Arguments" in script
    assert "& sc.exe @Arguments" not in script
