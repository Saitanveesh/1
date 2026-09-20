"""Windows MSI package lifecycle certification (disposable Windows runner only).

Requires MON_PKG_WIN=1 plus MON_PKG_MSI_A/B (MSIs built from byte-distinct
MONWindows.exe candidates, versions 1.0.0 and 1.0.1) and MON_PKG_EXE_A/B (their
source executables, used for digest comparison). Installs a real service named
MONWindows, so it must never run outside a disposable runner.
"""

# ruff: noqa: E501
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

pytestmark = pytest.mark.skipif(
    not (
        sys.platform == "win32"
        and os.environ.get("MON_PKG_WIN") == "1"
        and all(os.environ.get(k) for k in ("MON_PKG_MSI_A", "MON_PKG_MSI_B", "MON_PKG_EXE_A", "MON_PKG_EXE_B"))
    ),
    reason="requires a disposable Windows runner (MON_PKG_WIN=1)",
)

REPORT_PATH = Path("windows-package-lifecycle-report.json")
SERVICE = "MONWindows"
INSTALL_EXE = Path(r"C:\Program Files\MON Windows Collector\MONWindows.exe")
STATE_DIR = Path(r"C:\ProgramData\MON\WindowsCollectorState")


def run(cmd: list[str], timeout: float = 180) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def ps(script: str) -> str:
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=90, env=env, check=False,
    )  # fmt: skip
    return result.stdout.strip()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def msi(action: str, path: Path, log: Path, *props: str) -> int:
    flag = "/i" if action == "install" else "/x"
    result = run(["msiexec.exe", flag, str(path), "/qn", "/norestart", "/l*v", str(log), *props])
    return result.returncode


def scm_absent() -> bool:
    return run(["sc.exe", "query", SERVICE]).returncode == 1060


def queryex() -> dict[str, object]:
    out = run(["sc.exe", "queryex", SERVICE]).stdout
    state = re.search(r"STATE\s*:\s*\d+\s+(\w+)", out)
    pid = re.search(r"PID\s*:\s*(\d+)", out)
    return {"state": state.group(1) if state else None, "pid": int(pid.group(1)) if pid else 0}


def wait_state(wanted: str, seconds: float = 40) -> str | None:
    deadline = time.monotonic() + seconds
    state = None
    while time.monotonic() < deadline:
        state = queryex()["state"]
        if state == wanted:
            return state
        time.sleep(0.5)
    return state


def qc() -> dict[str, str]:
    out = run(["sc.exe", "qc", SERVICE]).stdout
    binary = re.search(r"BINARY_PATH_NAME\s*:\s*(.+)", out)
    start = re.search(r"START_TYPE\s*:\s*\d+\s+(\w+)", out)
    return {
        "binary_path": binary.group(1).strip() if binary else "",
        "start_type": start.group(1) if start else "",
    }


def start_service() -> None:
    assert run(["sc.exe", "start", SERVICE]).returncode == 0
    assert wait_state("RUNNING") == "RUNNING"


def stop_service() -> None:
    run(["sc.exe", "stop", SERVICE])
    assert wait_state("STOPPED") == "STOPPED"
    time.sleep(1)


def state_hashes() -> dict[str, str]:
    return {
        p.name: sha(p) for p in sorted(STATE_DIR.glob("*")) if p.is_file() and p.stat().st_size >= 0
    }


def collector_processes() -> int:
    out = ps(
        "@(Get-CimInstance Win32_Process -Filter \"Name='MONWindows.exe'\" | "
        "Where-Object { $_.ExecutablePath -like 'C:\\Program Files\\MON Windows Collector\\*' }).Count"
    )
    return int(out or "0")


def authenticode(path: Path) -> str:
    return ps(f"(Get-AuthenticodeSignature -LiteralPath '{path}').Status.ToString()")


def test_windows_msi_package_lifecycle(tmp_path: Path) -> None:
    msi_a, msi_b = Path(os.environ["MON_PKG_MSI_A"]), Path(os.environ["MON_PKG_MSI_B"])
    exe_a, exe_b = sha(Path(os.environ["MON_PKG_EXE_A"])), sha(Path(os.environ["MON_PKG_EXE_B"]))
    assert exe_a != exe_b
    report: dict = {
        "schema": "mon.windows-package-lifecycle.v1",
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "runner": {"platform": platform.platform(), "version": platform.version()},
        "package_format": "MSI (WiX v5)",
        "msi_sha256": {"a": sha(msi_a), "b": sha(msi_b)},
        "exe_sha256": {"a": exe_a, "b": exe_b},
        "stages": {},
        "not_proven": [
            "production Authenticode/MSI signing",
            "enterprise deployment tooling (GPO/SCCM/Intune)",
            "in-place downgrade (blocked by design; rollback is uninstall + install)",
            "Windows versions beyond the runner image",
            "user's physical laptop",
        ],
    }
    logs = tmp_path

    def stage(name: str, **facts: object) -> None:
        report["stages"][name] = {"status": "PROVEN", **facts}
        REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True))

    try:
        assert scm_absent(), "runner already has a MONWindows service"
        signature = {"msi_a": authenticode(msi_a), "msi_b": authenticode(msi_b)}
        assert set(signature.values()) == {"NotSigned"}, signature
        stage("unsigned_state_explicit", authenticode=signature)

        # clean install
        code = msi("install", msi_a, logs / "install-a.log")
        assert code in (0, 3010), f"msiexec install exit {code}"
        config = qc()
        binary = config["binary_path"]
        assert binary.startswith(f'"{INSTALL_EXE}" service-run'), binary
        assert f"--state-dir {STATE_DIR}" in binary and "--service-name MONWindows" in binary
        assert config["start_type"] == "DEMAND_START"
        assert not re.search(r"password|token|secret|apikey", binary, re.I)
        assert sha(INSTALL_EXE) == exe_a
        assert STATE_DIR.is_dir()
        stage("clean_install", msiexec_exit=code, binary_path=binary,
              start_type=config["start_type"], exe_digest_matches_candidate_a=True,
              state_dir_created=True, credentials_in_binary_path=False)  # fmt: skip

        # start / status / stop
        start_service()
        info = queryex()
        assert collector_processes() >= 1
        deadline = time.monotonic() + 30
        while not (STATE_DIR / "windows-endpoint-buffer.db").exists() and time.monotonic() < deadline:
            time.sleep(0.5)
        assert (STATE_DIR / "windows-endpoint-buffer.db").exists()
        stop_service()
        assert collector_processes() == 0
        before = state_hashes()
        assert "windows-endpoint-buffer.db" in before
        stage("start_status_stop", service_pid=info["pid"], state_files=sorted(before))

        # upgrade A -> B (service stopped)
        code = msi("install", msi_b, logs / "upgrade-b.log")
        assert code in (0, 3010), f"msiexec upgrade exit {code}"
        assert sha(INSTALL_EXE) == exe_b
        assert qc()["binary_path"].startswith(f'"{INSTALL_EXE}" service-run')
        assert state_hashes() == before, "upgrade changed durable state"
        start_service()
        stop_service()
        stage("upgrade_a_to_b", msiexec_exit=code, exe_digest_matches_candidate_b=True,
              state_unchanged_by_upgrade=True, started_after_upgrade=True)  # fmt: skip

        # direct downgrade is blocked by design
        blocked = msi("install", msi_a, logs / "downgrade-a.log")
        assert blocked != 0 and sha(INSTALL_EXE) == exe_b
        stage("direct_downgrade_blocked", msiexec_exit=blocked)

        # rollback B -> A = uninstall B, install A, on the same preserved state
        pre_rollback = state_hashes()
        assert msi("uninstall", msi_b, logs / "remove-b.log") in (0, 3010)
        assert scm_absent() and not INSTALL_EXE.exists()
        assert state_hashes() == pre_rollback, "uninstall changed state"
        code = msi("install", msi_a, logs / "reinstall-a.log")
        assert code in (0, 3010)
        assert sha(INSTALL_EXE) == exe_a
        start_service()
        stop_service()
        assert "windows-endpoint-buffer.db" in state_hashes()
        stage("rollback_b_to_a", msiexec_exit=code, exe_digest_matches_candidate_a=True,
              state_preserved=True, started_after_rollback=True)  # fmt: skip

        # final uninstall
        preserved = state_hashes()
        assert msi("uninstall", msi_a, logs / "remove-a.log") in (0, 3010)
        assert scm_absent()
        assert not INSTALL_EXE.exists()
        assert collector_processes() == 0
        assert state_hashes() == preserved
        stage("uninstall_preserves_state", service_removed=True, binary_removed=True,
              state_files_preserved=sorted(preserved), residual_processes=0)  # fmt: skip
        report["overall"] = "PASS"
    except BaseException:
        report["overall"] = "FAIL"
        raise
    finally:
        for package in (msi_b, msi_a):
            with contextlib.suppress(Exception):
                msi("uninstall", package, logs / f"cleanup-{package.stem}.log")
        if not scm_absent():
            run(["sc.exe", "stop", SERVICE])
            run(["sc.exe", "delete", SERVICE])
        ps("Get-Process -Name MONWindows -ErrorAction SilentlyContinue | Stop-Process -Force")
        report["cleanup"] = {
            "service_absent": scm_absent(),
            "collector_processes": collector_processes(),
            "install_dir_present": INSTALL_EXE.parent.exists(),
        }
        shutil.rmtree(STATE_DIR.parent, ignore_errors=True)  # disposable runner test data
        REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True))
    assert report["cleanup"]["service_absent"] and report["cleanup"]["collector_processes"] == 0
