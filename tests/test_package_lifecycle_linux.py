"""Linux .deb package lifecycle certification (disposable Ubuntu runner, root, systemd).

Requires MON_PKG_LINUX=1, MON_PKG_DEB_A / MON_PKG_DEB_B (versions 0.1.0 / 0.1.1 built
from byte-distinct collector binaries) and MON_PKG_BIN_A / MON_PKG_BIN_B. Installs a real
system package and starts a real systemd unit, so it must never run outside a disposable
VM.
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
        sys.platform == "linux"
        and os.environ.get("MON_PKG_LINUX") == "1"
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
        and all(os.environ.get(k) for k in ("MON_PKG_DEB_A", "MON_PKG_DEB_B", "MON_PKG_BIN_A", "MON_PKG_BIN_B"))
    ),
    reason="requires a disposable root Ubuntu runner (MON_PKG_LINUX=1)",
)

REPORT_PATH = Path("linux-package-lifecycle-report.json")
PKG = "mon-linux-endpoint-collector"
BIN = Path("/usr/bin/mon-linux-endpoint-collector")
UNIT = Path("/lib/systemd/system/mon-linux-endpoint-collector.service")
ENV_FILE = Path("/etc/mon-linux-endpoint-collector/collector.env")
STATE = Path("/var/lib/mon-linux-endpoint-collector")


def run(cmd: list[str], timeout: float = 180, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    if check and result.returncode != 0:
        raise AssertionError(f"{cmd} -> {result.returncode}\n{result.stdout[-800:]}\n{result.stderr[-800:]}")
    return result


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def state_hashes() -> dict[str, str]:
    return {str(p.relative_to(STATE)): sha(p) for p in sorted(STATE.rglob("*")) if p.is_file()}


def installed_version() -> str | None:
    result = run(["dpkg-query", "-W", "-f=${Version}", PKG], check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def active() -> str:
    return run(["systemctl", "is-active", PKG], check=False).stdout.strip()


def wait_active(wanted: str, seconds: float = 40) -> str:
    deadline = time.monotonic() + seconds
    state = ""
    while time.monotonic() < deadline:
        state = active()
        if state == wanted:
            return state
        time.sleep(0.5)
    return state


def test_deb_package_lifecycle(tmp_path: Path) -> None:
    deb_a, deb_b = Path(os.environ["MON_PKG_DEB_A"]), Path(os.environ["MON_PKG_DEB_B"])
    bin_a, bin_b = sha(Path(os.environ["MON_PKG_BIN_A"])), sha(Path(os.environ["MON_PKG_BIN_B"]))
    assert bin_a != bin_b
    report: dict = {
        "schema": "mon.linux-package-lifecycle.v1",
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "runner": {"platform": platform.platform(), "kernel": platform.release()},
        "package_format": "deb (dpkg-deb, unsigned)",
        "deb_sha256": {"a": sha(deb_a), "b": sha(deb_b)},
        "binary_sha256": {"a": bin_a, "b": bin_b},
        "stages": {},
        "not_proven": [
            "package/repository signing (no GPG signing key available)",
            "apt repository publication",
            "distributions other than the runner Ubuntu image",
            "auditd process-execution evidence collection under the packaged unit",
            "in-place upgrade while the service is under production load",
        ],
    }

    def stage(name: str, **facts: object) -> None:
        report["stages"][name] = {"status": "PROVEN", **facts}
        REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True))

    try:
        assert installed_version() is None, "package already installed on runner"
        # ---- static inspection of the artifact --------------------------------
        info = run(["dpkg-deb", "--info", str(deb_a)]).stdout
        contents = run(["dpkg-deb", "--contents", str(deb_a)]).stdout
        assert "Version: 0.1.0" in info and "Architecture: amd64" in info
        assert "./usr/bin/mon-linux-endpoint-collector" in contents
        assert "./lib/systemd/system/mon-linux-endpoint-collector.service" in contents
        assert "./etc/mon-linux-endpoint-collector/collector.env" in contents
        extracted = tmp_path / "x"
        run(["dpkg-deb", "-x", str(deb_a), str(extracted)])
        unit_text = (extracted / "lib/systemd/system/mon-linux-endpoint-collector.service").read_text()
        env_text = (extracted / "etc/mon-linux-endpoint-collector/collector.env").read_text()
        assert "<TENANT_ID>" not in unit_text and "EnvironmentFile=" in unit_text
        assert "User=mon-collector" in unit_text and "NoNewPrivileges=true" in unit_text
        for text in (unit_text, env_text, info):
            code_lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
            joined = "\n".join(code_lines)
            assert not re.search(r"(password|secret|token|api[_-]?key)\s*[=:]", joined, re.I)
            assert "PRIVATE KEY" not in joined
        stage("artifact_inspection", secrets_embedded=False, unit_uses_env_file=True)

        # ---- clean install -----------------------------------------------------
        run(["apt-get", "install", "-y", str(deb_a)])
        assert installed_version() == "0.1.0"
        assert sha(BIN) == bin_a
        binary_stat = BIN.stat()
        assert oct(binary_stat.st_mode & 0o7777) == "0o755" and binary_stat.st_uid == 0
        assert oct(UNIT.stat().st_mode & 0o7777) == "0o644"
        assert run(["getent", "passwd", "mon-collector"]).returncode == 0
        stage("clean_install", version="0.1.0", binary_mode="0755", owner="root",
              service_user_created=True, binary_digest_matches_candidate_a=True)  # fmt: skip

        # ---- start / status / stop ----------------------------------------------
        run(["systemctl", "start", PKG])
        assert wait_active("active") == "active"
        pid = int(run(["systemctl", "show", "-p", "MainPID", "--value", PKG]).stdout.strip())
        assert pid > 0 and os.readlink(f"/proc/{pid}/exe") == str(BIN)
        owner = run(["ps", "-o", "user=", "-p", str(pid)]).stdout.strip()
        assert owner == "mon-collector"
        deadline = time.monotonic() + 30
        while not (STATE / "linux-endpoint-buffer.db").exists() and time.monotonic() < deadline:
            time.sleep(0.5)
        assert (STATE / "linux-endpoint-buffer.db").exists()
        run(["systemctl", "stop", PKG])
        assert wait_active("inactive") == "inactive"
        before = state_hashes()
        assert "linux-endpoint-buffer.db" in before
        stage("start_status_stop", main_pid=pid, service_user=owner, state_files=sorted(before),
              stopped="inactive")  # fmt: skip

        # ---- upgrade A -> B (operator config edit must survive) ---------------------
        ENV_FILE.write_text(ENV_FILE.read_text().replace("local-tenant", "ops-edited-tenant"))
        run(["apt-get", "install", "-y", str(deb_b)])
        assert installed_version() == "0.1.1"
        assert sha(BIN) == bin_b
        assert "ops-edited-tenant" in ENV_FILE.read_text(), "conffile edit lost on upgrade"
        assert state_hashes() == before, "upgrade changed durable state"
        run(["systemctl", "start", PKG])
        assert wait_active("active") == "active"
        run(["systemctl", "stop", PKG])
        assert wait_active("inactive") == "inactive"
        stage("upgrade_a_to_b", version="0.1.1", binary_digest_matches_candidate_b=True,
              conffile_edit_preserved=True, state_unchanged_by_upgrade=True)  # fmt: skip

        # ---- rollback B -> A ------------------------------------------------------------
        run(["dpkg", "-i", str(deb_a)])
        assert installed_version() == "0.1.0" and sha(BIN) == bin_a
        assert state_hashes() == before
        run(["systemctl", "start", PKG])
        assert wait_active("active") == "active"
        run(["systemctl", "stop", PKG])
        stage("rollback_b_to_a", version="0.1.0", state_preserved=True, started_after_rollback=True)

        # ---- remove, then purge ---------------------------------------------------------
        run(["dpkg", "-r", PKG])
        assert installed_version() is None or "rc" in run(["dpkg", "-l", PKG], check=False).stdout
        assert not BIN.exists() and not UNIT.exists()
        assert ENV_FILE.exists(), "dpkg must keep conffiles on remove"
        assert state_hashes() == before
        run(["dpkg", "-P", PKG])
        assert not ENV_FILE.exists()
        assert state_hashes() == before, "purge must not delete durable state"
        status = run(["systemctl", "list-unit-files", "mon-linux-endpoint-collector.service"],
                     check=False).stdout  # fmt: skip
        assert "mon-linux-endpoint-collector.service" not in status
        stage("remove_and_purge", binary_removed=True, unit_removed=True,
              conffile_kept_on_remove=True, conffile_removed_on_purge=True,
              state_preserved_on_remove_and_purge=True)  # fmt: skip
        report["overall"] = "PASS"
    except BaseException:
        report["overall"] = "FAIL"
        raise
    finally:
        with contextlib.suppress(Exception):
            run(["systemctl", "stop", PKG], check=False)
        with contextlib.suppress(Exception):
            run(["dpkg", "-P", PKG], check=False)
        shutil.rmtree(STATE, ignore_errors=True)  # disposable runner test data
        report["cleanup"] = {
            "package_absent": installed_version() is None,
            "unit_absent": not UNIT.exists(),
            "collector_processes": len(
                [
                    p
                    for p in run(["pgrep", "-f", "/usr/bin/mon-linux-endpoint-collector"], check=False)
                    .stdout.split()
                ]
            ),
        }
        REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True))
    assert report["cleanup"]["package_absent"] and report["cleanup"]["collector_processes"] == 0
