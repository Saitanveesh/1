"""Mocked safety and recovery checks; never touches the host's actual services."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "mon-three-labctl.sh"


class LabCtlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.home = self.base / "home"
        (self.home / "mon-three" / "identity").mkdir(parents=True)
        (self.home / "mon-three" / "identity" / "operator.jwt").write_text("safe-fake-test-token\n")
        self.log = self.base / "cmd.log"
        self.docker_state = self.base / "docker_started"
        self.env = os.environ.copy()
        self.env.update(
            PATH=f"{self.bin}:{os.environ['PATH']}", HOME=str(self.home),
            FAKE_LOG=str(self.log), FAKE_ROLE="pc-7", FAKE_HTTP="200",
            FAKE_DOCKER_STATE=str(self.docker_state),
        )
        self.mock("id", """#!/bin/sh
if [ "$1" = -un ]; then echo "$FAKE_ROLE"; else /usr/bin/id "$@"; fi
""")
        self.mock("sudo", """#!/bin/sh
printf 'sudo %s\\n' "$*" >> "$FAKE_LOG"
exec "$@"
""")
        self.mock("systemctl", """#!/bin/sh
printf 'systemctl %s\\n' "$*" >> "$FAKE_LOG"
exit "${FAKE_SYSTEMCTL_RC:-0}"
""")
        self.mock("ip", """#!/bin/sh
printf 'inet 10.77.0.%s/32 scope global wg0\\n' "${FAKE_WG_LAST:-70}"
""")
        self.mock("ping", "#!/bin/sh\nexit 0\n")
        self.mock("curl", """#!/bin/sh
printf 'curl called\\n' >> "$FAKE_LOG"
codeonly=0
for arg in "$@"; do
  if [ "$arg" = --write-out ]; then codeonly=1; fi
done
if [ "$codeonly" = 0 ]; then
  for arg in "$@"; do
    case "$arg" in
      *portal/health*) echo '{"state":"READY","capture":"CAPTURING"}'; exit 0;;
      *8085/health*) echo '{"status":"READY","training":true,"version":4}'; exit 0;;
    esac
  done
fi
for arg in "$@"; do
  case "$arg" in *api/v1/me*) echo "${FAKE_ME:-200}"; exit 0;;
      *api/v1/live/snapshot*) echo "${FAKE_SNAPSHOT:-200}"; exit 0;; esac
done
echo "$FAKE_HTTP"
""")
        self.mock("docker", """#!/bin/sh
printf 'docker %s\\n' "$*" >> "$FAKE_LOG"
if [ "$1" = inspect ]; then
  case "$2" in --format)
    if [ -f "$FAKE_DOCKER_STATE" ]; then echo true; else echo "${FAKE_DOCKER_RUNNING:-true}"; fi;;
  esac
fi
if [ "$1" = start ]; then touch "$FAKE_DOCKER_STATE"; fi
exit 0
""")
        self.mock("ssh", """#!/bin/sh
printf 'ssh %s\\n' "$*" >> "$FAKE_LOG"
exit 0
""")

    def mock(self, command: str, content: str) -> None:
        path = self.bin / command
        path.write_text(content)
        path.chmod(0o755)

    def run_ctl(self, arg: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(SCRIPT), arg], env=self.env, capture_output=True,
            text=True, timeout=12,
        )

    def test_shell_syntax(self) -> None:
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)

    def test_renew_token_code_syntax(self) -> None:
        source = SCRIPT.read_text()
        code = source.split("<<'PYJWT'\n", 1)[1].split("\nPYJWT", 1)[0]
        compile(code, "embedded-token-renewal", "exec")

    def test_pc7_status_is_read_only(self) -> None:
        result = self.run_ctl("status")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("READY", result.stdout)
        log = self.log.read_text()
        self.assertNotIn("systemctl start", log)
        self.assertNotIn("docker start", log)
        self.assertNotIn("sudo ", log)

    def test_pc7_start_only_existing_service_and_no_attack(self) -> None:
        result = self.run_ctl("start")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        log = self.log.read_text()
        self.assertIn("systemctl start mon-batch2-attack-console.service", log)
        self.assertNotIn("docker start", log)
        self.assertNotIn("nft", log)
        self.assertNotIn("attack.py", log)

    def test_pc2_starts_existing_database_not_a_new_one(self) -> None:
        self.env.update(FAKE_ROLE="pc-2", FAKE_WG_LAST="1", FAKE_DOCKER_RUNNING="false")
        result = self.run_ctl("start")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        log = self.log.read_text()
        self.assertIn("docker start mon-three-postgres", log)
        self.assertNotIn("docker run", log)
        self.assertNotIn("docker rm", log)
        self.assertIn("systemctl start mon-stage4-gate.service", log)

    def test_snapshot_500_fails_closed(self) -> None:
        self.env.update(FAKE_ROLE="pc-2", FAKE_WG_LAST="1", FAKE_SNAPSHOT="500")
        result = self.run_ctl("status")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HTTP 500", result.stderr)
        self.assertNotIn("READY: verified", result.stdout)

    def test_invalid_user_rejected_without_mutations(self) -> None:
        self.env["FAKE_ROLE"] = "student"
        result = self.run_ctl("start")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())

    def test_start_all_reports_ssh_unavailable(self) -> None:
        self.env.update(FAKE_ROLE="pc-2", FAKE_WG_LAST="1")
        self.mock("ssh", "#!/bin/sh\nexit 255\n")
        result = self.run_ctl("start-all")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("node(s) failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
