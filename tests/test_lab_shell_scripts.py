from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = [
    REPO / "tools" / "lab-ssh-orchestrator.sh",
    REPO / "tools" / "lab-pc2-remote-readiness.sh",
]


@pytest.mark.parametrize("script", SCRIPTS)
def test_lab_shell_syntax(script: Path) -> None:
    """Catch shell parsing errors without contacting any lab PCs."""
    if not shutil.which("bash"):
        pytest.skip("bash unavailable")
    completed = subprocess.run(
        ["bash", "-n", str(script)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_lab_ssh_script_has_no_unattended_isolation() -> None:
    source = (REPO / "tools" / "lab-ssh-orchestrator.sh").read_text()
    assert 'read -r -p "Type ISOLATE to proceed: "' in source
    assert "PC6" in source
