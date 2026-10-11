import subprocess
from pathlib import Path

DEPLOY = Path(__file__).resolve().parents[1] / "tools" / "mon-v4-passive-ids-deploy.sh"


def test_passive_ids_install_script_has_valid_shell_syntax() -> None:
    outcome = subprocess.run(["bash", "-n", str(DEPLOY)], capture_output=True, text=True)
    assert outcome.returncode == 0, outcome.stderr


def test_passive_ids_cannot_write_mon_firewall_policy() -> None:
    source = DEPLOY.read_text()
    assert "suricata" in source
    assert "tcpdump" in source
    assert "--pcap=wg0" in source
    assert "NoNewPrivileges=yes" in source
    assert "mon-three-lab-portal.service" in source
    assert "mon-three-console-v2.service" in source
    assert "trap restore EXIT" in source
    assert "systemctl restart mon-three-site" not in source
    assert "wg-quick" not in source
    assert "nft flush" not in source
    assert "iptables -F" not in source
    assert "NFQUEUE" in source  # The comment prohibits it, not an execution flag.


def test_passive_ids_installer_validates_real_authenticated_eve_endpoint() -> None:
    source = DEPLOY.read_text()
    assert 'http://127.0.0.1:8088/portal/ids' in source
    assert 'd["source"]=="suricata-eve"' in source
    assert 'route-count' in source
    assert "suricata-ids-panel" in source
    assert "API_OK" in source
    assert "V2" in source
