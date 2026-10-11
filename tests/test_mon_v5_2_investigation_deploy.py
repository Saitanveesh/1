from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "tools/mon-v5-2-investigation-deploy.sh"
GRAFANA = ROOT / "tools/mon-grafana-recover.sh"


def test_both_upgrade_scripts_have_valid_bash_syntax():
    for script in (DEPLOY, GRAFANA):
        proc = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr


def test_incidents_upgrade_preserves_everything_in_overview_and_network():
    source = DEPLOY.read_text()
    assert "src/IncidentQueue.tsx" in source
    assert "src/IncidentWorkspace.css" in source
    assert "src/IncidentEventFlow.tsx" in source
    assert "src/SocGauges.tsx" not in source
    assert "src/PacketObservability.tsx" not in source
    assert "src/styles.css" not in source
    assert "npm run build" in source
    assert "trap restore EXIT" in source
    assert "wg-quick" not in source
    assert "nft flush" not in source
    assert "iptables -F" not in source
    assert "apt-get" not in source
    assert "systemctl restart mon-three-site" not in source
    assert "systemctl restart mon-three-lab-portal" not in source


def test_grafana_recovery_is_guarded_and_does_not_overwrite_credentials():
    source = GRAFANA.read_text()
    assert "compose.yaml" in source
    assert "grafana-admin.env" in source
    assert "metrics-token" in source
    assert "docker compose" in source
    assert "api/health" in source
    assert "GF_SECURITY_ADMIN_PASSWORD" not in source
    assert "wg-quick" not in source
    assert "nft" not in source


def test_event_chain_describes_case_sequence_not_invented_hops():
    chain = (ROOT / "console/src/IncidentEventFlow.tsx").read_text()
    assert "How this incident unfolded" in chain
    assert "not a verified packet-hop trace" in chain
    assert "No response recorded" in chain
    detail = (ROOT / "console/src/IncidentDetail.tsx").read_text()
    assert 'caseTab === "events"' in detail
    assert 'caseTab === "evidence"' in detail
    assert 'caseTab === "response"' in detail
