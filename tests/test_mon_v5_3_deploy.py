from pathlib import Path
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "tools/mon-v5-3-flow-and-baseline-deploy.sh"

def test_v53_installer_valid_shell_and_safe_scope():
    syntax = subprocess.run(["bash", "-n", str(INSTALL)], capture_output=True, text=True)
    assert syntax.returncode == 0, syntax.stderr
    source = INSTALL.read_text()
    assert "trap restore EXIT" in source
    assert "npm run build" in source
    assert "src/IncidentFlowMap.tsx" in source
    assert "MON V5.3 exit code:" in source
    assert "mon-three-console-v2.service" in source
    assert "mon-three-lab-portal.service" in source
    for dangerous in ("wg-quick down", "nft flush", "iptables -F", "apt-get", "systemctl restart mon-three-site"):
        assert dangerous not in source

def test_grafana_baseline_is_real_prometheus_not_incident_simulation():
    path = ROOT / "monitoring/grafana-provisioning/dashboards/mon/mon-network.json"
    board = json.loads(path.read_text())
    assert board["uid"] == "mon-network"
    titles = {panel["title"]: panel for panel in board["panels"]}
    baseline = titles["Continuous traffic baseline · five-minute measured packet rate"]
    scrape = titles["Prometheus scrape health · PC2 sensor"]
    assert "mon_capture_packets_total[5m]" in baseline["targets"][0]["expr"]
    assert scrape["targets"][0]["expr"] == 'up{job="mon_pc2_capture"}'

def test_incident_flow_removes_visible_overlapping_timeline_and_playback():
    workspace = (ROOT / "console/src/IncidentWorkspace.css").read_text()
    assert ".mon-event-chain-arrow{display:none!important}" in workspace
    assert ".mon-incidents-main .aiwb-rail," in workspace
    investigation = (ROOT / "console/src/Incident3D.tsx").read_text()
    assert '<IncidentFlowMap key={id} model={model} capture={capture} />' in investigation
    scene = (ROOT / "console/src/IncidentFlowMap.tsx").read_text()
    assert "incident-3d-scene" in scene
    assert 'data-testid="mon-normal-traffic"' in scene
    assert "Recorded case sequence" not in scene
    assert "incident-play" not in scene
