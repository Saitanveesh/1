from pathlib import Path
import subprocess
import json

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/mon-v5-full-soc-deploy.sh"


def test_v5_deployment_has_valid_bash_syntax():
    result = subprocess.run(["bash", "-n", str(SCRIPT)], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


def test_v5_does_not_mutate_core_router_configuration():
    text = SCRIPT.read_text()
    assert "Incident3D.tsx" in text
    assert "SocGauges.tsx" in text
    assert "mon-incident-pcap.sh" in text
    assert "mon-three-console-v2.service" in text
    assert "mon-three-lab-portal.service" in text
    assert "trap restore EXIT" in text
    assert "wg-quick" not in text
    assert "nft flush" not in text
    assert "iptables -F" not in text
    assert "systemctl restart mon-three-site" not in text


def test_grafana_dashboard_uses_observed_metrics_and_real_gauges():
    dashboard = json.loads(
        (ROOT / "monitoring/grafana-provisioning/dashboards/mon/mon-network.json").read_text()
    )
    expressions = [t["expr"] for p in dashboard["panels"] for t in p.get("targets", [])]
    assert any(p["type"] == "gauge" for p in dashboard["panels"])
    assert any(p["type"] == "bargauge" for p in dashboard["panels"])
    assert "mon_capture_up" in expressions
    assert any("mon_capture_packets_total" in expr for expr in expressions)
    assert any("mon_capture_bytes_total" in expr for expr in expressions)
    assert not any("vector(" in expr or "rand(" in expr for expr in expressions)


def test_optional_log_stack_local_only_with_retention():
    config = (ROOT / "monitoring/logging/loki-config.yaml").read_text()
    assert "http_listen_address: 127.0.0.1" in config
    assert "retention_period: 168h" in config
    alloy = (ROOT / "monitoring/logging/alloy.config").read_text()
    assert "loki.source.file" in alloy
    assert "eve.json" in alloy
    assert "loki.write" in alloy
    pcap = (ROOT / "tools/mon-incident-pcap.sh").read_text()
    assert "AUTHORIZE PCAP 30S" in pcap
    assert "10.77.0.60" in pcap and "10.77.0.50" in pcap
