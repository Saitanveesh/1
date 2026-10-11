import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "mon-v2-observability-upgrade.sh"
DASH = ROOT / "monitoring/grafana-provisioning/dashboards/mon/mon-network.json"


def test_monitoring_upgrade_shell_syntax() -> None:
    p = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr


def test_monitoring_upgrade_requires_real_observed_frames_and_preserves_backend() -> None:
    s = SCRIPT.read_text()
    assert "MON_PORTAL_INTERFACE=any" in s
    assert "mon_capture_raw_frames_total" in s
    assert "AFTER-BEFORE" in s
    assert "mon_capture_packets_total" in s
    assert "sudo systemctl restart mon-three-lab-portal.service" in s
    assert "sudo docker compose" in s
    assert "mon-three-console-v2" in s
    assert "src/IncidentDetail.tsx" in s
    assert "kill -TERM" not in s
    assert "nft flush" not in s
    assert "wg-quick" not in s
    assert "systemctl restart mon-three-site-router" not in s


def test_grafana_dashboard_graphs_measured_prometheus_counters_only() -> None:
    obj = json.loads(DASH.read_text())
    expressions = [
        target["expr"]
        for panel in obj["panels"]
        for target in panel.get("targets", [])
    ]
    assert "mon_capture_up" in expressions
    assert any("rate(mon_capture_packets_total" in exp for exp in expressions)
    assert any("rate(mon_capture_bytes_total" in exp for exp in expressions)
    assert all("vector(" not in exp and "rand(" not in exp for exp in expressions)


def test_prometheus_scrape_requires_local_token() -> None:
    prom = (ROOT / "monitoring/prometheus.yml").read_text()
    assert '127.0.0.1:8088' in prom
    assert "credentials_file: /etc/prometheus/metrics-token" in prom
    compose = (ROOT / "monitoring/compose.yaml").read_text()
    assert "--web.listen-address=127.0.0.1:9090" in compose
    assert 'GF_USERS_ALLOW_SIGN_UP: "false"' in compose
