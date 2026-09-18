from fastapi.testclient import TestClient

from mon.site_api import create_site_app
from mon.site_controller import SiteController, SQLiteEventSpool


def test_site_health_exposes_offline_queue_state(tmp_path) -> None:
    spool = SQLiteEventSpool(tmp_path / "spool.db")
    controller = SiteController("t1", "s1", spool)
    client = TestClient(create_site_app(controller))

    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["tenant_id"] == "t1"
    assert response.json()["cloud_sender_configured"] is False
    assert response.json()["spool"]["queued"] == 0
    spool.close()
