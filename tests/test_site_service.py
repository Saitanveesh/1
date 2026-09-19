from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mon.site_service import (
    SiteServiceConfig,
    SiteServiceConfigurationError,
    build_site_service_resources,
    create_site_service_app,
)


def offline_config(tmp_path) -> SiteServiceConfig:
    return SiteServiceConfig(
        tenant_id="tenant-a",
        site_id="site-a",
        state_dir=tmp_path / "state",
        flush_interval_seconds=0.01,
        recovery_interval_seconds=0.01,
        command_interval_seconds=0.01,
    ).validate()


def test_offline_site_service_builds_all_durable_state(tmp_path) -> None:
    config = offline_config(tmp_path)
    resources = build_site_service_resources(config)
    try:
        status = resources.controller.status()
        assert status["tenant_id"] == "tenant-a"
        assert status["site_id"] == "site-a"
        assert status["cloud_sender_configured"] is False
        assert status["command_channel_configured"] is False
        assert status["local_recovery_configured"] is True
        assert status["spool"]["durability"] == "WAL_FULL"
        assert status["local_pipeline_state_persistence"] == "MEMORY_ONLY"
        assert resources.response_store.diagnostics()["tenant_id"] == "tenant-a"
        assert resources.command_result_outbox.diagnostics()["queued"] == 0
        assert resources.response_update_outbox.diagnostics()["queued"] == 0
        for name in (
            "event-spool.db",
            "response-state.db",
            "command-results.db",
            "response-updates.db",
        ):
            assert (config.state_dir / name).is_file()
    finally:
        resources.close()


def test_site_service_state_files_are_bound_to_original_scope(tmp_path) -> None:
    config = offline_config(tmp_path)
    resources = build_site_service_resources(config)
    resources.close()

    foreign = SiteServiceConfig(
        tenant_id="tenant-b",
        site_id="site-a",
        state_dir=config.state_dir,
    )
    with pytest.raises(ValueError, match="tenant_id mismatch"):
        build_site_service_resources(foreign)


def test_cloud_configuration_requires_https_and_complete_mtls_identity(tmp_path) -> None:
    base = dict(
        tenant_id="tenant-a",
        site_id="site-a",
        state_dir=tmp_path,
        ingress_url="https://control.example",
    )
    with pytest.raises(SiteServiceConfigurationError, match="cloud ingress requires"):
        SiteServiceConfig(**base).validate()

    with pytest.raises(SiteServiceConfigurationError, match="must use https"):
        SiteServiceConfig(
            tenant_id="tenant-a",
            site_id="site-a",
            state_dir=tmp_path,
            ingress_url="http://control.example",
            bearer_token="token",
            ca_certificate_file=tmp_path / "ca.pem",
            client_certificate_file=tmp_path / "site.pem",
            client_private_key_file=tmp_path / "site-key.pem",
        ).validate()


def test_environment_loader_supports_token_file_without_exposing_secret(tmp_path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("site-secret\n", encoding="utf-8")
    ca = tmp_path / "ca.pem"
    cert = tmp_path / "site.pem"
    key = tmp_path / "site-key.pem"
    for path in (ca, cert, key):
        path.write_text("test fixture", encoding="utf-8")

    config = SiteServiceConfig.from_environment(
        {
            "MON_TENANT_ID": "tenant-a",
            "MON_SITE_ID": "site-a",
            "MON_SITE_STATE_DIR": str(tmp_path / "state"),
            "MON_SITE_INGRESS_URL": "https://control.example",
            "MON_SITE_BEARER_TOKEN_FILE": str(token_file),
            "MON_SITE_CA_CERT_FILE": str(ca),
            "MON_SITE_CLIENT_CERT_FILE": str(cert),
            "MON_SITE_CLIENT_KEY_FILE": str(key),
        }
    )
    assert config.bearer_token == "site-secret"
    assert config.ingress_url == "https://control.example"

    with pytest.raises(SiteServiceConfigurationError, match="only one"):
        SiteServiceConfig.from_environment(
            {
                "MON_TENANT_ID": "tenant-a",
                "MON_SITE_ID": "site-a",
                "MON_SITE_BEARER_TOKEN": "inline",
                "MON_SITE_BEARER_TOKEN_FILE": str(token_file),
            }
        )


def test_site_service_app_runs_managed_runtime_and_exposes_status(tmp_path) -> None:
    app = create_site_service_app(offline_config(tmp_path))
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["tenant_id"] == "tenant-a"

        runtime = client.get("/api/v1/site/runtime")
        assert runtime.status_code == 200
        payload = runtime.json()
        assert set(payload) >= {
            "last_flush_state",
            "last_recovery_state",
            "last_command_state",
        }


def test_environment_loader_rejects_invalid_numeric_configuration(tmp_path) -> None:
    with pytest.raises(SiteServiceConfigurationError, match="must be an integer"):
        SiteServiceConfig.from_environment(
            {
                "MON_TENANT_ID": "tenant-a",
                "MON_SITE_ID": "site-a",
                "MON_SITE_STATE_DIR": str(tmp_path),
                "MON_SITE_PORT": "not-a-port",
            }
        )

    with pytest.raises(SiteServiceConfigurationError, match="must be numeric"):
        SiteServiceConfig.from_environment(
            {
                "MON_TENANT_ID": "tenant-a",
                "MON_SITE_ID": "site-a",
                "MON_SITE_STATE_DIR": str(Path(tmp_path)),
                "MON_SITE_FLUSH_INTERVAL_SECONDS": "bad",
            }
        )
