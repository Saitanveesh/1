from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from mon.enforcement import EnforcementRegistry
from mon.pipeline import PipelinePersistenceMode, SecurityPipeline
from mon.production_site_controller import ProductionSiteController
from mon.site_analysis_store import SQLiteSiteAnalysisStore
from mon.site_api import create_site_app
from mon.site_command_client import HttpSiteCommandClient
from mon.site_command_outbox import SQLiteCommandResultOutbox
from mon.site_controller import HttpControlPlaneSender, SQLiteEventSpool
from mon.site_identity import create_mtls_client_ssl_context
from mon.site_response import SiteResponseExecutor
from mon.site_response_outbox import SQLiteResponseUpdateOutbox
from mon.site_response_store import SQLiteSiteResponseStore
from mon.site_runtime import SiteControllerRuntime


class SiteServiceConfigurationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SiteServiceConfig:
    tenant_id: str
    site_id: str
    state_dir: Path
    ingress_url: str | None = None
    bearer_token: str | None = None
    ca_certificate_file: Path | None = None
    client_certificate_file: Path | None = None
    client_private_key_file: Path | None = None
    client_private_key_password: str | None = None
    listen_host: str = "127.0.0.1"
    listen_port: int = 8090
    flush_interval_seconds: float = 5.0
    recovery_interval_seconds: float = 5.0
    command_interval_seconds: float = 2.0
    request_timeout_seconds: float = 10.0

    def validate(self) -> SiteServiceConfig:
        if not self.tenant_id.strip() or not self.site_id.strip():
            raise SiteServiceConfigurationError(
                "tenant_id and site_id must be configured"
            )
        if self.listen_port < 1 or self.listen_port > 65535:
            raise SiteServiceConfigurationError(
                "listen_port must be between 1 and 65535"
            )
        intervals = {
            "flush_interval_seconds": self.flush_interval_seconds,
            "recovery_interval_seconds": self.recovery_interval_seconds,
            "command_interval_seconds": self.command_interval_seconds,
            "request_timeout_seconds": self.request_timeout_seconds,
        }
        for name, value in intervals.items():
            if value <= 0 or value > 3600:
                raise SiteServiceConfigurationError(
                    f"{name} must be greater than 0 and at most 3600"
                )

        cloud_fields = {
            "bearer_token": self.bearer_token,
            "ca_certificate_file": self.ca_certificate_file,
            "client_certificate_file": self.client_certificate_file,
            "client_private_key_file": self.client_private_key_file,
        }
        if self.ingress_url:
            missing = [name for name, value in cloud_fields.items() if not value]
            if missing:
                raise SiteServiceConfigurationError(
                    "cloud ingress requires " + ", ".join(sorted(missing))
                )
            if not self.ingress_url.lower().startswith("https://"):
                raise SiteServiceConfigurationError(
                    "production site ingress URL must use https"
                )
            for name in (
                "ca_certificate_file",
                "client_certificate_file",
                "client_private_key_file",
            ):
                path = getattr(self, name)
                assert isinstance(path, Path)
                if not path.is_file():
                    raise SiteServiceConfigurationError(
                        f"{name} does not exist: {path}"
                    )
        elif any(cloud_fields.values()):
            raise SiteServiceConfigurationError(
                "cloud credentials cannot be configured without ingress_url"
            )

        return self

    @classmethod
    def from_environment(
        cls,
        env: Mapping[str, str] | None = None,
    ) -> SiteServiceConfig:
        values = os.environ if env is None else env

        def required(name: str) -> str:
            value = values.get(name, "").strip()
            if not value:
                raise SiteServiceConfigurationError(f"{name} is required")
            return value

        def optional_path(name: str) -> Path | None:
            value = values.get(name, "").strip()
            return Path(value) if value else None

        token_value = values.get("MON_SITE_BEARER_TOKEN", "").strip()
        token_file_value = values.get("MON_SITE_BEARER_TOKEN_FILE", "").strip()
        if token_value and token_file_value:
            raise SiteServiceConfigurationError(
                "configure only one of MON_SITE_BEARER_TOKEN or "
                "MON_SITE_BEARER_TOKEN_FILE"
            )
        bearer_token: str | None = token_value or None
        if token_file_value:
            token_file = Path(token_file_value)
            if not token_file.is_file():
                raise SiteServiceConfigurationError(
                    f"MON_SITE_BEARER_TOKEN_FILE does not exist: {token_file}"
                )
            bearer_token = token_file.read_text(encoding="utf-8").strip()
            if not bearer_token:
                raise SiteServiceConfigurationError(
                    "MON_SITE_BEARER_TOKEN_FILE is empty"
                )

        def positive_float(name: str, default: str) -> float:
            raw = values.get(name, default).strip()
            try:
                return float(raw)
            except ValueError as exc:
                raise SiteServiceConfigurationError(
                    f"{name} must be numeric"
                ) from exc

        raw_port = values.get("MON_SITE_PORT", "8090").strip()
        try:
            port = int(raw_port)
        except ValueError as exc:
            raise SiteServiceConfigurationError(
                "MON_SITE_PORT must be an integer"
            ) from exc

        ingress_url = values.get("MON_SITE_INGRESS_URL", "").strip() or None
        config = cls(
            tenant_id=required("MON_TENANT_ID"),
            site_id=required("MON_SITE_ID"),
            state_dir=Path(
                values.get("MON_SITE_STATE_DIR", "/var/lib/mon-site").strip()
                or "/var/lib/mon-site"
            ),
            ingress_url=ingress_url,
            bearer_token=bearer_token,
            ca_certificate_file=optional_path("MON_SITE_CA_CERT_FILE"),
            client_certificate_file=optional_path("MON_SITE_CLIENT_CERT_FILE"),
            client_private_key_file=optional_path("MON_SITE_CLIENT_KEY_FILE"),
            client_private_key_password=(
                values.get("MON_SITE_CLIENT_KEY_PASSWORD", "").strip() or None
            ),
            listen_host=(
                values.get("MON_SITE_HOST", "127.0.0.1").strip()
                or "127.0.0.1"
            ),
            listen_port=port,
            flush_interval_seconds=positive_float(
                "MON_SITE_FLUSH_INTERVAL_SECONDS",
                "5",
            ),
            recovery_interval_seconds=positive_float(
                "MON_SITE_RECOVERY_INTERVAL_SECONDS",
                "5",
            ),
            command_interval_seconds=positive_float(
                "MON_SITE_COMMAND_INTERVAL_SECONDS",
                "2",
            ),
            request_timeout_seconds=positive_float(
                "MON_SITE_REQUEST_TIMEOUT_SECONDS",
                "10",
            ),
        )
        return config.validate()


@dataclass(slots=True)
class SiteServiceResources:
    config: SiteServiceConfig
    controller: ProductionSiteController
    runtime: SiteControllerRuntime
    event_spool: SQLiteEventSpool
    analysis_store: SQLiteSiteAnalysisStore
    response_store: SQLiteSiteResponseStore
    command_result_outbox: SQLiteCommandResultOutbox
    response_update_outbox: SQLiteResponseUpdateOutbox

    def close(self) -> None:
        self.response_update_outbox.close()
        self.command_result_outbox.close()
        self.response_store.close()
        self.analysis_store.close()
        self.event_spool.close()


def build_site_service_resources(
    config: SiteServiceConfig,
    *,
    registry: EnforcementRegistry | None = None,
) -> SiteServiceResources:
    config.validate()
    config.state_dir.mkdir(parents=True, exist_ok=True)

    event_spool = SQLiteEventSpool(
        config.state_dir / "event-spool.db",
        tenant_id=config.tenant_id,
        site_id=config.site_id,
    )
    analysis_store = SQLiteSiteAnalysisStore(
        config.state_dir / "analysis-state.db",
        tenant_id=config.tenant_id,
        site_id=config.site_id,
    )
    response_store = SQLiteSiteResponseStore(
        config.state_dir / "response-state.db",
        tenant_id=config.tenant_id,
        site_id=config.site_id,
    )
    command_result_outbox = SQLiteCommandResultOutbox(
        config.state_dir / "command-results.db",
        tenant_id=config.tenant_id,
        site_id=config.site_id,
    )
    response_update_outbox = SQLiteResponseUpdateOutbox(
        config.state_dir / "response-updates.db",
        tenant_id=config.tenant_id,
        site_id=config.site_id,
    )

    try:
        pipeline = SecurityPipeline(
            store=analysis_store,
            persistence_mode=PipelinePersistenceMode.DURABLE_RESTORED,
        )
        pipeline.restore_scope(config.tenant_id, config.site_id)

        enforcement = registry or EnforcementRegistry()
        response_executor = SiteResponseExecutor(
            config.tenant_id,
            config.site_id,
            response_store,
            enforcement,
        )

        sender = None
        command_client = None
        if config.ingress_url is not None:
            assert config.bearer_token is not None
            assert config.ca_certificate_file is not None
            assert config.client_certificate_file is not None
            assert config.client_private_key_file is not None
            ssl_context = create_mtls_client_ssl_context(
                str(config.ca_certificate_file),
                str(config.client_certificate_file),
                str(config.client_private_key_file),
                private_key_password=config.client_private_key_password,
            )
            sender = HttpControlPlaneSender(
                config.ingress_url,
                timeout_seconds=config.request_timeout_seconds,
                bearer_token=config.bearer_token,
                ssl_context=ssl_context,
            )
            command_client = HttpSiteCommandClient(
                config.ingress_url,
                bearer_token=config.bearer_token,
                ssl_context=ssl_context,
                timeout_seconds=config.request_timeout_seconds,
            )

        controller = ProductionSiteController(
            config.tenant_id,
            config.site_id,
            event_spool,
            sender=sender,
            pipeline=pipeline,
            command_client=command_client,
            response_executor=response_executor,
            result_outbox=command_result_outbox,
            response_update_outbox=response_update_outbox,
        )
        controller.recover_pending_analysis(limit=1000)
        runtime = SiteControllerRuntime(
            controller,
            flush_interval_seconds=config.flush_interval_seconds,
            recovery_interval_seconds=config.recovery_interval_seconds,
            command_interval_seconds=config.command_interval_seconds,
        )
        return SiteServiceResources(
            config=config,
            controller=controller,
            runtime=runtime,
            event_spool=event_spool,
            analysis_store=analysis_store,
            response_store=response_store,
            command_result_outbox=command_result_outbox,
            response_update_outbox=response_update_outbox,
        )
    except Exception:
        response_update_outbox.close()
        command_result_outbox.close()
        response_store.close()
        analysis_store.close()
        event_spool.close()
        raise


def create_site_service_app(
    config: SiteServiceConfig,
    *,
    registry: EnforcementRegistry | None = None,
) -> FastAPI:
    resources = build_site_service_resources(config, registry=registry)
    stop_event = asyncio.Event()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        runtime_task = asyncio.create_task(resources.runtime.run(stop_event))
        try:
            yield
        finally:
            stop_event.set()
            try:
                await asyncio.wait_for(runtime_task, timeout=15)
            except TimeoutError:
                runtime_task.cancel()
                await asyncio.gather(runtime_task, return_exceptions=True)
            finally:
                resources.close()

    app = create_site_app(resources.controller, lifespan=lifespan)
    app.state.site_resources = resources

    @app.get("/api/v1/site/runtime")
    def runtime_status() -> dict[str, object]:
        return asdict(resources.runtime.status())

    return app


def main() -> None:
    config = SiteServiceConfig.from_environment()
    app = create_site_service_app(config)
    uvicorn.run(
        app,
        host=config.listen_host,
        port=config.listen_port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
