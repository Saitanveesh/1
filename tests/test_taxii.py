import asyncio
import base64
import datetime as dt
import json

import httpx
import pytest

from mon.connector_secrets import ConnectorSecretKeyring, ConnectorSecretVault
from mon.database import DatabaseStore
from mon.store import InMemoryStore
from mon.taxii import (
    TAXII_ACCEPT,
    TaxiiAuthMode,
    TaxiiClient,
    TaxiiFailureClass,
    TaxiiFeedConfig,
    TaxiiFeedHealth,
    TaxiiFeedRecord,
    TaxiiFeedScheduler,
    TaxiiFeedState,
    TaxiiSecurityError,
    TaxiiSynchronizer,
)

NOW = dt.datetime(2026, 9, 19, 12, 0, tzinfo=dt.UTC)


def keyring() -> ConnectorSecretKeyring:
    return ConnectorSecretKeyring(
        active_key_id="key-a",
        keys={"key-a": b"k" * 32},
    )


def feed(
    *,
    feed_id: str = "feed-1",
    auth_mode: TaxiiAuthMode = TaxiiAuthMode.NONE,
    credential_ref: str | None = None,
    enabled: bool = True,
    max_pages_per_sync: int = 20,
    max_objects_per_sync: int = 1000,
    max_response_bytes: int = 2_000_000,
) -> TaxiiFeedRecord:
    config = TaxiiFeedConfig(
        feed_id=feed_id,
        tenant_id="tenant-a",
        site_id="site-a",
        source_id=f"source-{feed_id}",
        source_name=f"Feed {feed_id}",
        api_root_url="https://taxii.example/api-root/",
        collection_id="collection-1",
        credential_ref=credential_ref,
        auth_mode=auth_mode,
        enabled=enabled,
        poll_interval_seconds=60,
        reject_private_addresses=False,
        max_pages_per_sync=max_pages_per_sync,
        max_objects_per_sync=max_objects_per_sync,
        max_response_bytes=max_response_bytes,
        created_at=NOW,
        updated_at=NOW,
    )
    return TaxiiFeedRecord(
        config=config,
        state=TaxiiFeedState(
            feed_id=config.feed_id,
            tenant_id=config.tenant_id,
            site_id=config.site_id,
        ),
    )


def indicator(index: int, *, modified: str = "2026-09-19T00:00:00Z") -> dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--00000000-0000-4000-8000-{index:012d}",
        "created": "2026-09-19T00:00:00Z",
        "modified": modified,
        "pattern": f"[ipv4-addr:value = '203.0.113.{index}']",
        "pattern_type": "stix",
        "valid_from": "2026-09-19T00:00:00Z",
        "confidence": 80,
    }


def response(document: dict, *, content_type: str = "application/taxii+json;version=2.1"):
    return httpx.Response(200, json=document, headers={"Content-Type": content_type})


def sync_once(store, transport) -> tuple[TaxiiSynchronizer, TaxiiClient]:
    client = TaxiiClient(http_client=httpx.Client(transport=transport))
    return TaxiiSynchronizer(store, client=client, jitter=lambda: 0), client


def test_successful_taxii_collection_sync_accept_headers_and_audit() -> None:
    store = InMemoryStore()
    store.add_taxii_feed(feed())
    seen_accepts = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_accepts.append(request.headers.get("Accept"))
        if request.url.path.endswith("/collections/collection-1"):
            return response({"id": "collection-1", "can_read": True})
        assert request.url.path.endswith("/collections/collection-1/objects/")
        return response({"objects": [indicator(1)], "more": False})

    synchronizer, _ = sync_once(store, httpx.MockTransport(handler))

    result = asyncio.run(synchronizer.sync_feed("feed-1", "tenant-a", "site-a"))

    assert result.health is TaxiiFeedHealth.HEALTHY
    assert result.imported == 1
    assert result.page_count == 1
    assert seen_accepts == [TAXII_ACCEPT, TAXII_ACCEPT]
    state = store.get_taxii_feed("tenant-a", "site-a", "feed-1").state
    assert state.last_successful_sync == result.cursor
    assert state.health is TaxiiFeedHealth.HEALTHY
    audits = store.list_audit_records("tenant-a", "site-a")
    serialized = json.dumps([item.model_dump(mode="json") for item in audits])
    assert "Authorization" not in serialized
    assert "secret" not in serialized


def test_taxii_discovery_validates_configured_api_root() -> None:
    store = InMemoryStore()
    record = feed()
    record = record.model_copy(
        update={"config": record.config.model_copy(update={"discover": True})}
    )
    store.add_taxii_feed(record)
    paths = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/taxii2/":
            return response({"api_roots": ["https://taxii.example/api-root/"]})
        if request.url.path.endswith("/collections/collection-1"):
            return response({"id": "collection-1", "can_read": True})
        return response({"objects": [indicator(1)], "more": False})

    synchronizer, _ = sync_once(store, httpx.MockTransport(handler))

    result = asyncio.run(synchronizer.sync_feed("feed-1", "tenant-a", "site-a"))

    assert result.health is TaxiiFeedHealth.HEALTHY
    assert paths[0] == "/taxii2/"


def test_multipage_pagination_uses_opaque_next_and_incremental_added_after() -> None:
    store = InMemoryStore()
    record = feed()
    record = record.model_copy(
        update={
            "state": record.state.model_copy(
                update={"last_successful_sync": dt.datetime(2026, 9, 19, 1, tzinfo=dt.UTC)}
            )
        }
    )
    store.add_taxii_feed(record)
    queries = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/collections/collection-1"):
            return response({"id": "collection-1", "can_read": True})
        queries.append(dict(request.url.params))
        if "next" not in request.url.params:
            return response({"objects": [indicator(1)], "more": True, "next": "opaque/next==token"})
        assert request.url.params["next"] == "opaque/next==token"
        return response({"objects": [indicator(2)], "more": False})

    synchronizer, _ = sync_once(store, httpx.MockTransport(handler))

    result = asyncio.run(synchronizer.sync_feed("feed-1", "tenant-a", "site-a"))

    assert result.imported == 2
    assert queries[0]["added_after"] == "2026-09-19T01:00:00Z"
    assert queries[1]["next"] == "opaque/next==token"


def test_cursor_advances_only_after_successful_ingestion_and_retry_is_idempotent() -> None:
    store = InMemoryStore()
    store.add_taxii_feed(feed())
    bad = {"type": "not-indicator", "id": "malware--bad"}
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if request.url.path.endswith("/collections/collection-1"):
            return response({"id": "collection-1", "can_read": True})
        calls += 1
        objects = [bad] if calls == 1 else [indicator(1)]
        return response({"objects": objects, "more": False})

    synchronizer, _ = sync_once(store, httpx.MockTransport(handler))

    failed = asyncio.run(synchronizer.sync_feed("feed-1", "tenant-a", "site-a"))
    assert failed.health is TaxiiFeedHealth.DEGRADED
    assert failed.failure_class is TaxiiFailureClass.INGESTION
    assert store.get_taxii_feed("tenant-a", "site-a", "feed-1").state.last_successful_sync is None

    first = asyncio.run(synchronizer.sync_feed("feed-1", "tenant-a", "site-a"))
    second = asyncio.run(synchronizer.sync_feed("feed-1", "tenant-a", "site-a"))

    assert first.imported == 1
    assert second.unchanged == 1
    assert len(store.list_active_threat_indicators("tenant-a", "site-a", now=NOW)) == 1


def test_bearer_auth_uses_secret_reference_without_plaintext_persistence(tmp_path) -> None:
    store = InMemoryStore()
    vault_store = DatabaseStore(
        f"sqlite+pysqlite:///{tmp_path / 'bearer-secrets.db'}",
        create_schema=True,
    )
    try:
        vault = ConnectorSecretVault(vault_store, keyring())
        vault.put(
            tenant_id="tenant-a",
            site_id="site-a",
            secret_id="taxii-token",
            plaintext=b"super-secret-token",
            actor_id="operator-1",
            now=NOW,
        )
        store.add_taxii_feed(
            feed(
                auth_mode=TaxiiAuthMode.BEARER,
                credential_ref="taxii-token",
            )
        )

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers.get("Authorization") == "Bearer super-secret-token"
            if request.url.path.endswith("/collections/collection-1"):
                return response({"id": "collection-1", "can_read": True})
            return response({"objects": [indicator(1)], "more": False})

        client = TaxiiClient(
            http_client=httpx.Client(transport=httpx.MockTransport(handler)),
            secret_vault=vault,
        )
        synchronizer = TaxiiSynchronizer(store, client=client, jitter=lambda: 0)

        result = asyncio.run(synchronizer.sync_feed("feed-1", "tenant-a", "site-a"))

        assert result.health is TaxiiFeedHealth.HEALTHY
        serialized_feeds = json.dumps(
            [item.model_dump(mode="json") for item in store.list_taxii_feeds()],
            sort_keys=True,
        )
        serialized_audit = json.dumps(
            [
                item.model_dump(mode="json")
                for item in store.list_audit_records("tenant-a", "site-a")
            ],
            sort_keys=True,
        )
        assert "super-secret-token" not in serialized_feeds
        assert "super-secret-token" not in serialized_audit
        assert "taxii-token" in serialized_feeds
    finally:
        vault_store.close()


def test_basic_auth_uses_json_secret_reference(tmp_path) -> None:
    store = InMemoryStore()
    vault_store = DatabaseStore(
        f"sqlite+pysqlite:///{tmp_path / 'basic-secrets.db'}",
        create_schema=True,
    )
    try:
        vault = ConnectorSecretVault(vault_store, keyring())
        vault.put(
            tenant_id="tenant-a",
            site_id="site-a",
            secret_id="taxii-basic",
            plaintext=json.dumps({"username": "alice", "password": "wonder"}).encode(),
            actor_id="operator-1",
            now=NOW,
        )
        store.add_taxii_feed(
            feed(auth_mode=TaxiiAuthMode.BASIC, credential_ref="taxii-basic")
        )
        expected = "Basic " + base64.b64encode(b"alice:wonder").decode()

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers.get("Authorization") == expected
            if request.url.path.endswith("/collections/collection-1"):
                return response({"id": "collection-1", "can_read": True})
            return response({"objects": [indicator(1)], "more": False})

        client = TaxiiClient(
            http_client=httpx.Client(transport=httpx.MockTransport(handler)),
            secret_vault=vault,
        )
        synchronizer = TaxiiSynchronizer(store, client=client, jitter=lambda: 0)

        assert asyncio.run(synchronizer.sync_feed("feed-1", "tenant-a", "site-a")).imported == 1
    finally:
        vault_store.close()


@pytest.mark.parametrize(
    ("bad_config", "match"),
    [
        ({"api_root_url": "http://taxii.example/api-root/"}, "HTTPS"),
        ({"api_root_url": "https://user:pass@taxii.example/api-root/"}, "credentials"),
    ],
)
def test_url_security_rejections_by_default(bad_config, match) -> None:
    kwargs = {
        "feed_id": "bad",
        "tenant_id": "tenant-a",
        "site_id": "site-a",
        "source_id": "source-bad",
        "source_name": "Bad",
        "api_root_url": "https://taxii.example/api-root/",
        "collection_id": "collection-1",
        **bad_config,
    }
    with pytest.raises((ValueError, TaxiiSecurityError), match=match):
        TaxiiFeedConfig(**kwargs)


def test_credential_bearing_cross_origin_redirect_is_rejected(tmp_path) -> None:
    store = InMemoryStore()
    vault_store = DatabaseStore(
        f"sqlite+pysqlite:///{tmp_path / 'redirect-secrets.db'}",
        create_schema=True,
    )
    vault = ConnectorSecretVault(vault_store, keyring())
    try:
        vault.put(
            tenant_id="tenant-a",
            site_id="site-a",
            secret_id="taxii-token",
            plaintext=b"token",
            actor_id="operator-1",
            now=NOW,
        )
        store.add_taxii_feed(feed(auth_mode=TaxiiAuthMode.BEARER, credential_ref="taxii-token"))

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": "https://evil.example/steal"})

        client = TaxiiClient(
            http_client=httpx.Client(transport=httpx.MockTransport(handler)),
            secret_vault=vault,
        )
        synchronizer = TaxiiSynchronizer(store, client=client, jitter=lambda: 0)

        result = asyncio.run(synchronizer.sync_feed("feed-1", "tenant-a", "site-a"))

        assert result.health is TaxiiFeedHealth.DEGRADED
        assert result.failure_class is TaxiiFailureClass.SECURITY
    finally:
        vault_store.close()


@pytest.mark.parametrize(
    "document",
    [
        {"objects": [indicator(1)], "more": "yes"},
        {"objects": [indicator(1)], "more": True},
        {"not_objects": [], "more": False},
    ],
)
def test_malformed_taxii_envelopes_fail_safely(document) -> None:
    store = InMemoryStore()
    store.add_taxii_feed(feed())

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/collections/collection-1"):
            return response({"id": "collection-1", "can_read": True})
        return response(document)

    synchronizer, _ = sync_once(store, httpx.MockTransport(handler))

    result = asyncio.run(synchronizer.sync_feed("feed-1", "tenant-a", "site-a"))

    assert result.health is TaxiiFeedHealth.DEGRADED
    assert result.failure_class is TaxiiFailureClass.PROTOCOL


def test_limits_content_type_timeout_and_auth_failures_update_backoff() -> None:
    cases = [
        httpx.Response(200, content=b"{}", headers={"Content-Type": "text/plain"}),
        httpx.Response(401, json={}, headers={"Content-Type": "application/taxii+json"}),
        httpx.Response(429, json={}, headers={"Content-Type": "application/taxii+json"}),
        httpx.Response(500, json={}, headers={"Content-Type": "application/taxii+json"}),
        httpx.Response(
            200,
            content=b"x" * 2048,
            headers={"Content-Type": "application/taxii+json"},
        ),
    ]
    expected = [
        TaxiiFailureClass.PROTOCOL,
        TaxiiFailureClass.AUTHENTICATION,
        TaxiiFailureClass.TRANSPORT,
        TaxiiFailureClass.TRANSPORT,
        TaxiiFailureClass.PROTOCOL,
    ]
    for index, mocked in enumerate(cases):
        store = InMemoryStore()
        store.add_taxii_feed(feed(feed_id=f"feed-{index}", max_response_bytes=1024))

        def handler(request: httpx.Request, mocked=mocked) -> httpx.Response:
            return mocked

        synchronizer, _ = sync_once(store, httpx.MockTransport(handler))
        result = asyncio.run(
            synchronizer.sync_feed(f"feed-{index}", "tenant-a", "site-a")
        )

        assert result.failure_class is expected[index]
        state = store.get_taxii_feed("tenant-a", "site-a", f"feed-{index}").state
        assert state.next_attempt_after is not None
        assert state.last_successful_sync is None


def test_object_and_page_limits_fail_safely() -> None:
    cases = [
        feed(feed_id="object-limit", max_objects_per_sync=1),
        feed(feed_id="page-limit", max_pages_per_sync=1),
    ]
    for record in cases:
        store = InMemoryStore()
        store.add_taxii_feed(record)

        def handler(request: httpx.Request, feed_id=record.config.feed_id) -> httpx.Response:
            if request.url.path.endswith("/collections/collection-1"):
                return response({"id": "collection-1", "can_read": True})
            if feed_id == "object-limit":
                return response({"objects": [indicator(1), indicator(2)], "more": False})
            return response({"objects": [indicator(1)], "more": True, "next": "again"})

        synchronizer, _ = sync_once(store, httpx.MockTransport(handler))
        result = asyncio.run(
            synchronizer.sync_feed(record.config.feed_id, "tenant-a", "site-a")
        )

        assert result.health is TaxiiFeedHealth.DEGRADED
        assert result.failure_class is TaxiiFailureClass.PROTOCOL


def test_timeout_behavior_is_transport_failure() -> None:
    store = InMemoryStore()
    store.add_taxii_feed(feed())

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    synchronizer, _ = sync_once(store, httpx.MockTransport(handler))

    result = asyncio.run(synchronizer.sync_feed("feed-1", "tenant-a", "site-a"))

    assert result.failure_class is TaxiiFailureClass.TRANSPORT


def test_disabled_feed_does_not_fetch() -> None:
    store = InMemoryStore()
    store.add_taxii_feed(feed(enabled=False))

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("disabled feed should not call TAXII")

    synchronizer, _ = sync_once(store, httpx.MockTransport(handler))

    result = asyncio.run(synchronizer.sync_feed("feed-1", "tenant-a", "site-a"))

    assert result.health is TaxiiFeedHealth.DISABLED


def test_scheduler_prevents_overlap_and_one_failure_does_not_block_another() -> None:
    store = InMemoryStore()
    store.add_taxii_feed(feed(feed_id="feed-1"))
    store.add_taxii_feed(feed(feed_id="feed-2"))
    calls = {"feed-1": 0, "feed-2": 0}

    class FakeSynchronizer:
        async def sync_feed(self, feed_id: str, tenant_id: str, site_id: str):
            calls[feed_id] += 1
            if feed_id == "feed-1":
                await asyncio.sleep(0.05)
                raise RuntimeError("feed failed")
            await asyncio.sleep(0.01)

    async def run_scheduler_once():
        scheduler = TaxiiFeedScheduler(store, FakeSynchronizer(), tick_seconds=0.01)
        task = asyncio.create_task(scheduler.run())
        await asyncio.sleep(0.03)
        await scheduler.shutdown()
        await task

    asyncio.run(run_scheduler_once())

    assert calls["feed-1"] == 1
    assert calls["feed-2"] >= 1


def test_tenant_site_isolation_for_feed_state() -> None:
    store = InMemoryStore()
    store.add_taxii_feed(feed())

    assert store.get_taxii_feed("tenant-b", "site-a", "feed-1") is None
    assert store.list_taxii_feeds("tenant-a", "site-a")
    assert store.list_taxii_feeds("tenant-b", "site-a") == []
