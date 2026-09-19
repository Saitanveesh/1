import datetime as dt

import pytest

from mon.domain import SecurityEvent
from mon.pipeline import SecurityPipeline
from mon.store import InMemoryStore
from mon.threat_intel import (
    ThreatIntelError,
    ingest_stix_bundle,
    match_event_indicators,
)

NOW = dt.datetime(2026, 9, 19, 12, 0, tzinfo=dt.UTC)


def bundle(*objects):
    return {
        "type": "bundle",
        "id": "bundle--11111111-1111-4111-8111-111111111111",
        "objects": list(objects),
    }


def indicator(stix_id: str, pattern: str, **updates):
    data = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id,
        "created": "2026-09-19T00:00:00Z",
        "modified": "2026-09-19T00:00:00Z",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": "2026-09-19T00:00:00Z",
        "labels": ["malicious-activity"],
        "confidence": 70,
    }
    data.update(updates)
    return data


def event(**updates):
    data = {
        "event_id": "event-1",
        "tenant_id": "tenant-a",
        "site_id": "site-a",
        "sensor_id": "sensor-1",
        "observed_at": NOW,
        "category": "network.connection",
        "src_ip": "203.0.113.10",
        "dst_ip": "2001:db8::1",
        "protocol": "tcp",
        "attributes": {},
    }
    data.update(updates)
    return SecurityEvent(**data)


def import_bundle(store, item, *, tenant_id="tenant-a", site_id="site-a"):
    return ingest_stix_bundle(
        store,
        tenant_id=tenant_id,
        site_id=site_id,
        source_id="source-1",
        source_name="Test Feed",
        bundle=bundle(item),
        imported_at=NOW,
    )


def test_valid_stix_bundle_ingestion_and_idempotent_replay() -> None:
    store = InMemoryStore()
    item = indicator(
        "indicator--11111111-1111-4111-8111-111111111111",
        "[ipv4-addr:value = '203.0.113.10']",
    )

    first = import_bundle(store, item)
    second = import_bundle(store, item)

    assert first.imported == 1
    assert second.unchanged == 1
    indicators = store.list_active_threat_indicators("tenant-a", "site-a", now=NOW)
    assert len(indicators) == 1
    assert indicators[0].stix_id == item["id"]
    assert indicators[0].normalized_value == "203.0.113.10"


def test_stix_object_update_version_replaces_older_indicator() -> None:
    store = InMemoryStore()
    stix_id = "indicator--22222222-2222-4222-8222-222222222222"
    import_bundle(store, indicator(stix_id, "[domain-name:value = 'Example.COM']"))
    updated = indicator(
        stix_id,
        "[domain-name:value = 'example.org']",
        modified="2026-09-19T01:00:00Z",
    )

    result = import_bundle(store, updated)

    assert result.updated == 1
    stored = store.list_active_threat_indicators("tenant-a", "site-a", now=NOW)[0]
    assert stored.normalized_value == "example.org"


def test_ipv4_ipv6_domain_url_and_hash_matching_create_evidence_findings() -> None:
    store = InMemoryStore()
    items = [
        indicator(
            "indicator--33333333-3333-4333-8333-333333333331",
            "[ipv4-addr:value = '203.0.113.10']",
        ),
        indicator(
            "indicator--33333333-3333-4333-8333-333333333332",
            "[ipv6-addr:value = '2001:0db8::1']",
        ),
        indicator(
            "indicator--33333333-3333-4333-8333-333333333333",
            "[domain-name:value = 'Example.COM']",
        ),
        indicator(
            "indicator--33333333-3333-4333-8333-333333333334",
            "[url:value = 'https://Example.com/a?b=C']",
        ),
        indicator(
            "indicator--33333333-3333-4333-8333-333333333335",
            "[file:hashes.'SHA-256' = "
            "'ABCDEFabcdefABCDEFabcdefABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD']",
        ),
    ]
    ingest_stix_bundle(
        store,
        tenant_id="tenant-a",
        site_id="site-a",
        source_id="source-1",
        source_name="Test Feed",
        bundle=bundle(*items),
        imported_at=NOW,
    )

    findings = match_event_indicators(
        store,
        event(
            attributes={
                "dns_query": "example.com.",
                "url": "https://Example.com/a?b=C",
                "file_hashes": {
                    "SHA-256": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
                },
            }
        ),
        now=NOW,
    )

    assert {finding.attributes["indicator_type"] for finding in findings} == {
        "IPV4",
        "IPV6",
        "DOMAIN",
        "URL",
        "FILE_HASH",
    }
    assert all("not proof of compromise" in finding.attributes["claim"] for finding in findings)
    assert all(finding.severity.value == "MEDIUM" for finding in findings)
    assert all(finding.confidence < 1.0 for finding in findings)


def test_domain_matching_is_exact_not_substring_or_parent_match() -> None:
    store = InMemoryStore()
    import_bundle(
        store,
        indicator(
            "indicator--44444444-4444-4444-8444-444444444444",
            "[domain-name:value = 'evil.example']",
        ),
    )

    assert match_event_indicators(
        store,
        event(attributes={"dns_query": "not-evil.example"}),
        now=NOW,
    ) == []
    assert match_event_indicators(
        store,
        event(attributes={"dns_query": "sub.evil.example"}),
        now=NOW,
    ) == []


def test_expired_and_revoked_indicators_do_not_match() -> None:
    store = InMemoryStore()
    ingest_stix_bundle(
        store,
        tenant_id="tenant-a",
        site_id="site-a",
        source_id="source-1",
        source_name="Test Feed",
        bundle=bundle(
            indicator(
                "indicator--55555555-5555-4555-8555-555555555551",
                "[ipv4-addr:value = '203.0.113.10']",
                valid_until="2026-09-19T11:00:00Z",
            ),
            indicator(
                "indicator--55555555-5555-4555-8555-555555555552",
                "[ipv6-addr:value = '2001:db8::1']",
                revoked=True,
            ),
        ),
        imported_at=NOW,
    )

    assert match_event_indicators(store, event(), now=NOW) == []


def test_malformed_and_unsupported_stix_rejected() -> None:
    store = InMemoryStore()
    with pytest.raises(ThreatIntelError, match="bundle"):
        ingest_stix_bundle(
            store,
            tenant_id="tenant-a",
            site_id="site-a",
            source_id="source-1",
            source_name="Test Feed",
            bundle={"type": "not-bundle", "objects": []},
            imported_at=NOW,
        )
    with pytest.raises(ThreatIntelError, match="unsupported"):
        import_bundle(
            store,
            indicator(
                "indicator--66666666-6666-4666-8666-666666666666",
                "[process:name = 'cmd.exe']",
            ),
        )
    with pytest.raises(ThreatIntelError, match="syntax"):
        import_bundle(
            store,
            indicator(
                "indicator--77777777-7777-4777-8777-777777777777",
                "[ipv4-addr:value MATCHES '203.*']",
            ),
        )


def test_tenant_site_isolation_for_matching() -> None:
    store = InMemoryStore()
    import_bundle(
        store,
        indicator(
            "indicator--88888888-8888-4888-8888-888888888888",
            "[ipv4-addr:value = '203.0.113.10']",
        ),
        tenant_id="tenant-b",
        site_id="site-a",
    )

    assert match_event_indicators(store, event(), now=NOW) == []


def test_pipeline_persists_ti_match_finding_and_correlation_semantics() -> None:
    store = InMemoryStore()
    import_bundle(
        store,
        indicator(
            "indicator--99999999-9999-4999-8999-999999999999",
            "[ipv4-addr:value = '203.0.113.10']",
        ),
    )
    pipeline = SecurityPipeline(store=store)

    result = pipeline.process_event(event())

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.detector_id == "threat-intel-indicator-match"
    assert finding.attributes["source_name"] == "Test Feed"
    assert finding.attributes["stix_id"].startswith("indicator--")
    assert "not proof of compromise" in finding.attributes["claim"]
    assert len(result.incidents) == 1
    assert result.incidents[0].confidence < 1.0


def test_import_transaction_rolls_back_on_failed_indicator() -> None:
    class FailingStore(InMemoryStore):
        def __init__(self) -> None:
            super().__init__()
            self._snapshots = []

        def transaction(self):
            store = self

            class Transaction:
                def __enter__(self):
                    store._snapshots.append(
                        (
                            dict(store.threat_intel_sources),
                            dict(store.threat_indicators),
                        )
                    )

                def __exit__(self, exc_type, exc, tb):
                    if exc_type is not None:
                        sources, indicators = store._snapshots.pop()
                        store.threat_intel_sources = sources
                        store.threat_indicators = indicators
                    return False

            return Transaction()

        def upsert_threat_indicator(self, indicator):
            raise RuntimeError("simulated import failure")

    store = FailingStore()
    with pytest.raises(RuntimeError, match="simulated"):
        import_bundle(
            store,
            indicator(
                "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "[ipv4-addr:value = '203.0.113.10']",
            ),
        )
    assert store.threat_intel_sources == {}
    assert store.threat_indicators == {}
