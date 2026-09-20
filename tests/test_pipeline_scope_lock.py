"""Regression: pipeline event processing is serialized per tenant/site when the store offers it."""

from __future__ import annotations

import contextlib
import datetime as dt

from mon.domain import SecurityEvent
from mon.pipeline import PipelineStateError, SecurityPipeline
from mon.store import InMemoryStore


class _LockingStore(InMemoryStore):
    def __init__(self, *, fail: bool = False) -> None:
        super().__init__()
        self.scopes: list[tuple[str, str]] = []
        self.fail = fail

    @contextlib.contextmanager
    def scope_lock(self, tenant_id: str, site_id: str):
        if self.fail:
            raise TimeoutError("timed out waiting for the tenant/site processing lock")
        self.scopes.append((tenant_id, site_id))
        yield


def _event() -> SecurityEvent:
    return SecurityEvent(
        event_id="lock-1",
        tenant_id="t",
        site_id="s",
        sensor_id="sensor",
        category="test.event",
        observed_at=dt.datetime.now(dt.UTC),
    )


def test_pipeline_takes_scope_lock_for_new_and_duplicate_events() -> None:
    store = _LockingStore()
    pipeline = SecurityPipeline(store=store)
    assert pipeline.process_event(_event()).duplicate is False
    assert pipeline.process_event(_event()).duplicate is True
    assert store.scopes == [("t", "s"), ("t", "s")]


def test_scope_lock_timeout_becomes_pipeline_state_error() -> None:
    pipeline = SecurityPipeline(store=_LockingStore(fail=True))
    try:
        pipeline.process_event(_event())
    except PipelineStateError:
        return
    raise AssertionError("expected PipelineStateError")
