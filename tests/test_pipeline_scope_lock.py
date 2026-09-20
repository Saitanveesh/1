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


def test_response_dispatcher_serializes_dispatch_and_rollback_per_scope() -> None:
    import asyncio

    from mon.domain import ResponseRequest, ResponseTarget
    from mon.response import ResponseStateError
    from mon.response_dispatch import ResponseDispatcher

    store = _LockingStore()
    dispatcher = ResponseDispatcher(store, None, None)  # type: ignore[arg-type]

    async def run() -> None:
        request = ResponseRequest(
            request_id="r1",
            tenant_id="t",
            site_id="s",
            incident_id="i",
            target=ResponseTarget(ip_address="203.0.113.1"),
            action="BLOCK_IP",
            enforcement_point_id="fw",
            ttl_seconds=60,
            reason="x",
        )
        for call in (
            dispatcher.dispatch(request),
            dispatcher.rollback("t", "s", "r1", actor_id="a", reason="x"),
        ):
            with contextlib.suppress(Exception):  # only the lock acquisition is under test
                await call

    asyncio.run(run())
    assert store.scopes == [("t", "s"), ("t", "s")]
    store.fail = True
    try:
        asyncio.run(dispatcher.rollback("t", "s", "r1", actor_id="a", reason="x"))
    except ResponseStateError:
        return
    raise AssertionError("lock timeout must surface as ResponseStateError")
