import asyncio

import pytest

from mon.live import LiveEventHub, LiveMessageKind


@pytest.mark.asyncio
async def test_live_hub_isolates_tenant_site_scope() -> None:
    hub = LiveEventHub()
    first = await hub.subscribe("tenant-a", "site-1")
    second = await hub.subscribe("tenant-b", "site-1")

    await hub.publish(
        LiveMessageKind.INCIDENT_UPDATED,
        "tenant-a",
        "site-1",
        {"incident_id": "inc-1"},
    )

    message = await asyncio.wait_for(first.queue.get(), timeout=0.1)
    assert message.tenant_id == "tenant-a"
    assert message.site_id == "site-1"
    assert second.queue.empty()

    await hub.unsubscribe(first)
    await hub.unsubscribe(second)


@pytest.mark.asyncio
async def test_slow_subscriber_does_not_block_publisher() -> None:
    hub = LiveEventHub(queue_size=2)
    subscription = await hub.subscribe("tenant-a", "site-1")

    for index in range(3):
        await hub.publish(
            LiveMessageKind.ASSET_UPDATED,
            "tenant-a",
            "site-1",
            {"index": index},
        )

    assert subscription.dropped_messages == 1
    assert subscription.queue.qsize() == 2
    first = subscription.queue.get_nowait()
    second = subscription.queue.get_nowait()
    assert [first.sequence, second.sequence] == [2, 3]

    await hub.unsubscribe(subscription)
