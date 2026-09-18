from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mon.domain import EventProcessingResult, utcnow


class LiveMessageKind(StrEnum):
    STREAM_READY = "stream.ready"
    HEARTBEAT = "stream.heartbeat"
    EVENT_PROCESSED = "event.processed"
    ASSET_UPDATED = "asset.updated"
    INCIDENT_UPDATED = "incident.updated"
    ENFORCEMENT_UPDATED = "enforcement.updated"
    RESPONSE_PLANNED = "response.planned"


class LiveEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: LiveMessageKind
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    sequence: int = Field(ge=0)
    emitted_at: object = Field(default_factory=utcnow)
    payload: dict[str, Any] = Field(default_factory=dict)


@dataclass
class LiveSubscription:
    subscription_id: str
    tenant_id: str
    site_id: str
    queue: asyncio.Queue[LiveEnvelope]
    dropped_messages: int = 0


class LiveEventHub:
    """In-process non-blocking live fan-out.

    Ingestion never waits for a browser. Each subscriber has a bounded queue; if a
    subscriber falls behind, the oldest queued message is dropped and the drop count
    is exposed in heartbeats. A broker-backed implementation can replace this class
    when the control plane is scaled to multiple replicas.
    """

    def __init__(self, queue_size: int = 256) -> None:
        if queue_size < 1:
            raise ValueError("queue_size must be positive")
        self.queue_size = queue_size
        self._subscribers: dict[
            tuple[str, str], dict[str, LiveSubscription]
        ] = defaultdict(dict)
        self._sequence: dict[tuple[str, str], int] = defaultdict(int)
        self._lock = asyncio.Lock()

    def reset(self) -> None:
        if any(self._subscribers.values()):
            raise RuntimeError("cannot reset live hub with active subscribers")
        self._subscribers.clear()
        self._sequence.clear()

    async def subscribe(self, tenant_id: str, site_id: str) -> LiveSubscription:
        subscription = LiveSubscription(
            subscription_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            site_id=site_id,
            queue=asyncio.Queue(maxsize=self.queue_size),
        )
        async with self._lock:
            self._subscribers[(tenant_id, site_id)][subscription.subscription_id] = (
                subscription
            )
        return subscription

    async def unsubscribe(self, subscription: LiveSubscription) -> None:
        async with self._lock:
            scope = (subscription.tenant_id, subscription.site_id)
            self._subscribers[scope].pop(subscription.subscription_id, None)
            if not self._subscribers[scope]:
                self._subscribers.pop(scope, None)

    async def current_sequence(self, tenant_id: str, site_id: str) -> int:
        async with self._lock:
            return self._sequence[(tenant_id, site_id)]

    async def ready_envelope(self, tenant_id: str, site_id: str) -> LiveEnvelope:
        sequence = await self.current_sequence(tenant_id, site_id)
        return LiveEnvelope(
            kind=LiveMessageKind.STREAM_READY,
            tenant_id=tenant_id,
            site_id=site_id,
            sequence=sequence,
            payload={
                "transport": "websocket",
                "queue_size": self.queue_size,
                "mode": "push",
            },
        )

    async def heartbeat_envelope(
        self,
        subscription: LiveSubscription,
    ) -> LiveEnvelope:
        sequence = await self.current_sequence(
            subscription.tenant_id,
            subscription.site_id,
        )
        return LiveEnvelope(
            kind=LiveMessageKind.HEARTBEAT,
            tenant_id=subscription.tenant_id,
            site_id=subscription.site_id,
            sequence=sequence,
            payload={"dropped_messages": subscription.dropped_messages},
        )

    async def publish(
        self,
        kind: LiveMessageKind,
        tenant_id: str,
        site_id: str,
        payload: dict[str, Any],
    ) -> LiveEnvelope:
        scope = (tenant_id, site_id)
        async with self._lock:
            self._sequence[scope] += 1
            envelope = LiveEnvelope(
                kind=kind,
                tenant_id=tenant_id,
                site_id=site_id,
                sequence=self._sequence[scope],
                payload=payload,
            )
            subscriptions = list(self._subscribers.get(scope, {}).values())

            for subscription in subscriptions:
                if subscription.queue.full():
                    subscription.queue.get_nowait()
                    subscription.dropped_messages += 1
                subscription.queue.put_nowait(envelope)

        return envelope

    async def publish_processing_result(
        self,
        result: EventProcessingResult,
        *,
        processing_ms: float,
    ) -> LiveEnvelope | None:
        if result.duplicate:
            return None
        return await self.publish(
            LiveMessageKind.EVENT_PROCESSED,
            result.event.tenant_id,
            result.event.site_id,
            {
                "processing_ms": round(processing_ms, 3),
                "result": result.model_dump(mode="json"),
            },
        )
