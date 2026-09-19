from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from mon.domain import EventProcessingResult
from mon.event_fabric import (
    FabricEnvelope,
    FabricIngestResult,
    FabricReceipt,
    FabricReceiptStatus,
    security_event_from_envelope,
)
from mon.pipeline import SecurityPipeline
from mon.store import Store, TransactionalPipelineStore


class FabricEnvelopeCollision(ValueError):
    pass


class FabricProcessingUncertain(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class FabricIngressOutcome:
    acknowledgement: FabricIngestResult
    processing_result: EventProcessingResult | None


def ingest_fabric_envelope(
    store: Store,
    pipeline: SecurityPipeline,
    envelope: FabricEnvelope,
    *,
    received_at: dt.datetime | None = None,
) -> FabricIngressOutcome:
    """Claim and process one exact fabric envelope.

    The exact-envelope claim is durable before domain processing. A failed
    processing attempt leaves a PENDING claim so a different envelope cannot
    reuse the same event ID. For transactional stores, a committed event
    processing receipt proves whether a crash completed the domain mutation.
    """

    event = security_event_from_envelope(envelope)
    canonical = envelope.canonical_json()
    digest = envelope.canonical_sha256
    accepted_at = received_at or dt.datetime.now(dt.UTC)
    if accepted_at.tzinfo is None or accepted_at.utcoffset() is None:
        raise ValueError("fabric ingress received_at must be timezone-aware")
    accepted_at = accepted_at.astimezone(dt.UTC)

    existing_event = store.get_event(
        event.tenant_id,
        event.site_id,
        event.event_id,
    )
    if existing_event is not None and existing_event != event:
        raise FabricEnvelopeCollision(
            "fabric event_id already exists with different event content"
        )

    try:
        receipt = store.add_fabric_receipt(
            FabricReceipt(
                event_id=envelope.event_id,
                tenant_id=envelope.tenant_id,
                site_id=envelope.site_id,
                envelope_sha256=digest,
                envelope_json=canonical,
                status=FabricReceiptStatus.PENDING,
                received_at=accepted_at,
            )
        )
    except ValueError as exc:
        raise FabricEnvelopeCollision(str(exc)) from exc

    if (
        receipt.envelope_sha256 != digest
        or receipt.envelope_json != canonical
    ):
        raise FabricEnvelopeCollision(
            "fabric event_id is already claimed by a different envelope"
        )

    if receipt.status is FabricReceiptStatus.PROCESSED:
        return FabricIngressOutcome(
            acknowledgement=FabricIngestResult(
                event_id=envelope.event_id,
                duplicate=True,
                envelope_sha256=digest,
            ),
            processing_result=None,
        )

    existing_event = store.get_event(
        event.tenant_id,
        event.site_id,
        event.event_id,
    )
    if existing_event is not None:
        if existing_event != event:
            raise FabricEnvelopeCollision(
                "fabric event_id already exists with different event content"
            )
        if isinstance(store, TransactionalPipelineStore) and not store.event_processed(
            event.tenant_id,
            event.site_id,
            event.event_id,
        ):
            raise FabricProcessingUncertain(
                "event exists without a completed processing receipt"
            )
        store.complete_fabric_receipt(
            envelope.tenant_id,
            envelope.site_id,
            envelope.event_id,
            processed_at=dt.datetime.now(dt.UTC),
        )
        return FabricIngressOutcome(
            acknowledgement=FabricIngestResult(
                event_id=envelope.event_id,
                duplicate=True,
                envelope_sha256=digest,
            ),
            processing_result=None,
        )

    result = pipeline.process_event(event)
    if isinstance(store, TransactionalPipelineStore) and not store.event_processed(
        event.tenant_id,
        event.site_id,
        event.event_id,
    ):
        raise FabricProcessingUncertain(
            "event processing returned without a durable processing receipt"
        )

    store.complete_fabric_receipt(
        envelope.tenant_id,
        envelope.site_id,
        envelope.event_id,
        processed_at=dt.datetime.now(dt.UTC),
    )
    return FabricIngressOutcome(
        acknowledgement=FabricIngestResult(
            event_id=envelope.event_id,
            duplicate=result.duplicate,
            envelope_sha256=digest,
        ),
        processing_result=result,
    )
