from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mon.domain import EventBatchResult, EventProcessingResult, SecurityEvent
from mon.sensors.suricata import SuricataEveNormalizer
from mon.sensors.zeek import ZeekJsonNormalizer
from mon.site_controller import SiteController


class ZeekSensorRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sensor_id: str = Field(min_length=1, max_length=128)
    log_type: str = Field(min_length=1, max_length=64)
    record: dict[str, Any]


class SuricataSensorRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sensor_id: str = Field(min_length=1, max_length=128)
    record: dict[str, Any]


class ZeekSensorBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    records: list[ZeekSensorRecord] = Field(min_length=1, max_length=1000)


class SuricataSensorBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    records: list[SuricataSensorRecord] = Field(min_length=1, max_length=1000)


class SiteSensorIngress:
    """Normalize raw sensor records into scoped MON events before local analysis."""

    def __init__(self, controller: SiteController) -> None:
        self.controller = controller

    def _ingest_events(self, events: list[SecurityEvent]) -> EventBatchResult:
        results: list[EventProcessingResult] = []
        accepted: list[str] = []
        for event in events:
            result = self.controller.ingest(event)
            results.append(result)
            accepted.append(event.event_id)
        return EventBatchResult(
            results=results,
            accepted_event_ids=accepted,
        )

    def ingest_zeek(self, batch: ZeekSensorBatch) -> EventBatchResult:
        # Normalize the entire batch before mutating local state so one malformed
        # raw record cannot cause a partially normalized batch.
        normalizers: dict[str, ZeekJsonNormalizer] = {}
        events: list[SecurityEvent] = []
        for item in batch.records:
            normalizer = normalizers.setdefault(
                item.sensor_id,
                ZeekJsonNormalizer(
                    self.controller.tenant_id,
                    self.controller.site_id,
                    item.sensor_id,
                ),
            )
            events.append(normalizer.normalize(item.log_type, item.record))
        return self._ingest_events(events)

    def ingest_suricata(self, batch: SuricataSensorBatch) -> EventBatchResult:
        normalizers: dict[str, SuricataEveNormalizer] = {}
        events: list[SecurityEvent] = []
        for item in batch.records:
            normalizer = normalizers.setdefault(
                item.sensor_id,
                SuricataEveNormalizer(
                    self.controller.tenant_id,
                    self.controller.site_id,
                    item.sensor_id,
                ),
            )
            events.append(normalizer.normalize(item.record))
        return self._ingest_events(events)
