from __future__ import annotations

from typing import Protocol

from mon.domain import (
    IdentityConfidence,
    IdentityRecord,
    ProcessConfidence,
    ProcessRecord,
    SecurityEvent,
)
from mon.endpoint import identity_id_for, identity_key, process_id_for


class IdentityProcessStore(Protocol):
    def get_identity(
        self,
        tenant_id: str,
        site_id: str,
        identity_id: str,
    ) -> IdentityRecord | None: ...

    def add_identity(self, identity: IdentityRecord) -> IdentityRecord: ...

    def get_process(
        self,
        tenant_id: str,
        site_id: str,
        process_id: str,
    ) -> ProcessRecord | None: ...

    def add_process(self, process: ProcessRecord) -> ProcessRecord: ...


def _text(value: object, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(character for character in value.strip() if character.isprintable())
    return cleaned[:limit] if cleaned else None


class IdentityProcessEngine:
    def __init__(self, store: IdentityProcessStore) -> None:
        self.store = store

    def observe(
        self,
        event: SecurityEvent,
    ) -> tuple[IdentityRecord | None, ProcessRecord | None]:
        identity = self._observe_identity(event)
        process = self._observe_process(event, identity)
        return identity, process

    def _observe_identity(self, event: SecurityEvent) -> IdentityRecord | None:
        source, principal, domain, asset_id = identity_key(event)
        if source is None:
            return None
        weak = event.attributes.get("identity_confidence") == IdentityConfidence.WEAK.value
        identity_id = identity_id_for(
            event.tenant_id,
            event.site_id,
            source,
            principal,
            domain,
            asset_id,
            weak=weak,
        )
        existing = self.store.get_identity(event.tenant_id, event.site_id, identity_id)
        evidence_ids = {item.evidence_id for item in event.evidence}
        confidence = IdentityConfidence.WEAK if weak else IdentityConfidence.STRONG
        if existing is None:
            return self.store.add_identity(
                IdentityRecord(
                    identity_id=identity_id,
                    tenant_id=event.tenant_id,
                    site_id=event.site_id,
                    kind=source,
                    source=source,
                    principal=principal,
                    display_name=_text(event.attributes.get("identity_display_name"), 512),
                    domain=domain,
                    asset_id=asset_id if weak else None,
                    confidence=confidence,
                    evidence_basis=_text(
                        event.attributes.get("identity_evidence_basis"),
                        500,
                    )
                    or "endpoint identity observation",
                    first_seen=event.observed_at,
                    last_seen=event.observed_at,
                    evidence_ids=evidence_ids,
                )
            )
        return self.store.add_identity(
            existing.model_copy(
                update={
                    "display_name": existing.display_name
                    or _text(event.attributes.get("identity_display_name"), 512),
                    "first_seen": min(existing.first_seen, event.observed_at),
                    "last_seen": max(existing.last_seen, event.observed_at),
                    "evidence_ids": existing.evidence_ids | evidence_ids,
                }
            )
        )

    def _observe_process(
        self,
        event: SecurityEvent,
        identity: IdentityRecord | None,
    ) -> ProcessRecord | None:
        if not event.category.casefold().startswith("endpoint."):
            return None
        process_id = process_id_for(event)
        if process_id is None or event.asset_id is None:
            return None
        existing = self.store.get_process(event.tenant_id, event.site_id, process_id)
        evidence_ids = {item.evidence_id for item in event.evidence}
        process_guid = _text(event.attributes.get("process_guid"), 256)
        process_hashes = event.attributes.get("process_hashes")
        if not isinstance(process_hashes, dict):
            process_hashes = {}
        confidence = (
            ProcessConfidence.STRONG
            if process_guid
            else ProcessConfidence.OBSERVATIONAL
        )
        parent_guid = _text(event.attributes.get("parent_process_guid"), 256)
        parent_process_id = None
        if parent_guid:
            parent_event = event.model_copy(
                update={"attributes": {**event.attributes, "process_guid": parent_guid}}
            )
            parent_process_id = process_id_for(parent_event)
        if existing is None:
            return self.store.add_process(
                ProcessRecord(
                    process_id=process_id,
                    tenant_id=event.tenant_id,
                    site_id=event.site_id,
                    asset_id=event.asset_id,
                    identity_id=identity.identity_id if identity else None,
                    parent_process_id=parent_process_id,
                    source_process_guid=process_guid,
                    pid=event.attributes.get("process_pid")
                    if isinstance(event.attributes.get("process_pid"), int)
                    else None,
                    session_id=_text(event.attributes.get("session_id"), 256),
                    image=_text(event.attributes.get("image"), 1000),
                    command_line=_text(event.attributes.get("command_line"), 1000),
                    hashes={
                        str(key): str(value)
                        for key, value in process_hashes.items()
                        if isinstance(key, str) and isinstance(value, str)
                    },
                    confidence=confidence,
                    evidence_basis=(
                        "source process GUID"
                        if confidence is ProcessConfidence.STRONG
                        else "PID scoped to asset/session/event time"
                    ),
                    first_seen=event.observed_at,
                    last_seen=event.observed_at,
                    evidence_ids=evidence_ids,
                )
            )
        return self.store.add_process(
            existing.model_copy(
                update={
                    "identity_id": existing.identity_id
                    or (identity.identity_id if identity else None),
                    "parent_process_id": existing.parent_process_id
                    or parent_process_id,
                    "image": existing.image or _text(event.attributes.get("image"), 1000),
                    "command_line": existing.command_line
                    or _text(event.attributes.get("command_line"), 1000),
                    "first_seen": min(existing.first_seen, event.observed_at),
                    "last_seen": max(existing.last_seen, event.observed_at),
                    "evidence_ids": existing.evidence_ids | evidence_ids,
                }
            )
        )
