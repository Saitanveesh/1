from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from mon.domain import AuditRecord


class AuditIntegrityError(RuntimeError):
    """Raised when durable audit identity or content integrity is violated."""


def audit_payload_sha256(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        dict(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def audit_record_sha256(record: AuditRecord) -> str:
    return audit_payload_sha256(record.model_dump(mode="json"))
