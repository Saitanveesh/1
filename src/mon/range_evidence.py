"""Typed, tamper-evident but *self-reported* range-exercise receipts.

A hash detects accidental/tampered receipt changes; it does not prove host
identity, packet capture, attack attribution or applied containment.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExerciseSample(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    observed_at: str
    http_status: int | None = Field(default=None, ge=100, le=599)
    latency_seconds: float | None = Field(default=None, ge=0, le=10)

    @model_validator(mode="after")
    def valid_timestamp(self) -> ExerciseSample:
        instant = dt.datetime.fromisoformat(self.observed_at)
        if instant.utcoffset() is None:
            raise ValueError("sample must have timezone")
        if not (-1.0 < instant.timestamp() < 4102444800):
            raise ValueError("sample timestamp out of supported range")
        return self


class ExerciseReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    exercise_id: str = Field(min_length=4, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    tenant_id: str = Field(min_length=1, max_length=128)
    site_id: str = Field(min_length=1, max_length=128)
    approved_by: str = Field(min_length=3, max_length=128)
    target_ip: str
    started_at: str
    finished_at: str
    scenario: Literal["BOUNDED_SINGLE_SOURCE_HTTP_REQUESTS"]
    attack_claim: Literal["NONE"]
    containment_claim: Literal["NONE"]
    attempts: int = Field(ge=0, le=135)
    http_200: int = Field(ge=0, le=135)
    other_or_failed: int = Field(ge=0, le=135)
    samples: list[ExerciseSample] = Field(max_length=135)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provenance: Literal["SELF_REPORTED_EXERCISE"] = "SELF_REPORTED_EXERCISE"

    @model_validator(mode="after")
    def validate_integrity(self) -> ExerciseReceipt:
        # The runner hashes exactly these semantic fields. The fixed
        # provenance flag is transport metadata, not part of the runner payload.
        source = self.model_dump(mode="json", exclude={"sha256", "provenance"})
        digest = hashlib.sha256(
            json.dumps(source, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if digest != self.sha256:
            raise ValueError("exercise evidence sha256 mismatch")
        try:
            address = ipaddress.ip_address(self.target_ip)
            start = dt.datetime.fromisoformat(self.started_at)
            end = dt.datetime.fromisoformat(self.finished_at)
        except ValueError as exc:
            raise ValueError("invalid target/timestamps") from exc
        if address.version != 4 or not (address.is_private or address.is_loopback):
            raise ValueError("exercise target must be private or loopback")
        if start.utcoffset() is None or end.utcoffset() is None or not start <= end:
            raise ValueError("exercise timestamps invalid")
        if end - start > dt.timedelta(minutes=2):
            raise ValueError("exercise duration outside bounded limit")
        if self.attempts != len(self.samples) or (
            self.http_200 + self.other_or_failed != self.attempts
        ):
            raise ValueError("reported attempt totals do not match samples")
        if sum(s.http_status == 200 for s in self.samples) != self.http_200:
            raise ValueError("reported HTTP success count does not match samples")
        if not re.fullmatch(r"[\x20-\x7e]+", self.approved_by):
            raise ValueError("approved_by must be printable operator identity")
        for sample in self.samples:
            timestamp = dt.datetime.fromisoformat(sample.observed_at)
            if not start - dt.timedelta(seconds=2) <= timestamp <= end:
                raise ValueError("sample timestamp outside exercise")
        return self
