# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""Audit schemas — step log and audit entry."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field, field_serializer


class StepLog(BaseModel):
    agent: str
    result: dict[str, Any] = Field(default_factory=dict)
    ts: datetime = Field(default_factory=datetime.utcnow)
    error: str | None = None

    model_config = {"populate_by_name": True}

    @field_serializer("ts")
    def _ser_ts(self, v: datetime) -> str:
        return v.isoformat()


class AuditEntry(BaseModel):
    alert_id: str
    pipeline_trace: list[StepLog] = Field(default_factory=list)
    outcome: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    analyst_id: str | None = None
    hitl_elapsed_seconds: int | None = None

    model_config = {"populate_by_name": True}

    @field_serializer("timestamp")
    def _ser_ts(self, v: datetime) -> str:
        return v.isoformat()
