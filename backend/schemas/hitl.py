# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""HITL schemas — analyst approval decision."""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_serializer

from schemas.playbook import Playbook


class ApprovalDecision(BaseModel):
    review_id: str
    action: Literal["APPROVE", "EDIT", "REJECT", "ESCALATE"]
    analyst_id: str = "system"
    notes: str = ""
    final_playbook: Optional[Playbook] = None
    elapsed_seconds: int = 0
    decided_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"populate_by_name": True}

    @field_serializer("decided_at")
    def _ser_ts(self, v: datetime) -> str:
        return v.isoformat()
