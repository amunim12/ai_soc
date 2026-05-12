# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""AnalysisResult — output of the Log Analysis agent."""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_serializer


class AnalysisResult(BaseModel):
    alert_id: str


    is_duplicate: bool = False


    noise_filtered: bool = False


    adjusted_score: int = 0


    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)


    correlated_alert_ids: list[str] = Field(default_factory=list)
    is_burst: bool = False


    iocs: list[str] = Field(default_factory=list)
    has_iocs: bool = False


    asset_criticality: str = "LOW"
    alert_category: str = "generic"


    analysed_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"populate_by_name": True}

    @field_serializer("analysed_at")
    def _ser_ts(self, v: datetime) -> str:
        return v.isoformat()
