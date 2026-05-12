# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""WazuhAlert — raw alert from Wazuh SIEM via Kafka."""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_serializer
import uuid


class WazuhAlert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)


    agent_id: str
    agent_name: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None


    rule_id: int
    rule_level: int
    rule_description: str
    rule_groups: list[str] = Field(default_factory=list)


    severity: str = "MEDIUM"
    alert_category: str = "generic"
    full_log: str = ""


    decoder_name: Optional[str] = None
    location: Optional[str] = None
    manager_name: Optional[str] = None

    model_config = {"populate_by_name": True}

    @field_serializer("timestamp")
    def _ser_ts(self, v: datetime) -> str:
        return v.isoformat()
