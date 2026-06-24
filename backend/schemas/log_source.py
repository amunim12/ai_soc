# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


SourceType = Literal["agent", "syslog", "windows_event", "api", "network", "cloud"]
OsType = Literal["windows", "linux", "macos", "network", "cloud"]
WazuhStatus = Literal["active", "disconnected", "never_connected", "pending", "unknown"]

AVAILABLE_SOAR_ACTIONS = [
    "block_ip",
    "isolate_host",
    "disable_user",
    "kill_process",
    "collect_forensics",
    "restart_service",
    "run_vulnerability_scan",
]


class LogSourceBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str = Field("", max_length=512)
    source_type: SourceType = "agent"
    host: str = Field(..., min_length=1, max_length=255,
                      description="IP address or hostname of the source")
    os_type: Optional[OsType] = None
    soar_enabled: bool = False
    soar_actions: List[str] = Field(
        default_factory=list,
        description="Actions Shuffle SOAR can execute on this source",
    )
    soar_target_label: Optional[str] = Field(
        None, max_length=128,
        description="Asset label used in Shuffle to identify this host",
    )
    tags: List[str] = Field(default_factory=list)


class LogSourceCreate(LogSourceBase):
    pass


class LogSourceUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=512)
    source_type: Optional[SourceType] = None
    host: Optional[str] = Field(None, min_length=1, max_length=255)
    os_type: Optional[OsType] = None
    soar_enabled: Optional[bool] = None
    soar_actions: Optional[List[str]] = None
    soar_target_label: Optional[str] = None
    tags: Optional[List[str]] = None


class LogSource(LogSourceBase):
    id: str
    wazuh_agent_id: Optional[str] = None
    wazuh_status: WazuhStatus = "pending"
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class EnrollmentInstructions(BaseModel):
    log_source_id: str
    wazuh_manager_ip: str
    enrollment_key: Optional[str]
    install_commands: List[str]
    notes: str


class SoarTestResult(BaseModel):
    log_source_id: str
    reachable: bool
    message: str
