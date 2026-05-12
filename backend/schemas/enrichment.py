# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""TIEnrichment — output of the Threat Intelligence agent."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field, field_serializer


class VTResult(BaseModel):
    ioc: str
    malicious_ratio: float = 0.0
    malicious_votes: int = 0
    total_votes: int = 0
    categories: list[str] = Field(default_factory=list)
    last_analysis_date: Optional[str] = None
    error: Optional[str] = None


class MISPResult(BaseModel):
    ioc_matches: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    event_count: int = 0
    error: Optional[str] = None


class OTXResult(BaseModel):
    pulse_count: int = 0
    malware_families: list[str] = Field(default_factory=list)
    adversary: Optional[str] = None
    error: Optional[str] = None


class ShodanResult(BaseModel):
    ip: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    open_ports: list[int] = Field(default_factory=list)
    vuln_count: int = 0
    vulns: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    error: Optional[str] = None


class CVEReference(BaseModel):
    cve_id: str
    description: str
    cvss_score: float = 0.0
    severity: str = "UNKNOWN"
    published_date: Optional[str] = None


class GeoContext(BaseModel):
    ip: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    is_tor: bool = False
    is_vpn: bool = False
    is_datacenter: bool = False
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    error: Optional[str] = None


class TIEnrichment(BaseModel):
    alert_id: str

    vt_result: Optional[VTResult] = None
    misp_result: Optional[MISPResult] = None
    otx_result: Optional[OTXResult] = None
    shodan_result: Optional[ShodanResult] = None
    cve_references: list[CVEReference] = Field(default_factory=list)
    geo_context: Optional[GeoContext] = None


    threat_score: float = 0.0


    known_threat_actor: Optional[str] = None
    is_tor_exit: bool = False
    is_known_malicious: bool = False

    enriched_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"populate_by_name": True}

    @field_serializer("enriched_at")
    def _ser_ts(self, v: datetime) -> str:
        return v.isoformat()
