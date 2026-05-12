# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Tests — Threat Intelligence Agent

pytest tests/test_threat_intel.py -v
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from schemas.alert import WazuhAlert
from schemas.analysis import AnalysisResult
from schemas.enrichment import VTResult, MISPResult, OTXResult, ShodanResult
from orchestration.state import initial_state


def make_ti_state(iocs: list[str] | None = None, source_ip: str = "185.220.101.47"):
    alert = WazuhAlert(
        id="TI-TEST",
        agent_id="agent-001",
        rule_id=5763,
        rule_level=8,
        rule_description="Test",
        source_ip=source_ip,
    )
    state = initial_state(alert)
    state["analysis"] = AnalysisResult(
        alert_id="TI-TEST",
        iocs=iocs or [source_ip],
        has_iocs=bool(iocs),
        mitre_techniques=["T1110"],
        adjusted_score=80,
    )
    return state


@pytest.fixture
def agent():
    from agents.threat_intel_agent import ThreatIntelAgent
    return ThreatIntelAgent()


def test_composite_score_all_high(agent):
    vt      = VTResult(ioc="1.2.3.4", malicious_ratio=1.0, total_votes=50)
    misp    = MISPResult(confidence=1.0)
    otx     = OTXResult(pulse_count=100)
    shodan  = ShodanResult(vuln_count=10)
    score = agent._compute_threat_score(vt, misp, otx, shodan)
    assert abs(score - 1.0) < 0.01


def test_composite_score_all_zero(agent):
    vt     = VTResult(ioc="1.2.3.4", malicious_ratio=0.0, total_votes=0)
    misp   = MISPResult(confidence=0.0)
    otx    = OTXResult(pulse_count=0)
    shodan = ShodanResult(vuln_count=0)
    score = agent._compute_threat_score(vt, misp, otx, shodan)
    assert score == 0.0


def test_composite_score_partial(agent):
    vt     = VTResult(ioc="1.2.3.4", malicious_ratio=0.72, total_votes=50)
    misp   = MISPResult(confidence=0.0)
    otx    = OTXResult(pulse_count=0)
    shodan = ShodanResult(vuln_count=0)

    score = agent._compute_threat_score(vt, misp, otx, shodan)
    assert abs(score - 0.252) < 0.01


def test_composite_score_exception_resilience(agent):
    """Exception from one source should not break scoring."""
    vt      = Exception("API timeout")
    misp    = MISPResult(confidence=0.8)
    otx     = OTXResult(pulse_count=50)
    shodan  = ShodanResult(vuln_count=5)
    score = agent._compute_threat_score(vt, misp, otx, shodan)

    expected = 0.8 * 0.25 + (50/100) * 0.20 + (5/10) * 0.20
    assert abs(score - expected) < 0.01


def test_composite_score_caps_at_1(agent):
    vt     = VTResult(ioc="x", malicious_ratio=1.0, total_votes=10)
    misp   = MISPResult(confidence=1.0)
    otx    = OTXResult(pulse_count=200)
    shodan = ShodanResult(vuln_count=100)
    score = agent._compute_threat_score(vt, misp, otx, shodan)
    assert score <= 1.0


@pytest.mark.asyncio
async def test_run_full_mock():
    from agents.threat_intel_agent import ThreatIntelAgent
    agent = ThreatIntelAgent()
    state = make_ti_state()

    with (
        patch("agents.threat_intel_agent.redis_client.mark_malicious", new=AsyncMock()),
        patch("agents.threat_intel_agent.kafka_producer.send", new=AsyncMock()),
    ):
        result = await agent.run(state)

    assert result["enrichment"] is not None
    enrichment = result["enrichment"]
    assert enrichment.alert_id == "TI-TEST"
    assert 0.0 <= enrichment.threat_score <= 1.0
    assert len(result["audit_trail"]) == 1
    assert result["audit_trail"][0].agent == "threat_intel"
