# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Tests — Log Analysis Agent

pytest tests/test_log_analysis.py -v
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime

from schemas.alert import WazuhAlert
from orchestration.state import initial_state


def make_alert(**kwargs) -> WazuhAlert:
    defaults = dict(
        id="TEST-001",
        agent_id="agent-001",
        rule_id=5763,
        rule_level=8,
        rule_description="Brute force SSH",
        rule_groups=["ssh", "authentication_failures"],
        severity="HIGH",
        alert_category="authentication_failures",
        source_ip="185.220.101.47",
        full_log="Failed password for root from 185.220.101.47 port 22",
    )
    defaults.update(kwargs)
    return WazuhAlert(**defaults)


@pytest.fixture
def agent():
    from agents.log_analysis_agent import LogAnalysisAgent
    return LogAnalysisAgent()


def test_noise_filter_low_level(agent):
    alert = make_alert(rule_level=1, rule_id=999)
    assert agent._is_noise(alert) is True


def test_noise_filter_known_rule(agent):
    alert = make_alert(rule_level=5, rule_id=1002)
    assert agent._is_noise(alert) is True


def test_not_noise_high_level(agent):
    alert = make_alert(rule_level=8, rule_id=5763)
    assert agent._is_noise(alert) is False


def test_ioc_extraction_ip(agent):
    log_text = "Connection from 185.220.101.47 to 8.8.8.8"
    iocs = agent._extract_iocs(log_text)

    assert "185.220.101.47" in iocs


def test_ioc_extraction_sha256(agent):

    sha256_hash = "a" * 64
    log_text = f"File hash: {sha256_hash} is malicious"
    iocs = agent._extract_iocs(log_text)
    assert sha256_hash in iocs


def test_ioc_extraction_cve(agent):
    log_text = "Exploit targeting CVE-2021-44228 detected"
    iocs = agent._extract_iocs(log_text)
    assert "CVE-2021-44228" in iocs


def test_ioc_excludes_private_ip(agent):
    log_text = "Traffic from 192.168.1.100 to 10.0.0.1"
    iocs = agent._extract_iocs(log_text)
    assert "192.168.1.100" not in iocs
    assert "10.0.0.1" not in iocs


def test_rescore_baseline(agent):
    alert = make_alert(rule_level=8, user="nobody", agent_id="agent-999")
    score = agent._rescore(alert, is_known_malicious=False)
    assert score == 80


def test_rescore_privileged_user(agent):
    alert = make_alert(rule_level=8, user="root", agent_id="agent-999")

    score = agent._rescore(alert, is_known_malicious=False)
    assert score == 95


def test_rescore_crown_jewel(agent):
    alert = make_alert(rule_level=8, user="nobody", agent_id="agent-002")

    score = agent._rescore(alert, is_known_malicious=False)
    assert score == 105


def test_rescore_known_malicious_ip(agent):
    alert = make_alert(rule_level=8, user="nobody", agent_id="agent-999")
    score = agent._rescore(alert, is_known_malicious=True)
    assert score == 100


def test_rescore_max_150(agent):
    alert = make_alert(rule_level=15, user="root", agent_id="agent-002")
    score = agent._rescore(alert, is_known_malicious=True)
    assert score == 150


def test_mitre_mapping_known_rule(agent):
    techniques = agent._map_to_mitre(5763)
    assert "T1110" in techniques


def test_mitre_mapping_unknown_rule(agent):
    techniques = agent._map_to_mitre(99999)
    assert techniques == []


def test_asset_criticality_crown_jewel(agent):
    assert agent._get_asset_criticality("agent-002") == "CROWN_JEWEL"


def test_asset_criticality_default(agent):
    assert agent._get_asset_criticality("agent-999") == "LOW"


def test_category_brute_force(agent):
    alert = make_alert(
        alert_category="authentication_failures",
        rule_groups=["ssh", "authentication_failures"],
    )
    cat = agent._categorise(alert)
    assert cat == "brute_force"


def test_category_fallback_generic(agent):
    alert = make_alert(alert_category="unknown_custom", rule_groups=["custom"])
    cat = agent._categorise(alert)
    assert cat == "generic"


@pytest.mark.asyncio
async def test_run_full_pipeline():
    from agents.log_analysis_agent import LogAnalysisAgent

    agent = LogAnalysisAgent()
    alert = make_alert(
        rule_level=10,
        source_ip="185.220.101.47",
        full_log="Failed password for root from 185.220.101.47 port 22 sha256:3f3efb5b9bfbc88a6931b7b0ca0b76a8b1f5c9a38e6d4a2e1b0c9f8e7d6c5b4a3",
    )
    state = initial_state(alert)

    with (
        patch("agents.log_analysis_agent.redis_client.check_dedup", new=AsyncMock(return_value=False)),
        patch("agents.log_analysis_agent.redis_client.check_burst", new=AsyncMock(return_value=[])),
        patch("agents.log_analysis_agent.redis_client.is_known_malicious", new=AsyncMock(return_value=False)),
        patch("agents.log_analysis_agent.kafka_producer.send", new=AsyncMock()),
    ):
        result = await agent.run(state)

    assert result["analysis"] is not None
    analysis = result["analysis"]
    assert analysis.alert_id == alert.id
    assert analysis.has_iocs is True
    assert not analysis.noise_filtered
    assert not analysis.is_duplicate
    assert len(result["audit_trail"]) == 1
    assert result["audit_trail"][0].agent == "log_analysis"


@pytest.mark.asyncio
async def test_run_marks_noise():
    from agents.log_analysis_agent import LogAnalysisAgent
    agent = LogAnalysisAgent()
    alert = make_alert(rule_id=1002, rule_level=1, full_log="audit: type=1400")
    state = initial_state(alert)

    with (
        patch("agents.log_analysis_agent.redis_client.check_dedup", new=AsyncMock(return_value=False)),
        patch("agents.log_analysis_agent.redis_client.check_burst", new=AsyncMock(return_value=[])),
        patch("agents.log_analysis_agent.redis_client.is_known_malicious", new=AsyncMock(return_value=False)),
        patch("agents.log_analysis_agent.kafka_producer.send", new=AsyncMock()),
    ):
        result = await agent.run(state)

    assert result["analysis"].noise_filtered is True
