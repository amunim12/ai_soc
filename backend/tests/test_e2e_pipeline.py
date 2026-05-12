# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
End-to-End Pipeline Tests

Runs all 20 mock alerts through the full compiled LangGraph DAG
using fully mocked agents (no real network calls).

pytest tests/test_e2e_pipeline.py -v
"""
from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, patch

from bridge.mock_alert_generator import MOCK_ALERTS
from schemas.alert import WazuhAlert
from schemas.analysis import AnalysisResult
from schemas.enrichment import TIEnrichment
from schemas.playbook import Playbook, PlaybookPhase, PlaybookStep
from schemas.hitl import ApprovalDecision
from orchestration.state import initial_state
from orchestration.graph import process_alert


def _make_mock_analysis_agent(noise=False, has_iocs=True, is_dup=False):
    async def run(state):
        alert = state["alert"]
        state["analysis"] = AnalysisResult(
            alert_id=alert.id,
            noise_filtered=noise,
            is_duplicate=is_dup,
            has_iocs=has_iocs,
            iocs=["185.220.101.47"] if has_iocs else [],
            adjusted_score=80,
            mitre_techniques=["T1110"],
        )
        state.setdefault("audit_trail", [])
        return state
    return run


def _make_mock_ti_agent():
    async def run(state):
        state["enrichment"] = TIEnrichment(alert_id=state["alert"].id, threat_score=0.72)
        return state
    return run


def _make_mock_playbook_agent(confidence=0.88, irreversible=False):
    async def run(state):
        action = "ISOLATE_HOST" if irreversible else "BLOCK_IP"
        state["playbook"] = Playbook(
            alert_id=state["alert"].id,
            phases={"containment": PlaybookPhase(
                phase_name="containment",
                steps=[PlaybookStep(step_id="C1", action_type=action, description="Test step")],
            )},
            confidence_score=confidence,
        )
        state["confidence"] = confidence
        return state
    return run


def _make_mock_hitl_agent(action="APPROVE"):
    async def run(state):
        state["hitl_decision"] = ApprovalDecision(
            review_id="REV-E2E",
            action=action,
            analyst_id="e2e_test",
            elapsed_seconds=5,
        )
        state["approved"] = action in ("APPROVE", "EDIT")
        return state
    return run


@pytest.fixture(autouse=True)
def mock_kafka():
    async def _soar_noop(state):

        return state

    with patch("orchestration.graph.kafka_producer.send", new=AsyncMock()), \
         patch("agents.supervisor.kafka_producer.send", new=AsyncMock()), \
         patch("agents.supervisor.sqlite_client.store_audit_entry", new=AsyncMock()), \
         patch("agents.soar_agent.soar_agent.run", side_effect=_soar_noop):
        yield


@pytest.mark.asyncio
async def test_happy_path_execute():
    """
    Alert has IOCs, TI enriched, playbook high confidence (0.93) + non-critical
    → should reach EXECUTE without HITL.
    """
    alert = MOCK_ALERTS[0]

    alert = alert.model_copy(update={"severity": "MEDIUM"})

    with (
        patch("agents.log_analysis_agent.log_analysis_agent.run",
              side_effect=_make_mock_analysis_agent(has_iocs=True)),
        patch("agents.threat_intel_agent.threat_intel_agent.run",
              side_effect=_make_mock_ti_agent()),
        patch("agents.playbook_gen_agent.playbook_gen_agent.run",
              side_effect=_make_mock_playbook_agent(confidence=0.93, irreversible=False)),
        patch("agents.hitl_agent.hitl_agent.run",
              side_effect=_make_mock_hitl_agent("APPROVE")),
    ):
        state = await process_alert(alert)

    assert state["pipeline_stage"] == "executed"


@pytest.mark.asyncio
async def test_noise_alert_drops():
    """Noise alert should reach DROP without running later agents."""
    alert = MOCK_ALERTS[10]

    with (
        patch("agents.log_analysis_agent.log_analysis_agent.run",
              side_effect=_make_mock_analysis_agent(noise=True, has_iocs=False)),
        patch("agents.threat_intel_agent.threat_intel_agent.run",
              side_effect=AsyncMock(side_effect=AssertionError("TI agent should NOT run on noise"))),
        patch("agents.playbook_gen_agent.playbook_gen_agent.run",
              side_effect=AsyncMock(side_effect=AssertionError("Playbook should NOT run on noise"))),
    ):
        state = await process_alert(alert)

    assert state["pipeline_stage"] == "dropped"


@pytest.mark.asyncio
async def test_critical_alert_triggers_hitl():
    """CRITICAL severity → HITL even with high confidence."""
    alert = MOCK_ALERTS[6]

    with (
        patch("agents.log_analysis_agent.log_analysis_agent.run",
              side_effect=_make_mock_analysis_agent(has_iocs=True)),
        patch("agents.threat_intel_agent.threat_intel_agent.run",
              side_effect=_make_mock_ti_agent()),
        patch("agents.playbook_gen_agent.playbook_gen_agent.run",
              side_effect=_make_mock_playbook_agent(confidence=0.95, irreversible=False)),
        patch("agents.hitl_agent.hitl_agent.run",
              side_effect=_make_mock_hitl_agent("APPROVE")),
    ):
        state = await process_alert(alert)

    assert state["pipeline_stage"] == "executed"
    assert state.get("hitl_decision") is not None


@pytest.mark.asyncio
async def test_hitl_reject_drops_alert():
    """Analyst rejects → DROP."""
    alert = MOCK_ALERTS[5]

    with (
        patch("agents.log_analysis_agent.log_analysis_agent.run",
              side_effect=_make_mock_analysis_agent(has_iocs=True)),
        patch("agents.threat_intel_agent.threat_intel_agent.run",
              side_effect=_make_mock_ti_agent()),
        patch("agents.playbook_gen_agent.playbook_gen_agent.run",
              side_effect=_make_mock_playbook_agent(confidence=0.60)),
        patch("agents.hitl_agent.hitl_agent.run",
              side_effect=_make_mock_hitl_agent("REJECT")),
    ):
        state = await process_alert(alert)

    assert state["pipeline_stage"] == "dropped"


@pytest.mark.asyncio
async def test_no_ioc_skips_ti_agent():
    """Alert without IOCs should skip TI enrichment directly to playbook."""
    alert = MOCK_ALERTS[11]

    with (
        patch("agents.log_analysis_agent.log_analysis_agent.run",
              side_effect=_make_mock_analysis_agent(has_iocs=False)),
        patch("agents.threat_intel_agent.threat_intel_agent.run",
              side_effect=AsyncMock(side_effect=AssertionError("TI should be skipped"))),
        patch("agents.playbook_gen_agent.playbook_gen_agent.run",
              side_effect=_make_mock_playbook_agent(confidence=0.93)),
        patch("agents.hitl_agent.hitl_agent.run",
              side_effect=_make_mock_hitl_agent("APPROVE")),
    ):

        alert = alert.model_copy(update={"severity": "LOW"})
        state = await process_alert(alert)

    assert state["pipeline_stage"] == "executed"
    assert state.get("enrichment") is None


@pytest.mark.asyncio
async def test_audit_trail_populated():
    """Audit trail should have entries from each agent that ran."""
    alert = MOCK_ALERTS[0].model_copy(update={"severity": "MEDIUM"})

    with (
        patch("agents.log_analysis_agent.log_analysis_agent.run",
              side_effect=_make_mock_analysis_agent(has_iocs=True)),
        patch("agents.threat_intel_agent.threat_intel_agent.run",
              side_effect=_make_mock_ti_agent()),
        patch("agents.playbook_gen_agent.playbook_gen_agent.run",
              side_effect=_make_mock_playbook_agent(confidence=0.93)),
        patch("agents.hitl_agent.hitl_agent.run",
              side_effect=_make_mock_hitl_agent("APPROVE")),
    ):
        state = await process_alert(alert)


    agent_names = [s.agent for s in state.get("audit_trail", [])]
    assert "supervisor:execute" in agent_names


@pytest.mark.asyncio
async def test_all_20_mock_alerts_complete():
    """
    Smoke test: all 20 mock alerts should complete without exception.
    HITL is auto-approved. All should end in a terminal stage.
    """
    TERMINAL_STAGES = {"executed", "dropped", "escalated"}

    for alert in MOCK_ALERTS:
        is_noise = alert.rule_level < 3 or alert.rule_id in {100, 200, 533, 1002}

        with (
            patch("agents.log_analysis_agent.log_analysis_agent.run",
                  side_effect=_make_mock_analysis_agent(noise=is_noise, has_iocs=not is_noise)),
            patch("agents.threat_intel_agent.threat_intel_agent.run",
                  side_effect=_make_mock_ti_agent()),
            patch("agents.playbook_gen_agent.playbook_gen_agent.run",
                  side_effect=_make_mock_playbook_agent(confidence=0.75)),
            patch("agents.hitl_agent.hitl_agent.run",
                  side_effect=_make_mock_hitl_agent("APPROVE")),
        ):
            state = await process_alert(alert)
            assert state.get("pipeline_stage") in TERMINAL_STAGES, (
                f"Alert {alert.id} ended in unexpected stage: {state.get('pipeline_stage')}"
            )
