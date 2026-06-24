# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Tests — HITL Agent (non-network, mocked I/O)

pytest tests/test_hitl_agent.py -v
"""
from __future__ import annotations

import asyncio
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from schemas.alert import WazuhAlert
from schemas.playbook import Playbook, PlaybookPhase, PlaybookStep
from schemas.hitl import ApprovalDecision
from orchestration.state import initial_state


def make_hitl_state(confidence=0.7, severity="CRITICAL", irreversible=True):
    alert = WazuhAlert(
        id="HITL-TEST-001",
        agent_id="agent-002",
        rule_id=18125,
        rule_level=12,
        rule_description="Domain admin privilege granted",
        severity=severity,
    )
    state = initial_state(alert)
    state["confidence"] = confidence

    phase = PlaybookPhase(
        phase_name="containment",
        steps=[
            PlaybookStep(
                step_id="C1",
                action_type="ISOLATE_HOST" if irreversible else "BLOCK_IP",
                description="Test step",
            )
        ],
    )
    state["playbook"] = Playbook(
        alert_id=alert.id,
        phases={"containment": phase},
        confidence_score=confidence,
    )
    return state


@pytest.fixture
def agent():
    from agents.hitl_agent import HITLAgent
    a = HITLAgent()
    a._escalated = False
    return a


def test_explain_reason_low_confidence(agent):
    state = make_hitl_state(confidence=0.5, severity="MEDIUM", irreversible=False)
    reason = agent._explain_reason(state)
    assert "confidence" in reason.lower()


def test_explain_reason_critical(agent):
    state = make_hitl_state(confidence=0.9, severity="CRITICAL", irreversible=False)
    reason = agent._explain_reason(state)
    assert "critical" in reason.lower()


def test_explain_reason_irreversible(agent):
    state = make_hitl_state(confidence=0.9, severity="MEDIUM", irreversible=True)
    reason = agent._explain_reason(state)
    assert "irreversible" in reason.lower()


def test_explain_reason_all_triggers(agent):
    state = make_hitl_state(confidence=0.5, severity="CRITICAL", irreversible=True)
    reason = agent._explain_reason(state)
    assert "·" in reason


def test_auto_partial_approve(agent):
    decision = agent._auto_partial_approve("REV-001", elapsed=900)
    assert decision.action == "APPROVE"
    assert decision.analyst_id == "system:timeout"
    assert "timeout" in decision.notes.lower()
    assert decision.elapsed_seconds == 900


def test_has_irreversible_true(agent):
    pb = Playbook(phases={
        "containment": PlaybookPhase(
            phase_name="containment",
            steps=[PlaybookStep(step_id="C1", action_type="ISOLATE_HOST", description="x")]
        )
    })
    assert agent._has_irreversible(pb) is True


def test_has_irreversible_false(agent):
    pb = Playbook(phases={
        "containment": PlaybookPhase(
            phase_name="containment",
            steps=[PlaybookStep(step_id="C1", action_type="BLOCK_IP", description="x")]
        )
    })
    assert agent._has_irreversible(pb) is False


def test_has_irreversible_none(agent):
    assert agent._has_irreversible(None) is False


@pytest.mark.asyncio
async def test_run_fast_decision():
    """run() parks the alert and returns immediately; decision is processed in a detached task."""
    import agents.hitl_agent as hitl_mod
    from agents.hitl_agent import HITLAgent

    agent = HITLAgent()
    state = make_hitl_state()

    mock_decision = ApprovalDecision(
        review_id="REV-FAST",
        action="APPROVE",
        analyst_id="test_analyst",
        elapsed_seconds=10,
    )

    with (
        patch.object(hitl_mod.sqlite_client, "store_pending_review",
                     new=AsyncMock(return_value="REV-FAST")),
        patch.object(hitl_mod.sqlite_client, "poll_decision",
                     new=AsyncMock(return_value=mock_decision)),
        patch.object(hitl_mod.sqlite_client, "store_decision",
                     new=AsyncMock()),
        patch.object(hitl_mod.kafka_producer, "send",
                     new=AsyncMock()),
        patch.object(agent, "_notify_slack", new=AsyncMock()),
        patch.object(agent, "_notify_email", new=AsyncMock()),
        patch.object(agent, "_notify_electron", new=AsyncMock()),
        patch.object(agent, "_resume_after_decision", new=AsyncMock()),
        patch("agents.hitl_agent.POLL_INTERVAL", 0),
    ):
        result = await agent.run(state)

    assert result["pipeline_stage"] == "hitl_pending"
    assert result["hitl_review_id"] == "REV-FAST"
    assert len(result["audit_trail"]) == 1
    assert result["audit_trail"][0].agent == "hitl"
