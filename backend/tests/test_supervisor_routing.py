# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Tests — Supervisor Agent Routing Logic

pytest tests/test_supervisor_routing.py -v
"""
from __future__ import annotations

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, patch

from schemas.alert import WazuhAlert
from schemas.analysis import AnalysisResult
from schemas.enrichment import TIEnrichment
from schemas.playbook import Playbook, PlaybookPhase, PlaybookStep
from schemas.hitl import ApprovalDecision
from orchestration.state import initial_state, PipelineState


def make_state(
    severity="HIGH",
    noise=False,
    is_dup=False,
    has_iocs=True,
    confidence=0.9,
    irreversible=False,
    hitl_action="APPROVE",
) -> PipelineState:
    alert = WazuhAlert(
        id="ROUTE-TEST",
        agent_id="agent-001",
        rule_id=5763,
        rule_level=8,
        rule_description="Test alert",
        severity=severity,
    )
    state = initial_state(alert)

    state["analysis"] = AnalysisResult(
        alert_id="ROUTE-TEST",
        noise_filtered=noise,
        is_duplicate=is_dup,
        has_iocs=has_iocs,
        adjusted_score=80,
    )

    phases = {}
    if irreversible:
        phases["containment"] = PlaybookPhase(
            phase_name="containment",
            steps=[PlaybookStep(
                step_id="C1",
                action_type="ISOLATE_HOST",
                description="Isolate host",
            )],
        )
    else:
        phases["containment"] = PlaybookPhase(
            phase_name="containment",
            steps=[PlaybookStep(
                step_id="C1",
                action_type="BLOCK_IP",
                description="Block IP",
            )],
        )

    state["playbook"] = Playbook(
        alert_id="ROUTE-TEST",
        phases=phases,
        confidence_score=confidence,
    )
    state["confidence"] = confidence

    state["hitl_decision"] = ApprovalDecision(
        review_id="REV-001",
        action=hitl_action,
        analyst_id="test_analyst",
        elapsed_seconds=60,
    )
    return state


@pytest.fixture
def sup():
    from agents.supervisor import SupervisorAgent
    return SupervisorAgent()


def test_route_analysis_noise(sup):
    state = make_state(noise=True)
    assert sup.route_after_analysis(state) == "drop"


def test_route_analysis_duplicate(sup):
    state = make_state(is_dup=True)
    assert sup.route_after_analysis(state) == "drop"


def test_route_analysis_no_iocs(sup):
    state = make_state(has_iocs=False, noise=False, is_dup=False)
    assert sup.route_after_analysis(state) == "skip_to_playbook"


def test_route_analysis_has_iocs(sup):
    state = make_state(has_iocs=True, noise=False, is_dup=False)
    assert sup.route_after_analysis(state) == "enrich"


def test_route_analysis_none_analysis(sup):
    """If analysis is None (bug), should drop safely."""
    state = make_state()
    state["analysis"] = None
    assert sup.route_after_analysis(state) == "drop"


def test_route_enrichment_always_playbook(sup):
    state = make_state()
    assert sup.route_after_enrichment(state) == "generate_playbook"


def test_route_playbook_high_confidence_non_critical(sup):
    state = make_state(severity="HIGH", confidence=0.92, irreversible=False)
    assert sup.route_after_playbook(state) == "execute"


def test_route_playbook_low_confidence(sup):
    state = make_state(severity="MEDIUM", confidence=0.70, irreversible=False)
    assert sup.route_after_playbook(state) == "hitl"


def test_route_playbook_critical_severity(sup):
    state = make_state(severity="CRITICAL", confidence=0.95, irreversible=False)
    assert sup.route_after_playbook(state) == "hitl"


def test_route_playbook_irreversible_steps(sup):
    state = make_state(severity="MEDIUM", confidence=0.92, irreversible=True)
    assert sup.route_after_playbook(state) == "hitl"


def test_route_playbook_borderline_confidence(sup):

    state = make_state(severity="HIGH", confidence=0.85, irreversible=False)
    assert sup.route_after_playbook(state) == "execute"


def test_route_playbook_none_playbook(sup):
    state = make_state()
    state["playbook"] = None
    assert sup.route_after_playbook(state) == "hitl"


def test_route_hitl_approve(sup):
    state = make_state(hitl_action="APPROVE")
    assert sup.route_after_hitl(state) == "execute"


def test_route_hitl_edit(sup):
    state = make_state(hitl_action="EDIT")
    assert sup.route_after_hitl(state) == "generate_playbook"


def test_route_hitl_reject(sup):
    state = make_state(hitl_action="REJECT")
    assert sup.route_after_hitl(state) == "drop"


def test_route_hitl_escalate(sup):
    state = make_state(hitl_action="ESCALATE")
    assert sup.route_after_hitl(state) == "escalate"


def test_route_hitl_none_decision(sup):
    state = make_state()
    state["hitl_decision"] = None
    assert sup.route_after_hitl(state) == "drop"
