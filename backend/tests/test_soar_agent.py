# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agents.soar_agent import SOARAgent, _extract_params
from schemas.alert import WazuhAlert
from schemas.playbook import Playbook, PlaybookPhase, PlaybookStep


def _make_alert(**kwargs) -> WazuhAlert:
    defaults = dict(
        id="alert-001",
        timestamp=datetime.utcnow(),
        agent_id="agent-1",
        agent_name="host-1",
        rule_id=1002,
        rule_level=12,
        rule_description="Brute force",
        severity="HIGH",
        alert_category="brute_force",
        rule_groups=["brute_force"],
        full_log="Failed login",
    )
    defaults.update(kwargs)
    return WazuhAlert(**defaults)


def _make_state(alert: WazuhAlert, approved: bool = True) -> dict:
    step = PlaybookStep(
        step_id="s1",
        action_type="BLOCK_IP",
        target="1.2.3.4",
        parameters={"ip": "1.2.3.4"},
        risk_level="LOW",
    )
    phase = PlaybookPhase(phase_name="contain", steps=[step])
    playbook = Playbook(
        title="Test Playbook",
        phases={"contain": phase},
        summary="Block the IP",
    )
    return {
        "alert": alert,
        "playbook": playbook,
        "approved": approved,
        "audit_trail": [],
        "confidence": 0.9,
    }


@pytest.mark.asyncio
async def test_soar_returns_immediately_without_waiting():
    """run() must return before shuffle.wait() completes."""
    alert = _make_alert()
    state = _make_state(alert)

    wait_done = asyncio.Event()

    async def slow_wait(*args, **kwargs):
        await asyncio.sleep(0.2)
        wait_done.set()
        return {"status": "FINISHED", "steps": []}

    mock_shuffle = MagicMock()
    mock_shuffle.trigger = AsyncMock(return_value="exec-123")
    mock_shuffle.wait = slow_wait

    agent = SOARAgent()
    agent.shuffle = mock_shuffle

    with (
        patch("agents.soar_agent.kafka_producer") as mock_kafka,
        patch("agents.soar_agent.SOAR_ENABLED", True),
    ):
        mock_kafka.send = AsyncMock()
        returned_state = await agent.run(state)

    # Must return before wait() completes
    assert not wait_done.is_set(), "run() waited for shuffle — it should not"
    assert returned_state["soar_execution_id"] == "exec-123"
    assert returned_state["soar_result"]["status"] == "PENDING"
    assert returned_state["pipeline_stage"] == "soar_pending"

    # Let background task finish cleanly
    await asyncio.sleep(0.3)
    assert wait_done.is_set()


@pytest.mark.asyncio
async def test_soar_skips_when_not_approved():
    alert = _make_alert()
    state = _make_state(alert, approved=False)

    with patch("agents.soar_agent.SOAR_ENABLED", True):
        agent = SOARAgent()
        result = await agent.run(state)

    assert result["soar_result"]["status"] == "SKIPPED"


@pytest.mark.asyncio
async def test_soar_disabled_stubs_success():
    alert = _make_alert()
    state = _make_state(alert)

    with patch("agents.soar_agent.SOAR_ENABLED", False):
        agent = SOARAgent()
        result = await agent.run(state)

    assert result["soar_result"]["status"] == "STUBBED"


@pytest.mark.asyncio
async def test_soar_trigger_failure_does_not_detach_task():
    """If trigger() raises, no background task should be created and state is FAILED."""
    alert = _make_alert()
    state = _make_state(alert)

    mock_shuffle = MagicMock()
    mock_shuffle.trigger = AsyncMock(side_effect=Exception("Shuffle down"))

    agent = SOARAgent()
    agent.shuffle = mock_shuffle

    with (
        patch("agents.soar_agent.kafka_producer") as mock_kafka,
        patch("agents.soar_agent.SOAR_ENABLED", True),
    ):
        mock_kafka.send = AsyncMock()
        result = await agent.run(state)

    assert result["soar_result"]["status"] == "FAILED"
    assert "Shuffle down" in result["soar_result"]["error"]


@pytest.mark.asyncio
async def test_soar_resume_publishes_audit_on_success():
    """Background task must publish SOAR_EXECUTION_COMPLETE to wazuh.audit."""
    alert = _make_alert()
    state = _make_state(alert)

    mock_shuffle = MagicMock()
    mock_shuffle.trigger = AsyncMock(return_value="exec-456")
    mock_shuffle.wait = AsyncMock(return_value={"status": "FINISHED", "steps": ["block_ip"]})

    agent = SOARAgent()
    agent.shuffle = mock_shuffle

    published_topics: list[str] = []

    async def record_send(topic, payload, **kwargs):
        published_topics.append(topic)

    with (
        patch("agents.soar_agent.kafka_producer") as mock_kafka,
        patch("agents.soar_agent.SOAR_ENABLED", True),
    ):
        mock_kafka.send = record_send
        await agent.run(state)
        await asyncio.sleep(0.05)

    audit_publishes = [t for t in published_topics if t == "wazuh.audit"]
    assert len(audit_publishes) == 1


def test_extract_params_block_ip():
    step = PlaybookStep(
        step_id="s1",
        action_type="BLOCK_IP",
        target="10.0.0.1",
        parameters={},
        risk_level="LOW",
    )
    phase = PlaybookPhase(phase_name="contain", steps=[step])
    playbook = Playbook(title="T", phases={"contain": phase})
    params = _extract_params(playbook)
    assert params["source_ip"] == "10.0.0.1"
