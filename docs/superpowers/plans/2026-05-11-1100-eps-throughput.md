# 1100 EPS Throughput Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Increase the AI SOC pipeline's sustainable throughput from ~50–80 EPS to 1100+ EPS by fixing the SOAR blocking bottleneck, centralising all perf-tuning knobs in `settings.py`, raising concurrency defaults, fixing Wazuh bridge ingestion rate, and hardening the docker-compose stack.

**Architecture:** Four independent changes stack on top of each other. The biggest gain is the SOAR detach (frees up to 256 consumer slots that currently sit blocked on a 15-minute wait). The settings centralisation wires higher concurrency defaults. The Wazuh bridge fix unlocks ingestion at 1100 EPS. Docker compose hardening removes the dev-only password and enables Redis auth.

**Tech Stack:** Python 3.11, asyncio, LangGraph 0.2, FastAPI 0.115, confluent-kafka, pydantic-settings 2, Docker Compose v3.9

---

## File Map

| File | Change |
|---|---|
| `backend/config/settings.py` | Add 9 missing perf-tuning fields |
| `backend/orchestration/graph.py` | Read `MAX_CONCURRENT_ALERTS` / `NUM_CONSUMER_WORKERS` from `settings` |
| `backend/infrastructure/llm_client.py` | Read `LLM_MAX_CONCURRENT_CALLS` / `LLM_CALL_TIMEOUT_SECONDS` from `settings` |
| `backend/agents/soar_agent.py` | Detach `shuffle.wait()` into background task, return immediately |
| `backend/bridge/wazuh_kafka_bridge.py` | Read `POLL_INTERVAL_SECONDS` / `BATCH_SIZE` from `settings` |
| `backend/docker-compose.yml` | Postgres password env var, Redis `--requirepass`, Kafka `num.partitions=48` |
| `backend/.env.example` | Document all new settings |
| `backend/tests/test_soar_agent.py` | Tests for async-detached SOAR execution |
| `backend/tests/test_settings_perf.py` | Smoke test that all new settings load correctly |

---

## Task 1: Centralise All Performance Settings in `settings.py`

**Files:**
- Modify: `backend/config/settings.py`
- Create: `backend/tests/test_settings_perf.py`

Currently `graph.py`, `llm_client.py`, and `bridge/wazuh_kafka_bridge.py` all call `os.getenv(...)` directly to read performance knobs. This means they're invisible to `settings`, can't be validated, and have no single place to document them.

- [ ] **Step 1: Write the failing settings smoke test**

```python
# backend/tests/test_settings_perf.py
# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0
import pytest
from config.settings import Settings


def test_perf_settings_have_correct_defaults():
    s = Settings(
        SHUFFLE_API_KEY="test-key",
        LOCAL_LLM_BASE_URL="http://localhost:8001/v1",
    )
    assert s.PIPELINE_MAX_CONCURRENT_ALERTS == 512
    assert s.KAFKA_NUM_CONSUMER_WORKERS == 16
    assert s.LLM_MAX_CONCURRENT_CALLS == 64
    assert s.LLM_CALL_TIMEOUT_SECONDS == 30.0
    assert s.PLAYBOOK_CACHE_TTL_SECONDS == 3600
    assert s.RAG_CTX_CACHE_TTL_SECONDS == 3600
    assert s.WAZUH_POLL_INTERVAL == 1
    assert s.WAZUH_BATCH_SIZE == 1200
    assert s.SOAR_ENABLED is True


def test_perf_settings_are_overridable(monkeypatch):
    monkeypatch.setenv("PIPELINE_MAX_CONCURRENT_ALERTS", "128")
    monkeypatch.setenv("KAFKA_NUM_CONSUMER_WORKERS", "4")
    monkeypatch.setenv("LLM_MAX_CONCURRENT_CALLS", "8")
    monkeypatch.setenv("LLM_CALL_TIMEOUT_SECONDS", "5.0")
    monkeypatch.setenv("PLAYBOOK_CACHE_TTL_SECONDS", "60")
    monkeypatch.setenv("RAG_CTX_CACHE_TTL_SECONDS", "120")
    monkeypatch.setenv("WAZUH_POLL_INTERVAL", "10")
    monkeypatch.setenv("WAZUH_BATCH_SIZE", "50")
    monkeypatch.setenv("SOAR_ENABLED", "false")

    from importlib import reload
    import config.settings as settings_module
    reload(settings_module)

    s = settings_module.Settings(
        SHUFFLE_API_KEY="test-key",
        LOCAL_LLM_BASE_URL="http://localhost:8001/v1",
    )
    assert s.PIPELINE_MAX_CONCURRENT_ALERTS == 128
    assert s.KAFKA_NUM_CONSUMER_WORKERS == 4
    assert s.LLM_MAX_CONCURRENT_CALLS == 8
    assert s.LLM_CALL_TIMEOUT_SECONDS == 5.0
    assert s.PLAYBOOK_CACHE_TTL_SECONDS == 60
    assert s.RAG_CTX_CACHE_TTL_SECONDS == 120
    assert s.WAZUH_POLL_INTERVAL == 10
    assert s.WAZUH_BATCH_SIZE == 50
    assert s.SOAR_ENABLED is False
```

- [ ] **Step 2: Run test to verify it fails**

```
cd backend
pytest tests/test_settings_perf.py -v
```

Expected: `FAILED — AttributeError: 'Settings' object has no attribute 'PIPELINE_MAX_CONCURRENT_ALERTS'`

- [ ] **Step 3: Add the 9 new fields to `settings.py`**

In `backend/config/settings.py`, locate the `HITL_TIMEOUT_SECONDS` block (line 81) and add a new section for pipeline concurrency **before** the SHUFFLE block. The existing file already has sections separated by blank lines — follow that pattern.

Replace the block starting at line 80:
```python
    USE_MOCK_TI:            bool  = True
    HITL_TIMEOUT_SECONDS:   int   = 900
    HITL_ESCALATE_SECONDS:  int   = 600
    CONFIDENCE_THRESHOLD:   float = 0.85
    LOG_LEVEL:              str   = "INFO"
```

With:
```python
    USE_MOCK_TI:            bool  = True
    HITL_TIMEOUT_SECONDS:   int   = 900
    HITL_ESCALATE_SECONDS:  int   = 600
    CONFIDENCE_THRESHOLD:   float = 0.85
    LOG_LEVEL:              str   = "INFO"
    SOAR_ENABLED:           bool  = True

    # Pipeline concurrency & throughput
    PIPELINE_MAX_CONCURRENT_ALERTS: int   = 512
    KAFKA_NUM_CONSUMER_WORKERS:     int   = 16
    LLM_MAX_CONCURRENT_CALLS:       int   = 64
    LLM_CALL_TIMEOUT_SECONDS:       float = 30.0
    PLAYBOOK_CACHE_TTL_SECONDS:     int   = 3600
    RAG_CTX_CACHE_TTL_SECONDS:      int   = 3600

    # Wazuh bridge ingestion
    WAZUH_POLL_INTERVAL: int = 1
    WAZUH_BATCH_SIZE:    int = 1200
```

- [ ] **Step 4: Run test to verify it passes**

```
cd backend
pytest tests/test_settings_perf.py -v
```

Expected: `2 passed`

- [ ] **Step 5: Commit**

```bash
git add backend/config/settings.py backend/tests/test_settings_perf.py
git commit -m "feat(settings): centralise all perf-tuning env vars with 1100-EPS defaults"
```

---

## Task 2: Wire `graph.py` and `llm_client.py` to Use `settings`

**Files:**
- Modify: `backend/orchestration/graph.py` (lines 124–125)
- Modify: `backend/infrastructure/llm_client.py` (lines 35–36)

Both files currently call `os.getenv(...)` directly, bypassing pydantic validation and the settings singleton.

- [ ] **Step 1: Write failing test for graph concurrency values**

```python
# Add to backend/tests/test_settings_perf.py

def test_graph_reads_concurrency_from_settings(monkeypatch):
    """graph.py module-level constants must honour settings values."""
    monkeypatch.setenv("PIPELINE_MAX_CONCURRENT_ALERTS", "999")
    monkeypatch.setenv("KAFKA_NUM_CONSUMER_WORKERS", "7")

    import importlib
    import orchestration.graph as graph_module
    importlib.reload(graph_module)

    assert graph_module.MAX_CONCURRENT_ALERTS == 999
    assert graph_module.NUM_CONSUMER_WORKERS == 7


def test_llm_client_reads_concurrency_from_settings(monkeypatch):
    """LLMClient semaphore must honour LLM_MAX_CONCURRENT_CALLS."""
    monkeypatch.setenv("LLM_MAX_CONCURRENT_CALLS", "7")

    import importlib
    import infrastructure.llm_client as llm_module
    importlib.reload(llm_module)

    assert llm_module.LLM_MAX_CONCURRENT_CALLS == 7
```

- [ ] **Step 2: Run test to verify it fails**

```
cd backend
pytest tests/test_settings_perf.py::test_graph_reads_concurrency_from_settings \
       tests/test_settings_perf.py::test_llm_client_reads_concurrency_from_settings -v
```

Expected: `2 FAILED` (values won't match because the modules still read from `os.getenv` independently)

- [ ] **Step 3: Update `graph.py` lines 124–125**

Replace:
```python
MAX_CONCURRENT_ALERTS  = int(os.getenv("PIPELINE_MAX_CONCURRENT_ALERTS", "256"))
NUM_CONSUMER_WORKERS   = int(os.getenv("KAFKA_NUM_CONSUMER_WORKERS",       "8"))
```

With:
```python
from config.settings import settings as _settings

MAX_CONCURRENT_ALERTS  = _settings.PIPELINE_MAX_CONCURRENT_ALERTS
NUM_CONSUMER_WORKERS   = _settings.KAFKA_NUM_CONSUMER_WORKERS
```

Also update the docstring on line 131 to reflect the new default:
```python
    """
    Single Kafka consumer in the shared group.  Kafka assigns a subset of
    wazuh.raw partitions to each worker (48 partitions / 16 workers = 3 each).
    The semaphore is shared across all workers for global concurrency control.
    """
```

- [ ] **Step 4: Update `llm_client.py` lines 35–36**

Replace:
```python
LLM_CALL_TIMEOUT_SECONDS  = float(os.getenv("LLM_CALL_TIMEOUT_SECONDS",  "10"))
LLM_MAX_CONCURRENT_CALLS  = int(os.getenv("LLM_MAX_CONCURRENT_CALLS",    "16"))
```

With:
```python
from config.settings import settings as _settings

LLM_CALL_TIMEOUT_SECONDS  = _settings.LLM_CALL_TIMEOUT_SECONDS
LLM_MAX_CONCURRENT_CALLS  = _settings.LLM_MAX_CONCURRENT_CALLS
```

- [ ] **Step 5: Run tests**

```
cd backend
pytest tests/test_settings_perf.py -v
```

Expected: `4 passed`

- [ ] **Step 6: Commit**

```bash
git add backend/orchestration/graph.py backend/infrastructure/llm_client.py \
        backend/tests/test_settings_perf.py
git commit -m "refactor(pipeline): read concurrency limits from settings singleton"
```

---

## Task 3: Fix Wazuh Bridge Ingestion Rate

**Files:**
- Modify: `backend/bridge/wazuh_kafka_bridge.py` (lines 39–40)
- Modify: `backend/tests/test_settings_perf.py` (add bridge test)

The bridge defaults to polling every 5 seconds with batches of 100, giving max 20 EPS. At 1100 EPS the bridge needs to poll every second with batches of 1200.

- [ ] **Step 1: Write failing test**

```python
# Add to backend/tests/test_settings_perf.py

def test_bridge_reads_poll_settings_from_settings(monkeypatch):
    monkeypatch.setenv("WAZUH_POLL_INTERVAL", "2")
    monkeypatch.setenv("WAZUH_BATCH_SIZE", "500")

    import importlib
    import bridge.wazuh_kafka_bridge as bridge_module
    importlib.reload(bridge_module)

    assert bridge_module.POLL_INTERVAL_SECONDS == 2
    assert bridge_module.BATCH_SIZE == 500
```

- [ ] **Step 2: Run to verify it fails**

```
cd backend
pytest tests/test_settings_perf.py::test_bridge_reads_poll_settings_from_settings -v
```

Expected: `FAILED` (values mismatch because bridge still uses `os.getenv`)

- [ ] **Step 3: Update `wazuh_kafka_bridge.py` lines 39–40**

Replace:
```python
POLL_INTERVAL_SECONDS = int(os.getenv("WAZUH_POLL_INTERVAL", "5"))
BATCH_SIZE = int(os.getenv("WAZUH_BATCH_SIZE", "100"))
```

With:
```python
from config.settings import settings as _settings

POLL_INTERVAL_SECONDS = _settings.WAZUH_POLL_INTERVAL
BATCH_SIZE            = _settings.WAZUH_BATCH_SIZE
```

- [ ] **Step 4: Run test**

```
cd backend
pytest tests/test_settings_perf.py -v
```

Expected: `5 passed`

- [ ] **Step 5: Commit**

```bash
git add backend/bridge/wazuh_kafka_bridge.py backend/tests/test_settings_perf.py
git commit -m "fix(bridge): raise default ingestion to 1200 alerts/poll at 1s interval via settings"
```

---

## Task 4: Detach SOAR `wait()` into a Background Task

**Files:**
- Modify: `backend/agents/soar_agent.py`
- Create: `backend/tests/test_soar_agent.py`

This is the highest-impact code change. Currently `execute_playbook()` calls `await self.shuffle.wait(...)` which blocks the consumer concurrency slot for up to 15 minutes. The fix mirrors what `hitl_agent.py` already does: store the execution_id, emit `execution_started` to Kafka, then detach a background task for the `wait()` + final audit publish, and return immediately.

The graph reaches `END` after `soar_agent.run()` returns, so the background task only needs to call `shuffle.wait()` and publish the final result — it does not re-enter the graph.

- [ ] **Step 1: Write tests for the new async-detached behaviour**

```python
# backend/tests/test_soar_agent.py
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
    phase = PlaybookPhase(name="contain", steps=[step])
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

    wait_started = asyncio.Event()
    wait_done = asyncio.Event()

    async def slow_wait(*args, **kwargs):
        wait_started.set()
        await asyncio.sleep(0.2)
        wait_done.set()
        return {"status": "FINISHED", "steps": []}

    mock_shuffle = MagicMock()
    mock_shuffle.trigger = AsyncMock(return_value="exec-123")
    mock_shuffle.wait = slow_wait

    agent = SOARAgent()
    agent.shuffle = mock_shuffle

    with patch("agents.soar_agent.kafka_producer") as mock_kafka:
        mock_kafka.send = AsyncMock()

        returned_state = await agent.run(state)

    # Must return before wait() completes
    assert not wait_done.is_set(), "run() waited for shuffle — it should not"
    assert returned_state["soar_execution_id"] == "exec-123"
    assert returned_state["soar_result"]["status"] == "PENDING"
    assert returned_state["pipeline_stage"] == "soar_pending"

    # Let background task finish
    await asyncio.sleep(0.3)
    assert wait_done.is_set()


@pytest.mark.asyncio
async def test_soar_skips_when_not_approved():
    alert = _make_alert()
    state = _make_state(alert, approved=False)

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
    """If trigger() raises, no background task should be created."""
    alert = _make_alert()
    state = _make_state(alert)

    mock_shuffle = MagicMock()
    mock_shuffle.trigger = AsyncMock(side_effect=Exception("Shuffle down"))

    agent = SOARAgent()
    agent.shuffle = mock_shuffle

    with patch("agents.soar_agent.kafka_producer") as mock_kafka:
        mock_kafka.send = AsyncMock()
        result = await agent.run(state)

    assert result["soar_result"]["status"] == "FAILED"
    assert "Shuffle down" in result["soar_result"]["error"]


@pytest.mark.asyncio
async def test_soar_resume_publishes_audit_on_success():
    """Background task must publish SOAR_EXECUTION_COMPLETE to wazuh.audit."""
    alert = _make_alert()
    state = _make_state(alert)
    state["soar_execution_id"] = "exec-456"

    mock_shuffle = MagicMock()
    mock_shuffle.trigger = AsyncMock(return_value="exec-456")
    mock_shuffle.wait = AsyncMock(return_value={"status": "FINISHED", "steps": ["block_ip"]})

    agent = SOARAgent()
    agent.shuffle = mock_shuffle

    published_topics = []

    async def record_send(topic, payload, **kwargs):
        published_topics.append((topic, payload))

    with patch("agents.soar_agent.kafka_producer") as mock_kafka:
        mock_kafka.send = record_send
        await agent.run(state)
        await asyncio.sleep(0.05)

    audit_publishes = [t for t, _ in published_topics if t == "wazuh.audit"]
    assert len(audit_publishes) == 1


def test_extract_params_block_ip():
    step = PlaybookStep(
        step_id="s1",
        action_type="BLOCK_IP",
        target="10.0.0.1",
        parameters={},
        risk_level="LOW",
    )
    phase = PlaybookPhase(name="contain", steps=[step])
    playbook = Playbook(title="T", phases={"contain": phase})
    params = _extract_params(playbook)
    assert params["source_ip"] == "10.0.0.1"
```

- [ ] **Step 2: Run tests to verify they fail**

```
cd backend
pytest tests/test_soar_agent.py -v
```

Expected: `test_soar_returns_immediately_without_waiting FAILED` (run() currently awaits shuffle.wait)

- [ ] **Step 3: Rewrite `soar_agent.py` — add `_soar_resume` and detach `wait()`**

Replace the entire `execute_playbook` method (lines 92–276) and the class-level `SOAR_ENABLED` line. The full new file:

```python
# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Optional

import httpx

from orchestration.state import PipelineState
from schemas.audit import StepLog
from schemas.playbook import Playbook, PlaybookStep
from config.settings import settings
from infrastructure.kafka_client import kafka_producer
from services.shuffle_client import ShuffleClient

log = logging.getLogger(__name__)

SOAR_ENABLED = settings.SOAR_ENABLED

TOPIC_SOAR_ACTIONS = "wazuh.soar-actions"
TOPIC_AUDIT        = "wazuh.audit"


_CATEGORY_TO_ATTACK: dict[str, str] = {
    "malware":              "MALWARE",
    "brute_force":          "BRUTE_FORCE",
    "brute-force":          "BRUTE_FORCE",
    "privilege_escalation": "PRIVILEGE_ESCALATION",
    "privilege-escalation": "PRIVILEGE_ESCALATION",
    "data_exfiltration":    "DATA_EXFILTRATION",
    "data-exfiltration":    "DATA_EXFILTRATION",
}
_DEFAULT_ATTACK_TYPE = "MALWARE"


class SOARAgent:
    """
    Executes approved incident-response playbooks via Shuffle SOAR.

    execute_playbook() triggers the Shuffle workflow, stores execution_id in
    state, then detaches a background task for the wait + audit publish —
    freeing the consumer concurrency slot immediately (same pattern as
    HITLAgent). The pipeline graph reaches END before the Shuffle workflow
    completes; the background task handles final result logging.
    """

    def __init__(self) -> None:
        self.shuffle = ShuffleClient()

    async def run(self, state: PipelineState) -> PipelineState:
        alert    = state["alert"]
        playbook = state.get("playbook")

        if not SOAR_ENABLED:
            log.info("[SOAR] Disabled — stubbing success for alert=%s", alert.id)
            state["soar_result"]    = {"status": "STUBBED", "reason": "soar_disabled"}
            state["pipeline_stage"] = "soar_stubbed"
            state.setdefault("audit_trail", []).append(
                StepLog(agent="soar", result={"status": "STUBBED"}, ts=datetime.utcnow())
            )
            return state

        if not state.get("approved", False):
            log.warning("[SOAR] Skipping — not approved (alert=%s)", alert.id)
            state["soar_result"]    = {"status": "SKIPPED", "reason": "not_approved"}
            state["pipeline_stage"] = "soar_skipped"
            return state

        if playbook is None:
            log.error("[SOAR] No playbook in state (alert=%s)", alert.id)
            state["soar_result"]    = {"status": "FAILED", "reason": "no_playbook"}
            state["pipeline_stage"] = "soar_failed"
            return state

        return await self.execute_playbook(state, playbook)

    async def execute_playbook(
        self, state: PipelineState, playbook: Playbook
    ) -> PipelineState:
        """
        Trigger Shuffle, record execution_id, detach background resume task,
        and return immediately. The consumer slot is freed before Shuffle
        finishes executing the workflow.
        """
        alert = state["alert"]

        category    = (alert.alert_category or "").lower().replace(" ", "_")
        attack_type = _CATEGORY_TO_ATTACK.get(category, _DEFAULT_ATTACK_TYPE)
        log.info(
            "[SOAR] Triggering playbook: alert=%s attack_type=%s",
            alert.id, attack_type,
        )

        params = _extract_params(playbook)

        try:
            execution_id = await self.shuffle.trigger(
                attack_type      = attack_type,
                alert_id         = alert.id,
                agent_id         = alert.agent_id,
                agent_name       = alert.agent_name or alert.agent_id,
                source_ip        = params.get("source_ip") or alert.source_ip,
                dest_ip          = params.get("dest_ip") or alert.destination_ip,
                username         = params.get("username") or alert.user,
                pid              = params.get("pid"),
                playbook_summary = playbook.summary or playbook.title,
            )
        except (KeyError, httpx.HTTPStatusError, httpx.RequestError) as exc:
            log.error("[SOAR] Failed to trigger Shuffle: %s", exc)
            await kafka_producer.send(
                TOPIC_SOAR_ACTIONS,
                {"type": "execution_error", "alert_id": alert.id,
                 "error": str(exc), "timestamp": datetime.utcnow().isoformat()},
                key=alert.id,
            )
            state["soar_result"]    = {"status": "FAILED", "error": str(exc)}
            state["pipeline_stage"] = "soar_failed"
            state.setdefault("audit_trail", []).append(
                StepLog(agent="soar",
                        result={"status": "FAILED", "error": str(exc)},
                        error=str(exc), ts=datetime.utcnow())
            )
            return state

        state["soar_execution_id"] = execution_id
        state["soar_result"]       = {"status": "PENDING", "execution_id": execution_id}
        state["pipeline_stage"]    = "soar_pending"
        state.setdefault("audit_trail", []).append(
            StepLog(
                agent="soar",
                result={"status": "PENDING", "execution_id": execution_id},
                ts=datetime.utcnow(),
            )
        )

        log.info("[SOAR] Execution started: id=%s alert=%s — consumer freed",
                 execution_id, alert.id)

        await kafka_producer.send(
            TOPIC_SOAR_ACTIONS,
            {"type": "execution_started", "execution_id": execution_id,
             "alert_id": alert.id, "attack_type": attack_type,
             "timestamp": datetime.utcnow().isoformat()},
            key=execution_id,
        )

        asyncio.create_task(
            self._soar_resume(dict(state), execution_id, attack_type)
        )
        return state

    async def _soar_resume(
        self, parked_state: PipelineState, execution_id: str, attack_type: str
    ) -> None:
        """
        Detached task: waits for Shuffle to finish and publishes the final
        audit record. Does not re-enter the LangGraph (graph is at END).
        """
        alert = parked_state["alert"]
        try:
            result = await self.shuffle.wait(
                execution_id,
                timeout       = settings.SHUFFLE_EXECUTION_TIMEOUT,
                poll_interval = settings.SHUFFLE_POLL_INTERVAL,
            )
        except TimeoutError as exc:
            log.error("[SOAR] Execution timed out: id=%s alert=%s", execution_id, alert.id)
            await kafka_producer.send(
                TOPIC_SOAR_ACTIONS,
                {"type": "execution_timeout", "execution_id": execution_id,
                 "alert_id": alert.id, "error": str(exc),
                 "timestamp": datetime.utcnow().isoformat()},
                key=execution_id,
            )
            return
        except httpx.HTTPStatusError as exc:
            log.error("[SOAR] Shuffle API error: id=%s status=%d",
                      execution_id, exc.response.status_code)
            await kafka_producer.send(
                TOPIC_SOAR_ACTIONS,
                {"type": "execution_error", "execution_id": execution_id,
                 "alert_id": alert.id, "error": str(exc),
                 "timestamp": datetime.utcnow().isoformat()},
                key=execution_id,
            )
            return

        final_status = result.get("status", "UNKNOWN")
        log.info("[SOAR] Execution complete: id=%s status=%s alert=%s",
                 execution_id, final_status, alert.id)

        await kafka_producer.send(
            TOPIC_AUDIT,
            {"event": "SOAR_EXECUTION_COMPLETE", "execution_id": execution_id,
             "alert_id": alert.id, "attack_type": attack_type,
             "status": final_status, "steps": result.get("steps", []),
             "started_at": result.get("started_at", ""),
             "completed_at": result.get("completed_at", ""),
             "recorded_at": datetime.utcnow().isoformat()},
            key=alert.id,
        )


def _extract_params(playbook: Playbook) -> dict[str, Optional[str]]:
    """
    Walk all playbook steps and extract the first occurrence of each
    key parameter needed by Shuffle workflows.
    """
    params: dict[str, Optional[str]] = {
        "source_ip": None,
        "dest_ip":   None,
        "username":  None,
        "pid":       None,
    }

    all_steps: list[PlaybookStep] = [
        step
        for phase in playbook.phases.values()
        for step in phase.steps
    ]

    for step in all_steps:
        action = step.action_type.upper()

        if action == "BLOCK_IP" and params["source_ip"] is None:
            params["source_ip"] = step.target or step.parameters.get("ip")

        if action in ("DISABLE_USER", "RESET_PASSWORD") and params["username"] is None:
            params["username"] = step.target or step.parameters.get("username")

        if action == "KILL_PROCESS" and params["pid"] is None:
            params["pid"] = step.parameters.get("pid") or step.target

        if action == "COLLECT_FORENSICS" and params["dest_ip"] is None:
            params["dest_ip"] = step.parameters.get("dest_ip")

        for key in ("source_ip", "dest_ip", "username", "pid"):
            if params[key] is None and key in step.parameters:
                params[key] = str(step.parameters[key])

    return params


soar_agent = SOARAgent()
```

- [ ] **Step 4: Run all SOAR tests**

```
cd backend
pytest tests/test_soar_agent.py -v
```

Expected: `6 passed`

- [ ] **Step 5: Run full test suite to catch regressions**

```
cd backend
pytest tests/ -v --ignore=tests/eal4 -x
```

Expected: all passing (same as before this change)

- [ ] **Step 6: Commit**

```bash
git add backend/agents/soar_agent.py backend/tests/test_soar_agent.py
git commit -m "perf(soar): detach shuffle.wait() into background task — frees consumer slot immediately"
```

---

## Task 5: Update `docker-compose.yml` — Postgres Password, Redis Auth, Kafka Partitions

**Files:**
- Modify: `backend/docker-compose.yml`

Three hardening changes in one commit:
1. Change `POSTGRES_PASSWORD` from the hardcoded `soc_pipeline_dev` to read from env
2. Add Redis `--requirepass` via env
3. Add `KAFKA_NUM_PARTITIONS=48` so the 16 workers get 3 partitions each (same ratio as before)

- [ ] **Step 1: Edit `docker-compose.yml`**

**Kafka service** — add partition defaults after `KAFKA_AUTO_CREATE_TOPICS_ENABLE`:
```yaml
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: "false"
      KAFKA_NUM_PARTITIONS: "48"
      KAFKA_DEFAULT_REPLICATION_FACTOR: "1"
```

**Redis service** — replace the `command` line:
```yaml
    command: >
      redis-server
      --save 60 1
      --loglevel warning
      --requirepass ${REDIS_PASSWORD:-changeme_redis}
```

**PostgreSQL service** — replace the hardcoded password:
```yaml
    environment:
      POSTGRES_USER: soc
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme_postgres}
      POSTGRES_DB: soc_pipeline
```

- [ ] **Step 2: Verify compose file parses correctly**

```
cd backend
docker compose config --quiet
```

Expected: no errors (may warn about missing env vars — that's fine)

- [ ] **Step 3: Commit**

```bash
git add backend/docker-compose.yml
git commit -m "fix(compose): parameterise Postgres/Redis passwords, set 48 Kafka partitions for 16 workers"
```

---

## Task 6: Update `.env.example` with New Settings

**Files:**
- Modify: `backend/.env.example`

The `.env.example` is the reference template analysts use when deploying. All new settings from Task 1 must appear here with comments.

- [ ] **Step 1: Open `backend/.env.example` and append a new section after the existing `HITL_TIMEOUT_SECONDS` block**

Find the block that contains `HITL_TIMEOUT_SECONDS` and add immediately after it:

```dotenv
# ── Pipeline Concurrency & Throughput ────────────────────────────────────────
# Max alerts in-flight across all consumer workers (semaphore cap).
# At 1100 EPS with ~4s LLM latency you need at least 512.
PIPELINE_MAX_CONCURRENT_ALERTS=512

# Number of Kafka consumer workers. Must be <= number of topic partitions (48).
KAFKA_NUM_CONSUMER_WORKERS=16

# Max concurrent LLM inference calls. Each call holds a GPU context slot.
# Set to match vLLM --max-num-seqs (typically 64–128 on A100 80 GB).
LLM_MAX_CONCURRENT_CALLS=64

# Timeout for a single LLM completion call (seconds). 30s covers 70B at 4s/call
# plus retry headroom.
LLM_CALL_TIMEOUT_SECONDS=30.0

# How long (seconds) to cache generated playbooks keyed on (category, MITRE).
# 3600 = reuse the same playbook for 1 hour on repeated identical alerts.
PLAYBOOK_CACHE_TTL_SECONDS=3600

# How long (seconds) to cache RAG context keyed on (category, MITRE).
RAG_CTX_CACHE_TTL_SECONDS=3600

# ── Wazuh Bridge Ingestion ───────────────────────────────────────────────────
# Seconds between Wazuh API polls. 1 = poll every second.
# Combined with WAZUH_BATCH_SIZE this determines max ingestion EPS.
WAZUH_POLL_INTERVAL=1

# Max alerts fetched per poll. 1200 at 1s interval = 1200 EPS ceiling.
WAZUH_BATCH_SIZE=1200

# ── Infrastructure Passwords (required in production) ────────────────────────
POSTGRES_PASSWORD=<CHANGE_ME>
REDIS_PASSWORD=<CHANGE_ME>
```

- [ ] **Step 2: Verify no syntax errors by running a quick grep**

```
grep -n "PIPELINE_MAX_CONCURRENT_ALERTS\|KAFKA_NUM_CONSUMER_WORKERS\|LLM_MAX_CONCURRENT_CALLS\|WAZUH_POLL_INTERVAL\|WAZUH_BATCH_SIZE" backend/.env.example
```

Expected: 5 lines printed (one per new key).

- [ ] **Step 3: Commit**

```bash
git add backend/.env.example
git commit -m "docs(env): document all 1100-EPS performance settings in .env.example"
```

---

## Self-Review

**Spec coverage check:**

| Requirement from analysis | Task |
|---|---|
| `LLM_MAX_CONCURRENT_CALLS=64` | Task 1 + Task 2 |
| `PIPELINE_MAX_CONCURRENT_ALERTS=512` | Task 1 + Task 2 |
| `KAFKA_NUM_CONSUMER_WORKERS=16` | Task 1 + Task 2 |
| `PLAYBOOK_CACHE_TTL_SECONDS=3600` | Task 1 |
| `WAZUH_BATCH_SIZE=1200, WAZUH_POLL_INTERVAL=1` | Task 1 + Task 3 |
| Detach `soar_agent.wait()` non-blocking | Task 4 |
| Postgres password parameterised | Task 5 |
| Redis `--requirepass` | Task 5 |
| Kafka 48 partitions for 16 workers | Task 5 |
| `.env.example` updated | Task 6 |
| `SOAR_ENABLED` read from `settings` | Task 1 + Task 4 |

**Placeholder scan:** None found.

**Type consistency:**
- `SOAR_ENABLED` defined as `bool` in `settings.py`, read as `settings.SOAR_ENABLED` in `soar_agent.py` ✓
- `_soar_resume` takes `PipelineState` (which is `dict`) — consistent with HITL pattern ✓
- `execute_playbook` returns `PipelineState` in all paths ✓

---

## Execution Handoff

Plan saved. Two execution options:

**1. Subagent-Driven (recommended)** — Fresh subagent per task, review between tasks

**2. Inline Execution** — Execute tasks in this session using executing-plans skill

Which approach?
