# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

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
        except (KeyError, httpx.HTTPStatusError, httpx.RequestError, Exception) as exc:
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
