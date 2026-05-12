# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Supervisor Agent — Central orchestrator

Implements all four conditional routing methods:
  route_after_analysis()
  route_after_enrichment()
  route_after_playbook()
  route_after_hitl()

Also owns the terminal graph nodes:
  publish_to_soar()
  drop_and_log()
  escalate_to_senior()
"""
from __future__ import annotations

import logging
from datetime import datetime

from schemas.audit import AuditEntry, StepLog
from schemas.playbook import Playbook, IRREVERSIBLE_ACTIONS
from orchestration.state import PipelineState
from infrastructure.kafka_client import kafka_producer
from infrastructure.sqlite_client import sqlite_client

log = logging.getLogger(__name__)

CONFIDENCE_THRESHOLD = 0.85


class SupervisorAgent:
    """
    Central orchestrator. Runs on LangGraph StateGraph.
    Contains only routing logic — no agent-specific business logic.
    """


    def route_after_analysis(self, state: PipelineState) -> str:
        """
        After log analysis, decide next step.
        Returns: 'enrich' | 'skip_to_playbook' | 'drop'
        """
        analysis = state.get("analysis")
        if analysis is None:
            log.error("[Supervisor] route_after_analysis: analysis is None — dropping")
            return "drop"

        if analysis.is_duplicate:
            log.info("[Supervisor] route_after_analysis: duplicate → drop")
            return "drop"

        if analysis.noise_filtered:
            log.info("[Supervisor] route_after_analysis: noise → drop")
            return "drop"

        if not analysis.has_iocs:
            log.info("[Supervisor] route_after_analysis: no IOCs → skip_to_playbook")
            return "skip_to_playbook"

        log.info("[Supervisor] route_after_analysis: has IOCs → enrich")
        return "enrich"

    def route_after_enrichment(self, state: PipelineState) -> str:
        """After TI enrichment — always generate playbook."""
        return "generate_playbook"

    def route_after_playbook(self, state: PipelineState) -> str:
        """
        Supervisor evaluates playbook confidence.
        Routes to HITL if: confidence < 0.85, CRITICAL severity,
        or any irreversible actions present.
        """
        playbook = state.get("playbook")
        if playbook is None:
            log.error("[Supervisor] route_after_playbook: playbook is None → hitl")
            return "hitl"

        confidence = playbook.confidence_score
        severity   = state["alert"].severity
        irreversible = playbook.has_irreversible_steps

        log.info(
            "[Supervisor] route_after_playbook: confidence=%.2f severity=%s irreversible=%s",
            confidence, severity, irreversible,
        )

        if confidence < CONFIDENCE_THRESHOLD or severity == "CRITICAL" or irreversible:
            state["requires_hitl"] = True
            return "hitl"


        return "execute"

    def route_after_hitl(self, state: PipelineState) -> str:
        """
        Route based on the HITL node's outcome.

        With the decoupled HITL path, the HITL node returns immediately after
        parking the review and no decision is present — we route to 'park',
        which ends the graph. The detached resume task in HITLAgent runs the
        remaining pipeline stages when the analyst eventually decides.
        """
        if state.get("pipeline_stage") == "hitl_pending":
            log.info("[Supervisor] route_after_hitl: parked → ending graph")
            return "park"

        decision = state.get("hitl_decision")
        if decision is None:
            log.error("[Supervisor] route_after_hitl: no decision — dropping")
            return "drop"

        log.info("[Supervisor] route_after_hitl: action=%s", decision.action)

        action_map = {
            "APPROVE":   "execute",
            "EDIT":      "generate_playbook",
            "REJECT":    "drop",
            "ESCALATE":  "escalate",
        }
        return action_map.get(decision.action, "drop")


    async def publish_to_soar(self, state: PipelineState) -> PipelineState:
        """
        Final execution node — publish approved playbook to Kafka topics.
        If HITL edited the playbook, use the analyst's version.
        Strips irreversible steps if the approval was a timeout auto-approve.
        """

        state["approved"] = True
        playbook = state.get("playbook")
        decision = state.get("hitl_decision")
        alert    = state["alert"]


        if decision and decision.final_playbook:
            playbook = decision.final_playbook


        if (decision and
                decision.analyst_id.startswith("system:") and
                playbook and
                playbook.has_irreversible_steps):
            playbook = _strip_irreversible(playbook)
            log.warning("[Supervisor] Stripped irreversible steps from auto-approved playbook")


        await kafka_producer.send("wazuh.playbooks", playbook)
        log.info("[Supervisor] Playbook published → wazuh.playbooks (alert=%s)", alert.id)


        audit = AuditEntry(
            alert_id=alert.id,
            pipeline_trace=state.get("audit_trail", []),
            outcome="EXECUTED",
            timestamp=datetime.utcnow(),
            analyst_id=decision.analyst_id if decision else None,
            hitl_elapsed_seconds=decision.elapsed_seconds if decision else None,
        )
        await kafka_producer.send("wazuh.audit", audit)
        await sqlite_client.store_audit_entry(audit)

        state["pipeline_stage"] = "executed"
        state.setdefault("audit_trail", []).append(
            StepLog(agent="supervisor:execute", result={"outcome": "EXECUTED"}, ts=datetime.utcnow())
        )
        return state

    async def drop_and_log(self, state: PipelineState) -> PipelineState:
        """Drop alert — log noise, duplicate, or reject."""
        alert = state["alert"]
        analysis = state.get("analysis")

        reason = "rejected_by_hitl"
        if analysis:
            if analysis.is_duplicate:
                reason = "duplicate"
            elif analysis.noise_filtered:
                reason = "noise"

        log.info("[Supervisor] Dropping alert %s — reason=%s", alert.id, reason)

        audit = AuditEntry(
            alert_id=alert.id,
            pipeline_trace=state.get("audit_trail", []),
            outcome="DROPPED",
            timestamp=datetime.utcnow(),
        )
        await kafka_producer.send("wazuh.audit", audit)
        await sqlite_client.store_audit_entry(audit)

        state["pipeline_stage"] = "dropped"
        state.setdefault("audit_trail", []).append(
            StepLog(agent="supervisor:drop", result={"reason": reason}, ts=datetime.utcnow())
        )
        return state

    async def escalate_to_senior(self, state: PipelineState) -> PipelineState:
        """Escalate to senior analyst when HITL action=ESCALATE."""
        alert = state["alert"]
        log.warning("[Supervisor] Escalating alert %s to senior analyst", alert.id)

        await kafka_producer.send("wazuh.hitl-queue", {
            "type": "SENIOR_ESCALATION",
            "alert_id": alert.id,
            "severity": alert.severity,
            "reason": "Analyst escalated to senior review",
            "playbook": state.get("playbook", {}).model_dump() if state.get("playbook") else None,
        })


        hitl_dec = state.get("hitl_decision")
        audit = AuditEntry(
            alert_id=alert.id,
            pipeline_trace=state.get("audit_trail", []),
            outcome="ESCALATED",
            timestamp=datetime.utcnow(),
            analyst_id=hitl_dec.analyst_id if hitl_dec else None,
        )
        await kafka_producer.send("wazuh.audit", audit)
        await sqlite_client.store_audit_entry(audit)

        state["pipeline_stage"] = "escalated"
        state.setdefault("audit_trail", []).append(
            StepLog(agent="supervisor:escalate", result={"outcome": "ESCALATED"}, ts=datetime.utcnow())
        )
        return state


def _strip_irreversible(playbook: Playbook) -> Playbook:
    """Return a copy of the playbook with irreversible steps removed."""
    import copy
    pb = copy.deepcopy(playbook)
    for phase in pb.phases.values():
        phase.steps = [s for s in phase.steps if not s.is_irreversible]
    return pb


supervisor_agent = SupervisorAgent()
