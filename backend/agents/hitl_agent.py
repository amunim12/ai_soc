# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0


from __future__ import annotations

import asyncio
import logging
import os
import smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

try:
    import aiosmtplib
    _AIOSMTP_AVAILABLE = True
except ImportError:
    _AIOSMTP_AVAILABLE = False

try:
    from slack_sdk.webhook.async_client import AsyncWebhookClient
    _SLACK_AVAILABLE = True
except ImportError:
    _SLACK_AVAILABLE = False
    AsyncWebhookClient = None  # type: ignore

from dotenv import load_dotenv
from schemas.playbook import Playbook, IRREVERSIBLE_ACTIONS
from schemas.hitl import ApprovalDecision
from schemas.audit import StepLog
from orchestration.state import PipelineState
from infrastructure.kafka_client import kafka_producer
from infrastructure.sqlite_client import sqlite_client

load_dotenv()
log = logging.getLogger(__name__)

TIMEOUT_SECONDS  = int(os.getenv("HITL_TIMEOUT_SECONDS", "900"))
ESCALATE_SECONDS = int(os.getenv("HITL_ESCALATE_SECONDS", "600"))
POLL_INTERVAL    = 5

SLACK_WEBHOOK  = os.getenv("SLACK_WEBHOOK_URL", "")
SMTP_HOST      = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT      = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER      = os.getenv("SMTP_USER", "")
SMTP_PASSWORD  = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM      = os.getenv("SMTP_FROM", "soc-pipeline@example.com")
ANALYST_EMAIL  = os.getenv("ANALYST_EMAIL", "analyst@example.com")
HITL_API_BASE  = os.getenv("HITL_API_BASE", "http://localhost:8080")


class HITLAgent:
    """Human-in-the-Loop agent that pauses the pipeline for analyst review."""


    async def run(self, state: PipelineState) -> PipelineState:
        """
        Park the alert for analyst review and return immediately.

        Why: the previous implementation blocked inside `_await_decision` for
        up to HITL_TIMEOUT_SECONDS, which held the consumer's concurrency slot
        for the entire review window and destroyed Kafka throughput. Now HITL
        notifies, detaches a background task that waits for the decision and
        resumes the pipeline, and returns — freeing the worker immediately.
        """
        alert    = state["alert"]
        playbook = state["playbook"]
        reason   = self._explain_reason(state)

        log.info("[HITL] Requesting human review — alert=%s reason='%s'",
                  alert.id, reason)


        timeout_at = datetime.utcnow() + timedelta(seconds=TIMEOUT_SECONDS)
        review_id = await sqlite_client.store_pending_review(
            alert=alert,
            playbook=playbook,
            confidence=state.get("confidence", 0.0),
            reason=reason,
            expires_at=timeout_at,
        )
        state["hitl_timeout_at"] = timeout_at
        state["hitl_review_id"] = review_id


        await kafka_producer.send("wazuh.hitl-queue", {
            "review_id": review_id,
            "alert_id": alert.id,
            "alert_severity": alert.severity,
            "alert_description": alert.rule_description,
            "confidence": state.get("confidence", 0.0),
            "reason": reason,
            "playbook_summary": {
                "total_steps": playbook.total_steps,
                "has_irreversible": playbook.has_irreversible_steps,
                "estimated_duration_minutes": playbook.estimated_duration_minutes,
            },
            "expires_at": timeout_at.isoformat(),
            "hitl_url": f"{HITL_API_BASE}/api/hitl/{review_id}/decision",
        })


        await asyncio.gather(
            self._notify_slack(alert, review_id, reason, state.get("confidence", 0.0)),
            self._notify_email(alert, review_id, reason),
            self._notify_electron(alert, review_id),
            return_exceptions=True,
        )

        state["pipeline_stage"] = "hitl_pending"
        state.setdefault("audit_trail", []).append(
            StepLog(
                agent="hitl",
                result={"review_id": review_id, "parked": True, "reason": reason},
                ts=datetime.utcnow(),
            )
        )


        asyncio.create_task(self._resume_after_decision(dict(state), review_id))
        log.info("[HITL] Parked alert %s (review=%s) — consumer freed", alert.id, review_id)
        return state


    async def _resume_after_decision(
        self, parked_state: PipelineState, review_id: str
    ) -> None:
        """
        Detached resume task: waits for the analyst decision and runs the
        remainder of the pipeline (SOAR execution / drop / escalate) without
        holding a consumer concurrency slot.
        """
        from agents.supervisor import supervisor_agent
        from agents.soar_agent import soar_agent

        alert = parked_state["alert"]
        try:
            decision = await self._await_decision(review_id, alert)
            await sqlite_client.store_decision(decision)

            parked_state["hitl_decision"] = decision
            parked_state["approved"] = decision.action in ("APPROVE", "EDIT")
            parked_state["pipeline_stage"] = "hitl_complete"
            parked_state.setdefault("audit_trail", []).append(
                StepLog(
                    agent="hitl:resume",
                    result={
                        "review_id": review_id,
                        "action": decision.action,
                        "analyst_id": decision.analyst_id,
                        "elapsed_seconds": decision.elapsed_seconds,
                    },
                    ts=datetime.utcnow(),
                )
            )

            if decision.action in ("APPROVE", "EDIT"):
                await supervisor_agent.publish_to_soar(parked_state)
                await soar_agent.run(parked_state)
            elif decision.action == "ESCALATE":
                await supervisor_agent.escalate_to_senior(parked_state)
            else:
                await supervisor_agent.drop_and_log(parked_state)

            log.info(
                "[HITL] Resumed alert %s → action=%s analyst=%s elapsed=%ds",
                alert.id, decision.action, decision.analyst_id, decision.elapsed_seconds,
            )
        except Exception as exc:
            log.error("[HITL] Resume task failed for alert %s: %s", alert.id, exc)


    async def _notify_slack(
        self, alert, review_id: str, reason: str, confidence: float
    ) -> None:
        if not SLACK_WEBHOOK:
            log.debug("[HITL] Slack webhook not configured — skipping")
            return
        try:
            client = AsyncWebhookClient(SLACK_WEBHOOK)
            await client.send(
                text=f":rotating_light: *HITL Review Required* | Alert: {alert.id}",
                blocks=[
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f":rotating_light: *HITL Review Required*\n"
                                f"*Alert:* `{alert.id}` — {alert.rule_description}\n"
                                f"*Severity:* {alert.severity}\n"
                                f"*Reason:* {reason}\n"
                                f"*Confidence:* {confidence:.0%}\n"
                                f"*Review URL:* {HITL_API_BASE}/api/hitl/{review_id}/decision\n"
                                f"*Timeout:* {TIMEOUT_SECONDS // 60} minutes"
                            ),
                        },
                    }
                ],
            )
            log.info("[HITL] Slack notification sent")
        except Exception as exc:
            log.warning("[HITL] Slack notification failed: %s", exc)

    async def _notify_email(self, alert, review_id: str, reason: str) -> None:
        if not SMTP_USER or not ANALYST_EMAIL:
            log.debug("[HITL] Email not configured — skipping")
            return
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[SOC] HITL Review Required — {alert.severity} Alert {alert.id}"
            msg["From"]    = SMTP_FROM
            msg["To"]      = ANALYST_EMAIL

            html = f"""
            <html><body>
            <h2>🚨 HITL Review Required</h2>
            <table>
              <tr><td><b>Alert ID</b></td><td>{alert.id}</td></tr>
              <tr><td><b>Description</b></td><td>{alert.rule_description}</td></tr>
              <tr><td><b>Severity</b></td><td>{alert.severity}</td></tr>
              <tr><td><b>Reason</b></td><td>{reason}</td></tr>
              <tr><td><b>Action URL</b></td>
                  <td><a href="{HITL_API_BASE}/api/hitl/{review_id}/decision">
                    Submit Decision</a></td></tr>
              <tr><td><b>Timeout</b></td><td>{TIMEOUT_SECONDS // 60} minutes</td></tr>
            </table>
            </body></html>
            """
            msg.attach(MIMEText(html, "html"))
            if _AIOSMTP_AVAILABLE:
                await aiosmtplib.send(  # type: ignore[name-defined]
                    msg,
                    hostname=SMTP_HOST,
                    port=SMTP_PORT,
                    username=SMTP_USER,
                    password=SMTP_PASSWORD,
                    start_tls=True,
                )
            else:
                log.warning("[HITL] aiosmtplib not installed — email skipped")
            log.info("[HITL] Email notification sent → %s", ANALYST_EMAIL)
        except Exception as exc:
            log.warning("[HITL] Email notification failed: %s", exc)

    async def _notify_electron(self, alert, review_id: str) -> None:
        """
        Stub for Electron IPC notification.
        In the full stack, this would write to a named pipe or local socket
        that the Electron desktop app listens on.
        """
        log.info(
            "[HITL] [Electron IPC stub] Pushing review %s to desktop app "
            "(alert=%s severity=%s)",
            review_id, alert.id, alert.severity,
        )


    async def _await_decision(self, review_id: str, alert) -> ApprovalDecision:
        start = datetime.utcnow()

        if hasattr(sqlite_client, "wait_for_decision"):
            decision = await sqlite_client.wait_for_decision(
                review_id=review_id,
                timeout_seconds=TIMEOUT_SECONDS,
                escalate_seconds=ESCALATE_SECONDS,
                on_escalate=lambda rid, elapsed: self._escalate(rid, alert, elapsed),
            )
            elapsed = int((datetime.utcnow() - start).total_seconds())
            if decision is None:
                log.warning("[HITL] Timeout (%ds) — auto-partial-approving review %s",
                             TIMEOUT_SECONDS, review_id)
                return self._auto_partial_approve(review_id, elapsed)
            decision.elapsed_seconds = elapsed
            return decision

        # SQLite fallback: poll every POLL_INTERVAL seconds
        escalated = False
        while True:
            elapsed = int((datetime.utcnow() - start).total_seconds())

            if elapsed >= ESCALATE_SECONDS and not escalated:
                await self._escalate(review_id, alert, elapsed)
                escalated = True

            if elapsed >= TIMEOUT_SECONDS:
                log.warning("[HITL] Timeout (%ds) — auto-partial-approving review %s",
                             TIMEOUT_SECONDS, review_id)
                return self._auto_partial_approve(review_id, elapsed)

            decision = await sqlite_client.poll_decision(review_id)
            if decision:
                decision.elapsed_seconds = elapsed
                return decision

            await asyncio.sleep(POLL_INTERVAL)

    async def _escalate(self, review_id: str, alert, elapsed: int) -> None:
        log.warning("[HITL] Escalating review %s to senior analyst (elapsed=%ds)",
                     review_id, elapsed)

        await kafka_producer.send("wazuh.hitl-queue", {
            "type": "ESCALATION",
            "review_id": review_id,
            "alert_id": alert.id,
            "elapsed_seconds": elapsed,
            "message": f"No decision after {elapsed // 60} minutes — escalating to senior analyst",
        })

    def _auto_partial_approve(self, review_id: str, elapsed: int) -> ApprovalDecision:
        """
        On timeout, auto-approve only reversible steps.
        Returns an APPROVE decision so the pipeline continues.
        The supervisor's publish_to_soar will filter irreversible steps.
        """
        return ApprovalDecision(
            review_id=review_id,
            action="APPROVE",
            analyst_id="system:timeout",
            notes=(
                f"Auto-approved after {TIMEOUT_SECONDS // 60}-minute timeout. "
                "Irreversible steps have been removed by the supervisor."
            ),
            final_playbook=None,
            elapsed_seconds=elapsed,
        )


    def _explain_reason(self, state: PipelineState) -> str:
        reasons: list[str] = []
        confidence = state.get("confidence", 0.0)
        if confidence < 0.85:
            reasons.append(f"Low confidence ({confidence:.0%})")
        alert = state["alert"]
        if alert.severity == "CRITICAL":
            reasons.append("Critical severity alert")
        playbook = state.get("playbook")
        if playbook and playbook.has_irreversible_steps:
            reasons.append("Playbook contains irreversible steps (ISOLATE/DISABLE/REVOKE)")
        return " · ".join(reasons) or "Manual review policy"

    def _has_irreversible(self, playbook: Optional[Playbook]) -> bool:
        if not playbook:
            return False
        return playbook.has_irreversible_steps


hitl_agent = HITLAgent()
