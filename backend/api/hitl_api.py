# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
FastAPI HITL Decision API — api/hitl_api.py

Endpoints:
  POST /api/hitl/{review_id}/decision  — Analyst submits a decision
  GET  /api/hitl/{review_id}/status    — Check review status
  GET  /health                         — Health check
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel
from typing import Optional

from schemas.hitl import ApprovalDecision
from schemas.playbook import Playbook
from schemas.audit import AuditEntry, StepLog
from infrastructure.sqlite_client import sqlite_client
from infrastructure.kafka_client import kafka_producer
from api.metrics_middleware import prometheus_middleware, metrics_endpoint
from api.auth_api import get_current_user
from datetime import datetime
from starlette.middleware.base import BaseHTTPMiddleware


load_dotenv()
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: initialise SQLite tables."""
    await sqlite_client.initialise()
    log.info("HITL API started — SQLite initialised")
    yield
    kafka_producer.flush()
    log.info("HITL API shutting down")


app = FastAPI(
    title="AI SOC — HITL Decision API",
    description="Receive analyst decisions for Human-in-the-Loop pipeline reviews",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(BaseHTTPMiddleware, dispatch=prometheus_middleware)
app.add_route("/metrics", metrics_endpoint, methods=["GET"])


class DecisionRequest(BaseModel):
    action: str
    analyst_id: str
    notes: Optional[str] = ""
    final_playbook_yaml: Optional[str] = None


class DecisionResponse(BaseModel):
    review_id: str
    action: str
    recorded: bool
    message: str


class StatusResponse(BaseModel):
    review_id: str
    status: str
    decision: Optional[dict] = None


@app.post("/api/hitl/{review_id}/decision", response_model=DecisionResponse)
async def submit_decision(
    review_id: str,
    body: DecisionRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
) -> DecisionResponse:
    """
    Analyst submits a decision for a pending HITL review.
    The pipeline is polling SQLite and will pick this up within 5 seconds.

    For terminal actions (ESCALATE / REJECT) we also write an immediate
    audit_log entry so the Overview metrics card reflects the change
    without waiting for the background orchestration engine.
    """
    if body.action not in ("APPROVE", "EDIT", "REJECT", "ESCALATE"):
        raise HTTPException(
            status_code=422,
            detail=f"Invalid action '{body.action}'. Must be APPROVE | EDIT | REJECT | ESCALATE",
        )


    final_playbook = None
    if body.action == "EDIT" and body.final_playbook_yaml:
        try:
            final_playbook = Playbook.from_yaml(body.final_playbook_yaml)
        except Exception as exc:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid playbook YAML: {exc}",
            )

    decision = ApprovalDecision(
        review_id=review_id,
        action=body.action,
        analyst_id=body.analyst_id,
        notes=body.notes or "",
        final_playbook=final_playbook,
        elapsed_seconds=0,
    )


    await sqlite_client.store_decision(decision)
    log.info("Decision recorded: review=%s action=%s analyst=%s",
              review_id, body.action, body.analyst_id)


    outcome_map = {"ESCALATE": "ESCALATED", "REJECT": "DROPPED"}
    if body.action in outcome_map:
        review_row = await sqlite_client.get_review_by_id(review_id)
        alert_id = review_row["alert_id"] if review_row else review_id
        audit = AuditEntry(
            alert_id=alert_id,
            pipeline_trace=[],
            outcome=outcome_map[body.action],
            timestamp=datetime.utcnow(),
            analyst_id=body.analyst_id,
        )
        await sqlite_client.store_audit_entry(audit)
        log.info("Immediate audit entry written: alert=%s outcome=%s",
                  alert_id, outcome_map[body.action])


    background_tasks.add_task(
        kafka_producer.send,
        "wazuh.audit",
        {
            "event": "HITL_DECISION",
            "review_id": review_id,
            "action": body.action,
            "analyst_id": body.analyst_id,
        },
    )

    return DecisionResponse(
        review_id=review_id,
        action=body.action,
        recorded=True,
        message=f"Decision '{body.action}' recorded. Pipeline will resume within ~5 seconds.",
    )


@app.get("/api/hitl/{review_id}/status", response_model=StatusResponse)
async def get_review_status(review_id: str) -> StatusResponse:
    """Check the current status of a HITL review."""
    decision = await sqlite_client.poll_decision(review_id)
    if decision:
        return StatusResponse(
            review_id=review_id,
            status="DECIDED",
            decision={
                "action": decision.action,
                "analyst_id": decision.analyst_id,
                "notes": decision.notes,
                "decided_at": decision.decided_at.isoformat(),
            },
        )
    return StatusResponse(review_id=review_id, status="PENDING")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "hitl_api"}
