# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
SOAR Router — routes/soar.py

FastAPI APIRouter with prefix="/api/soar".
Handles Shuffle SOAR webhook callbacks and analyst decision endpoints.

Endpoints:
  POST /api/soar/execution-result        — Shuffle calls when workflow finishes
  POST /api/soar/hitl-gate               — Shuffle calls at HITL pause step
  POST /api/soar/hitl-approve/{exec_id}  — Dashboard: analyst approves
  POST /api/soar/hitl-reject/{exec_id}   — Dashboard: analyst rejects
  GET  /api/soar/execution/{exec_id}     — Dashboard: live SOAR trace
  GET  /api/soar/executions              — Dashboard: execution history

SQLite table: soar_hitl_requests
  (created by initialise_soar_tables() called from the lifespan event in main.py)

Mirrors the pattern used in api/hitl_api.py and infrastructure/sqlite_client.py.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Optional

import aiosqlite
import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from config.settings import settings
from infrastructure.kafka_client import kafka_producer
from infrastructure.sqlite_client import sqlite_client
from services.shuffle_client import shuffle_client

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/soar", tags=["soar"])


TOPIC_SOAR_ACTIONS = "wazuh.soar-actions"
TOPIC_HITL_QUEUE   = "wazuh.hitl-queue"
TOPIC_AUDIT        = "wazuh.audit"


SOAR_DDL = """
CREATE TABLE IF NOT EXISTS soar_hitl_requests (
    id            TEXT PRIMARY KEY,
    execution_id  TEXT NOT NULL UNIQUE,
    alert_id      TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'PENDING',
    evidence_json TEXT,
    analyst_id    TEXT,
    decided_at    TEXT,
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_soar_hitl_exec
    ON soar_hitl_requests(execution_id);
"""


async def initialise_soar_tables() -> None:
    """
    Create SOAR-specific SQLite tables if they don't exist.
    Called from the FastAPI lifespan event in main.py alongside
    sqlite_client.initialise().
    """
    async with aiosqlite.connect(sqlite_client.db_path) as db:
        await db.executescript(SOAR_DDL)
        await db.commit()
    log.info("SOAR SQLite tables initialised")


class ExecutionResultPayload(BaseModel):
    """Payload sent by Shuffle's 'notify' step when a workflow finishes."""
    execution_id: str
    workflow:     str
    status:       str
    results:      dict[str, Any] = {}


class HitlGatePayload(BaseModel):
    """Payload sent by Shuffle's 'hitl_gate' step to pause mid-workflow."""
    execution_id: str
    alert_id:     str

    forensics:    Optional[Any] = None
    pcap:         Optional[Any] = None
    agent_name:   Optional[str] = None
    dest_ip:      Optional[str] = None
    username:     Optional[str] = None
    pid:          Optional[str] = None


@router.post("/execution-result")
async def execution_result(payload: ExecutionResultPayload) -> dict[str, bool]:
    """
    Receive workflow completion callback from Shuffle.

    Called by the 'notify' step at the end of every workflow.
    Publishes the result to the SOAR_ACTIONS Kafka topic so the
    SOARAgent (blocked in shuffle_client.wait()) can pick it up.

    Returns:
        {"ok": True}
    """
    log.info(
        "[SOAR] execution-result received: id=%s workflow=%s status=%s",
        payload.execution_id, payload.workflow, payload.status,
    )

    await kafka_producer.send(
        TOPIC_SOAR_ACTIONS,
        {
            "type":         "execution_complete",
            "execution_id": payload.execution_id,
            "workflow":     payload.workflow,
            "status":       payload.status,
            "results":      payload.results,
            "received_at":  datetime.utcnow().isoformat(),
        },
        key=payload.execution_id,
    )

    return {"ok": True}


@router.post("/hitl-gate")
async def hitl_gate(payload: HitlGatePayload) -> dict[str, bool]:
    """
    Receive mid-workflow HITL pause notification from Shuffle.

    Shuffle calls this endpoint when it reaches a 'hitl_gate' step
    (privilege-escalation and data-exfiltration workflows).
    Returns 200 immediately — Shuffle blocks and waits for the analyst
    to call POST /api/soar/hitl-approve/{execution_id} to resume.

    Actions:
      1. Persist the pending HITL request in SQLite (soar_hitl_requests table)
      2. Publish to HITL_QUEUE Kafka topic so the dashboard is notified

    Returns:
        {"queued": True}
    """
    log.info(
        "[SOAR] hitl-gate received: execution_id=%s alert_id=%s",
        payload.execution_id, payload.alert_id,
    )

    evidence = {
        "forensics": payload.forensics,
        "pcap":      payload.pcap,
        "agent_name": payload.agent_name,
        "dest_ip":   payload.dest_ip,
        "username":  payload.username,
        "pid":       payload.pid,
    }


    request_id = str(uuid.uuid4())
    async with aiosqlite.connect(sqlite_client.db_path) as db:
        await db.execute(
            """
            INSERT INTO soar_hitl_requests
              (id, execution_id, alert_id, status, evidence_json, created_at)
            VALUES (?, ?, ?, 'PENDING', ?, ?)
            """,
            (
                request_id,
                payload.execution_id,
                payload.alert_id,
                json.dumps(evidence),
                datetime.utcnow().isoformat(),
            ),
        )
        await db.commit()

    log.info(
        "[SOAR] HITL request stored: id=%s execution_id=%s",
        request_id, payload.execution_id,
    )


    await kafka_producer.send(
        TOPIC_HITL_QUEUE,
        {
            "type":         "hitl_pending",
            "request_id":   request_id,
            "execution_id": payload.execution_id,
            "alert_id":     payload.alert_id,
            "evidence":     evidence,
            "approve_url":  (
                f"{settings.FASTAPI_INTERNAL_URL}"
                f"/api/soar/hitl-approve/{payload.execution_id}"
            ),
            "reject_url": (
                f"{settings.FASTAPI_INTERNAL_URL}"
                f"/api/soar/hitl-reject/{payload.execution_id}"
            ),
            "queued_at": datetime.utcnow().isoformat(),
        },
        key=payload.execution_id,
    )

    return {"queued": True}


@router.post("/hitl-approve/{execution_id}")
async def hitl_approve(
    execution_id: str,
    analyst_id:   str = Query(..., description="Analyst user ID"),
) -> dict[str, bool]:
    """
    Analyst approves a pending HITL Shuffle execution.

    Actions:
      1. POST to Shuffle /api/v1/workflowexecutions/{id}/continue
         to resume the paused workflow
      2. Mark the request as APPROVED in SQLite
      3. Publish hitl_approved event to HITL_QUEUE Kafka topic

    Args:
        execution_id: Shuffle execution UUID (path param).
        analyst_id:   Analyst user ID (query param).

    Returns:
        {"resumed": bool} — True if Shuffle accepted the resume.

    Raises:
        HTTPException 404: If no pending HITL request exists for this execution_id.
        HTTPException 502: If Shuffle rejects the /continue call.
    """
    log.info(
        "[SOAR] hitl-approve: execution_id=%s analyst=%s",
        execution_id, analyst_id,
    )


    async with aiosqlite.connect(sqlite_client.db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id FROM soar_hitl_requests WHERE execution_id = ? AND status = 'PENDING'",
            (execution_id,),
        ) as cursor:
            row = await cursor.fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"No pending HITL request found for execution_id={execution_id}",
        )

    approved_at = datetime.utcnow().isoformat()


    try:
        resumed = await shuffle_client.resume(
            execution_id,
            {"analyst_id": analyst_id, "approved_at": approved_at, "decision": "approved"},
        )
    except httpx.HTTPStatusError as exc:
        log.error(
            "[SOAR] Shuffle resume rejected: execution_id=%s status=%d",
            execution_id, exc.response.status_code,
        )
        raise HTTPException(
            status_code=502,
            detail=(
                f"Shuffle rejected resume for execution_id={execution_id}: "
                f"HTTP {exc.response.status_code}"
            ),
        )


    async with aiosqlite.connect(sqlite_client.db_path) as db:
        await db.execute(
            """
            UPDATE soar_hitl_requests
               SET status = 'APPROVED', analyst_id = ?, decided_at = ?
             WHERE execution_id = ?
            """,
            (analyst_id, approved_at, execution_id),
        )
        await db.commit()


    await kafka_producer.send(
        TOPIC_HITL_QUEUE,
        {
            "type":         "hitl_approved",
            "execution_id": execution_id,
            "analyst_id":   analyst_id,
            "approved_at":  approved_at,
            "resumed":      resumed,
        },
        key=execution_id,
    )

    log.info(
        "[SOAR] HITL approved: execution_id=%s analyst=%s resumed=%s",
        execution_id, analyst_id, resumed,
    )
    return {"resumed": resumed}


@router.post("/hitl-reject/{execution_id}")
async def hitl_reject(
    execution_id: str,
    analyst_id:   str = Query(..., description="Analyst user ID"),
    reason:       str = Query("", description="Optional rejection reason"),
) -> dict[str, bool]:
    """
    Analyst rejects a pending HITL Shuffle execution.

    Actions:
      1. Call ShuffleClient.abort(execution_id) to terminate the workflow
      2. Mark the request as REJECTED in SQLite
      3. Publish hitl_rejected event to HITL_QUEUE Kafka topic

    Args:
        execution_id: Shuffle execution UUID (path param).
        analyst_id:   Analyst user ID (query param).
        reason:       Human-readable rejection reason (optional query param).

    Returns:
        {"aborted": bool} — True if Shuffle successfully aborted.

    Raises:
        HTTPException 404: If no pending HITL request exists for this execution_id.
        HTTPException 502: If Shuffle rejects the abort call.
    """
    log.info(
        "[SOAR] hitl-reject: execution_id=%s analyst=%s reason='%s'",
        execution_id, analyst_id, reason,
    )


    async with aiosqlite.connect(sqlite_client.db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id FROM soar_hitl_requests WHERE execution_id = ? AND status = 'PENDING'",
            (execution_id,),
        ) as cursor:
            row = await cursor.fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"No pending HITL request found for execution_id={execution_id}",
        )

    decided_at = datetime.utcnow().isoformat()


    try:
        aborted = await shuffle_client.abort(execution_id)
    except httpx.HTTPStatusError as exc:
        log.error(
            "[SOAR] Shuffle abort rejected: execution_id=%s status=%d",
            execution_id, exc.response.status_code,
        )
        raise HTTPException(
            status_code=502,
            detail=(
                f"Shuffle rejected abort for execution_id={execution_id}: "
                f"HTTP {exc.response.status_code}"
            ),
        )


    async with aiosqlite.connect(sqlite_client.db_path) as db:
        await db.execute(
            """
            UPDATE soar_hitl_requests
               SET status = 'REJECTED', analyst_id = ?, decided_at = ?
             WHERE execution_id = ?
            """,
            (analyst_id, decided_at, execution_id),
        )
        await db.commit()


    await kafka_producer.send(
        TOPIC_HITL_QUEUE,
        {
            "type":         "hitl_rejected",
            "execution_id": execution_id,
            "analyst_id":   analyst_id,
            "reason":       reason,
            "decided_at":   decided_at,
            "aborted":      aborted,
        },
        key=execution_id,
    )

    log.info(
        "[SOAR] HITL rejected: execution_id=%s analyst=%s aborted=%s",
        execution_id, analyst_id, aborted,
    )
    return {"aborted": aborted}


@router.get("/execution/{execution_id}")
async def get_execution(execution_id: str) -> dict[str, Any]:
    """
    Fetch live SOAR execution trace from Shuffle.

    Used by the dashboard to render the live SOAR trace panel.
    Proxies directly to Shuffle's /api/v1/workflowexecutions/{id}.

    Args:
        execution_id: Shuffle execution UUID (path param).

    Returns:
        Normalised status dict from ShuffleClient.get_status().

    Raises:
        HTTPException 502: On Shuffle connectivity errors.
    """
    log.debug("[SOAR] get_execution: id=%s", execution_id)
    try:
        return await shuffle_client.get_status(execution_id)
    except httpx.HTTPStatusError as exc:
        log.error(
            "[SOAR] get_execution failed: id=%s status=%d",
            execution_id, exc.response.status_code,
        )
        raise HTTPException(
            status_code=502,
            detail=f"Shuffle returned HTTP {exc.response.status_code} for execution {execution_id}",
        )
    except httpx.RequestError as exc:
        log.error("[SOAR] get_execution network error: id=%s error=%s", execution_id, exc)
        raise HTTPException(
            status_code=502,
            detail=f"Cannot reach Shuffle: {exc}",
        )


@router.get("/executions")
async def list_executions(
    limit: int = Query(50, ge=1, le=500, description="Max number of executions to return"),
) -> list[dict[str, Any]]:
    """
    List recent Shuffle workflow executions.

    Used by the dashboard history panel.
    Proxies to Shuffle's /api/v1/workflowexecutions?limit={n}.

    Args:
        limit: Max number of results (1–500, default 50).

    Returns:
        Raw list of execution dicts from Shuffle.

    Raises:
        HTTPException 502: On Shuffle connectivity errors.
    """
    log.debug("[SOAR] list_executions: limit=%d", limit)
    try:
        raw = await shuffle_client.list_executions(limit)
        if raw:
            return raw
    except (httpx.HTTPStatusError, httpx.RequestError) as exc:
        log.warning("[SOAR] list_executions failed (%s) — SQLite fallback", exc)


    async with aiosqlite.connect(sqlite_client.db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT id, alert_id, outcome, recorded_at, analyst_id
            FROM audit_log
            WHERE outcome = 'EXECUTED'
            ORDER BY recorded_at DESC
            LIMIT ?
            """,
            (limit,),
        ) as cur:
            rows = await cur.fetchall()

    return [
        {
            "execution_id": row["id"],
            "workflow_id":  "",
            "workflow":     "pipeline-execution",
            "status":       "FINISHED",
            "started_at":   row["recorded_at"],
            "completed_at": row["recorded_at"],
            "steps":        [],
            "step_count":   0,
        }
        for row in rows
    ]
