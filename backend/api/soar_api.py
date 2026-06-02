# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
SOAR Dashboard API — api/soar_api.py

Native Shuffle SOAR dashboard backend.  Provides four data surfaces:

  GET /api/soar-dash/workflows    — all workflows configured in Shuffle
  GET /api/soar-dash/executions   — normalised execution list from Shuffle
  GET /api/soar-dash/telemetry    — per-hour execution success/failure counts
  GET /api/soar-dash/audit        — full trigger audit log from SQLite

Shuffle is queried through the existing ShuffleClient singleton.
If Shuffle is unreachable, endpoints degrade gracefully to SQLite-derived data.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import aiosqlite
import httpx
from fastapi import APIRouter, Query

from infrastructure.sqlite_client import sqlite_client, SQLITE_DB_PATH
from services.shuffle_client import shuffle_client, ATTACK_TO_WORKFLOW

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/soar-dash", tags=["soar-dashboard"])


_KNOWN_WORKFLOWS = [
    {"id": k, "name": v, "description": f"Automated response for {k.replace('_', ' ').title()}", "is_valid": True}
    for k, v in ATTACK_TO_WORKFLOW.items()
]


def _parse_shuffle_execution(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalise a raw Shuffle execution dict into a stable frontend shape."""
    wf = raw.get("workflow") or {}
    wf_name = wf.get("name", "") if isinstance(wf, dict) else str(wf)

    status = (raw.get("status") or "UNKNOWN").upper()

    steps = []
    for result in raw.get("results") or []:
        action = result.get("action") or {}
        steps.append({
            "action_id": action.get("id", ""),
            "label":     action.get("label", action.get("name", "")),
            "status":    (result.get("status") or "").upper(),
            "started":   result.get("started_at", ""),
            "stopped":   result.get("completed_at", ""),
        })

    return {
        "execution_id": raw.get("execution_id") or raw.get("id", ""),
        "workflow_id":  wf.get("id", "") if isinstance(wf, dict) else "",
        "workflow":     wf_name,
        "status":       status,
        "started_at":   raw.get("started_at", ""),
        "completed_at": raw.get("completed_at", ""),
        "steps":        steps,
        "step_count":   len(steps),
    }


@router.get("/workflows")
async def get_workflows() -> list[dict[str, Any]]:
    """
    List all Shuffle workflows.
    Falls back to the static ATTACK_TO_WORKFLOW registry if Shuffle is offline.
    """
    try:
        raw_workflows = await shuffle_client.list_workflows()
        if raw_workflows:
            return [
                {
                    "id":          w.get("id", ""),
                    "name":        w.get("name", "—"),
                    "description": w.get("description", ""),
                    "is_valid":    w.get("is_valid", False),
                    "trigger_count": len(w.get("triggers") or []),
                    "action_count":  len(w.get("actions")  or []),
                    "updated_at":    w.get("updated_at", ""),
                }
                for w in raw_workflows
            ]
    except httpx.RequestError as exc:
        log.warning("[SOAR-DASH] Shuffle offline: %s — using static fallback", exc)
    except httpx.HTTPStatusError as exc:
        log.warning("[SOAR-DASH] Shuffle error %d — using static fallback", exc.response.status_code)


    return _KNOWN_WORKFLOWS


@router.get("/executions")
async def get_executions(
    limit: int = Query(100, ge=1, le=500),
) -> list[dict[str, Any]]:
    """
    Normalised Shuffle execution list.
    Falls back to SQLite audit_log entries if Shuffle is unreachable.
    """
    try:
        raw = await shuffle_client.list_executions(limit=limit)
        if raw:
            return [_parse_shuffle_execution(e) for e in raw]
    except (httpx.RequestError, httpx.HTTPStatusError) as exc:
        log.warning("[SOAR-DASH] list_executions failed: %s — SQLite fallback", exc)


    async with aiosqlite.connect(SQLITE_DB_PATH) as db:
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


@router.get("/telemetry")
async def get_telemetry(
    hours: int = Query(24, ge=1, le=168),
) -> list[dict[str, Any]]:
    """
    Per-hour execution counts broken down by outcome (FINISHED / FAILED / ABORTED)
    for the last N hours.  Used to drive the recharts execution telemetry chart.

    Tries Shuffle first; falls back to SQLite audit_log.
    """

    since = datetime.now(timezone.utc) - timedelta(hours=hours)


    buckets: dict[str, dict[str, int]] = {}
    for i in range(hours):
        bucket_time = since + timedelta(hours=i + 1)
        label = bucket_time.strftime("%H:00")
        buckets[label] = {"hour": label, "FINISHED": 0, "FAILED": 0, "ABORTED": 0, "EXECUTING": 0}


    shuffle_ok = False
    try:
        raw = await shuffle_client.list_executions(limit=500)
        for item in raw:
            started = item.get("started_at") or ""
            if not started:
                continue
            try:
                dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
            except ValueError:
                continue
            if dt < since:
                continue
            label = dt.strftime("%H:00")
            if label not in buckets:
                buckets[label] = {"hour": label, "FINISHED": 0, "FAILED": 0, "ABORTED": 0, "EXECUTING": 0}
            status = (item.get("status") or "UNKNOWN").upper()
            if status in buckets[label]:
                buckets[label][status] += 1
        shuffle_ok = True
    except (httpx.RequestError, httpx.HTTPStatusError):
        pass

    if not shuffle_ok:

        async with aiosqlite.connect(SQLITE_DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT strftime('%H:00', recorded_at) as hour, outcome, COUNT(*) as cnt
                FROM audit_log
                WHERE recorded_at >= datetime('now', ?)
                GROUP BY strftime('%H', recorded_at), outcome
                """,
                (f"-{hours} hours",),
            ) as cur:
                rows = await cur.fetchall()

        outcome_map = {"EXECUTED": "FINISHED", "DROPPED": "FAILED", "ESCALATED": "ABORTED"}
        for row in rows:
            label   = row["hour"]
            outcome = outcome_map.get(row["outcome"], row["outcome"])
            if label not in buckets:
                buckets[label] = {"hour": label, "FINISHED": 0, "FAILED": 0, "ABORTED": 0, "EXECUTING": 0}
            if outcome in buckets[label]:
                buckets[label][outcome] += int(row["cnt"])

    return sorted(buckets.values(), key=lambda x: x["hour"])


@router.get("/audit")
async def get_audit_log(
    limit: int = Query(200, ge=1, le=1000),
) -> list[dict[str, Any]]:
    """
    Full trigger audit log combining:
      - audit_log table (pipeline outcomes)
      - soar_hitl_requests table (HITL mid-workflow pauses)

    Merged and sorted by timestamp descending.
    """
    results: list[dict[str, Any]] = []

    async with aiosqlite.connect(SQLITE_DB_PATH) as db:
        db.row_factory = aiosqlite.Row


        async with db.execute(
            """
            SELECT id, alert_id, outcome, analyst_id, hitl_elapsed_seconds, recorded_at
            FROM audit_log
            ORDER BY recorded_at DESC
            LIMIT ?
            """,
            (limit,),
        ) as cur:
            for row in await cur.fetchall():
                results.append({
                    "id":           row["id"],
                    "type":         "pipeline",
                    "alert_id":     row["alert_id"],
                    "outcome":      row["outcome"],
                    "analyst_id":   row["analyst_id"] or "system",
                    "elapsed_s":    row["hitl_elapsed_seconds"],
                    "recorded_at":  row["recorded_at"],
                    "execution_id": None,
                })


        async with db.execute(
            """
            SELECT id, execution_id, alert_id, status, analyst_id, decided_at, created_at
            FROM soar_hitl_requests
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ) as cur:
            for row in await cur.fetchall():
                results.append({
                    "id":           row["id"],
                    "type":         "soar_hitl",
                    "alert_id":     row["alert_id"],
                    "outcome":      row["status"],
                    "analyst_id":   row["analyst_id"] or "—",
                    "elapsed_s":    None,
                    "recorded_at":  row["decided_at"] or row["created_at"],
                    "execution_id": row["execution_id"],
                })


    results.sort(key=lambda x: x["recorded_at"] or "", reverse=True)
    return results[:limit]
