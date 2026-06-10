# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

"""
Alert API — backend/api/alert_api.py

Provides alert ingestion, retrieval, and management endpoints.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from api.auth_api import get_current_user
from schemas.alert import WazuhAlert
from infrastructure.kafka_client import kafka_producer
from infrastructure.sqlite_client import sqlite_client

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

TOPIC_ALERTS = "ALERTS"


@router.post("/ingest", response_model=dict)
async def ingest_alert(
    alert: WazuhAlert,
    current_user: dict = Depends(get_current_user),
) -> dict:
    """
    Ingest a single WazuhAlert into the pipeline.
    
    Publishes to the ALERTS Kafka topic for processing by the orchestration graph.
    
    Args:
        alert: WazuhAlert object
        
    Returns:
        {"alert_id": str, "status": "queued"}
    """
    log.info(
        "[Alerts] Ingesting alert: id=%s severity=%s rule_id=%s",
        alert.id, alert.severity, alert.rule_id
    )
    
    await kafka_producer.send(
        TOPIC_ALERTS,
        {
            "type": "alert_ingested",
            "alert": alert.model_dump(),
            "ingested_at": alert.timestamp.isoformat(),
        },
        key=alert.id,
    )
    
    return {
        "alert_id": alert.id,
        "status": "queued",
        "severity": alert.severity,
    }


@router.get("/{alert_id}", response_model=Optional[dict])
async def get_alert(alert_id: str) -> Optional[dict]:
    """
    Retrieve alert details by ID from SQLite.
    
    Args:
        alert_id: UUID of the alert
        
    Returns:
        Alert record or 404 if not found
    """
    alert = await sqlite_client.get_alert(alert_id)
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return alert


@router.get("", response_model=list[dict])
async def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),
) -> list[dict]:
    """
    List alerts with optional filtering.
    
    Args:
        limit: Max results (1-200, default 50)
        offset: Pagination offset
        severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
        
    Returns:
        List of alert records
    """
    filters = {}
    if severity:
        filters["severity"] = severity.upper()
    
    alerts = await sqlite_client.list_alerts(limit=limit, offset=offset, filters=filters)
    
    log.info("[Alerts] Listed %d alerts (offset=%d)", len(alerts), offset)
    
    return alerts


@router.get("/stats/summary", response_model=dict)
async def alert_summary() -> dict:
    """
    Return aggregate alert statistics.
    
    Returns:
        {"total": int, "by_severity": dict, "by_category": dict}
    """
    stats = await sqlite_client.get_alert_summary()
    return stats


@router.delete("/{alert_id}", response_model=dict)
async def delete_alert(alert_id: str) -> dict:
    """
    Delete an alert by ID (soft delete in SQLite).
    
    Args:
        alert_id: UUID of the alert
        
    Returns:
        {"deleted": True}
    """
    success = await sqlite_client.delete_alert(alert_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    log.info("[Alerts] Deleted alert: %s", alert_id)
    
    return {"deleted": True}